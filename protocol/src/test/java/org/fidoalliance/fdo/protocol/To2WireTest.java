package org.fidoalliance.fdo.protocol;

import com.upokecenter.cbor.CBORObject;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Arrays;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import org.apache.commons.codec.binary.Hex;
import org.fidoalliance.fdo.protocol.message.MsgType;
import org.fidoalliance.fdo.protocol.message.ProtocolVersion;
import org.fidoalliance.fdo.protocol.message.v200.To2Codec;
import org.fidoalliance.fdo.protocol.message.v200.To2Messages;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

public class To2WireTest {

    @Test
    public void installedAdapterHookAndUnavailableProviderFailClosed() throws Exception {
        To2Algorithms base = To2Algorithms.classical();
        To2Algorithms.HashAdapter alias = new To2Algorithms.HashAdapter() {
            public To2Algorithms.Descriptor descriptor() {
                return new To2Algorithms.Descriptor("INSTALLED-SHA256", -16, 128, "SHA-256", null);
            }
            public void checkAvailable() throws java.security.GeneralSecurityException, IOException {
                base.hash(-16).checkAvailable();
            }
            public CBORObject digest(byte[]... parts) throws java.security.GeneralSecurityException, IOException {
                return base.hash(-16).digest(parts);
            }
        };
        To2Algorithms registry = new To2Algorithms(java.util.List.of(alias), java.util.List.of(),
                java.util.List.of(base.exchange("ECDH256")),
                java.util.List.of(base.kdf("FDO-HMAC-SHA256")), java.util.List.of(base.cipher(1)));
        Path file = Files.createTempFile("to2-installed-policy-", ".json");
        Files.writeString(file, "{\"profile\":\"classical\",\"hashes\":[\"INSTALLED-SHA256\"],"
                + "\"kex_preferences\":[\"ECDH256\"],\"cipher_preferences\":[\"A128GCM\"],"
                + "\"minimum_security_bits\":128,\"require_pq_kex\":false,"
                + "\"allow_classical_fallback\":false}");
        String previous = System.getProperty("to2.crypto.policy");
        System.setProperty("to2.crypto.policy", file.toString());
        try (To2V2Dispatcher owner = new To2V2Dispatcher(registry)) {
            Assertions.assertFalse(owner.isConfigured());
            Assertions.assertEquals(-16, registry.loadPolicy(file).chooseHash(java.util.Set.of(-16))
                    .digest(new byte[] {1}).get(0).AsInt32());
        } finally {
            if (previous == null) {
                System.clearProperty("to2.crypto.policy");
            } else {
                System.setProperty("to2.crypto.policy", previous);
            }
        }
        To2Algorithms.HashAdapter missing = new To2Algorithms.HashAdapter() {
            public To2Algorithms.Descriptor descriptor() {
                return alias.descriptor();
            }
            public void checkAvailable() throws java.security.GeneralSecurityException {
                throw new java.security.NoSuchAlgorithmException("test provider unavailable");
            }
            public CBORObject digest(byte[]... parts) throws IOException {
                throw new IOException("test operation unavailable");
            }
        };
        To2Algorithms unavailable = new To2Algorithms(java.util.List.of(missing), java.util.List.of(),
                java.util.List.of(base.exchange("ECDH256")),
                java.util.List.of(base.kdf("FDO-HMAC-SHA256")), java.util.List.of(base.cipher(1)));
        Assertions.assertThrows(java.security.GeneralSecurityException.class,
                () -> unavailable.loadPolicy(file));
    }

    @Test
    public void registryOperationsMatchFrozenCryptoVectors() throws Exception {
    String input = System.getProperty("to2.crypto.vectors");
    Assumptions.assumeTrue(input != null, "shared crypto vectors required");
    CBORObject vectors = CBORObject.FromJSONString(Files.readString(Path.of(input)));
    To2Algorithms registry = To2Algorithms.classical();
    for (CBORObject vector : vectors.get("ecdh").getValues()) {
        To2Algorithms.KexAdapter adapter = registry.exchange(vector.get("suite").AsString());
        java.security.AlgorithmParameters parameters = java.security.AlgorithmParameters.getInstance("EC");
        parameters.init(new java.security.spec.ECGenParameterSpec(adapter.descriptor().parameterSet));
        java.security.spec.ECParameterSpec curve = parameters.getParameterSpec(
            java.security.spec.ECParameterSpec.class);
        java.security.KeyFactory factory = java.security.KeyFactory.getInstance("EC");
        java.security.PublicKey owner = factory.generatePublic(new java.security.spec.ECPublicKeySpec(
            curve.getGenerator(), curve));
        java.security.PrivateKey device = factory.generatePrivate(new java.security.spec.ECPrivateKeySpec(
            java.math.BigInteger.ONE, curve));
        int width = To2Crypto.width(owner);
        int randomBytes = adapter.publicMessageBytes() - width * 2 - 6;
        byte[] peer = Hex.decodeHex(vector.get("owner_xb_hex").AsString());
        byte[] shared = To2Crypto.sharedX(device,
            To2Crypto.peerKey(peer, owner, width, randomBytes), width);
        Assertions.assertArrayEquals(Hex.decodeHex(vector.get("shared_x_hex").AsString()), shared);
        byte[] secret = To2Crypto.concat(shared,
            Hex.decodeHex(vector.get("device_random_hex").AsString()),
            Hex.decodeHex(vector.get("owner_random_hex").AsString()));
        Assertions.assertArrayEquals(Hex.decodeHex(vector.get("shse_hex").AsString()), secret);
        for (CBORObject result : vector.get("kdf").getValues()) {
        int id = result.get("cipher").AsString().equals("A128GCM") ? 1 : 3;
        To2Algorithms.CipherAdapter cipher = registry.cipher(id);
        Assertions.assertArrayEquals(Hex.decodeHex(result.get("sevk_hex").AsString()),
            registry.kdf(cipher.kdfName()).derive(secret, cipher.keyBytes()));
        }
        try (To2Algorithms.KexState local = adapter.initiate(owner);
            To2Algorithms.KexState remote = adapter.respond(owner)) {
        byte[] first = local.complete(remote.contribution());
        byte[] second = remote.complete(local.contribution());
        Assertions.assertArrayEquals(first, second);
        Assertions.assertThrows(IOException.class, () -> local.complete(remote.contribution()));
        }
    }
    for (CBORObject vector : vectors.get("aead").getValues()) {
        To2Algorithms.CipherAdapter cipher = registry.cipher(vector.get("algorithm").AsInt32());
        try (To2Algorithms.Channel channel = cipher.open(Hex.decodeHex(vector.get("key_hex").AsString()))) {
        byte[] wire = Hex.decodeHex(vector.get("wire_hex").AsString());
        Assertions.assertArrayEquals(Hex.decodeHex(vector.get("plaintext_hex").AsString()),
            channel.decrypt(wire));
        Assertions.assertThrows(IOException.class, () -> channel.decrypt(wire));
        }
    }
    for (CBORObject vector : vectors.get("external_aad").getValues()) {
        Assertions.assertArrayEquals(Hex.decodeHex(vector.get("sig_structure_hex").AsString()),
            To2Crypto.signatureInput(Hex.decodeHex("a10126"), new byte[] {(byte) 0x80},
                vector.get("tag").AsString()));
    }
    CBORObject transcript = vectors.get("transcript");
    byte[] probe = Hex.decodeHex(transcript.get("probe_input_hex").AsString());
    Assertions.assertEquals(transcript.get("probe_sha256").AsString(),
        Hex.encodeHexString(registry.hash(-16).digest(probe).get(1).GetByteString()));
    Assertions.assertEquals(transcript.get("probe_sha384").AsString(),
        Hex.encodeHexString(registry.hash(-43).digest(probe).get(1).GetByteString()));
    }

    @Test
    public void legacyEcdh384SizeArgumentStillGeneratesP384() throws Exception {
    StandardCryptoService legacy = new StandardCryptoService();
    org.fidoalliance.fdo.protocol.message.KexMessage message = legacy.getKeyExchangeMessage(
        "ECDH384", org.fidoalliance.fdo.protocol.message.KexParty.A, null);
    java.util.List<byte[]> fields = legacy.decodeEcdhMessage(message.getMessage());
    Assertions.assertEquals(48, fields.get(0).length);
    Assertions.assertEquals(48, fields.get(1).length);
    Assertions.assertEquals(48, fields.get(2).length);
    org.fidoalliance.fdo.protocol.message.EcdhKex state = message.getState().covertValue(
        org.fidoalliance.fdo.protocol.message.EcdhKex.class);
    java.security.interfaces.ECPrivateKey privateKey = (java.security.interfaces.ECPrivateKey)
        java.security.KeyFactory.getInstance("EC", legacy.getProvider()).generatePrivate(
            new java.security.spec.PKCS8EncodedKeySpec(state.getEncodedKey()));
    Assertions.assertEquals(384, privateKey.getParams().getCurve().getField().getFieldSize());
    }

    @Test
    public void strictJsonPolicyAndFixtureCompatibilityAreStartupChecks() throws Exception {
    To2Algorithms registry = To2Algorithms.classical();
    Path file = Files.createTempFile("to2-policy-", ".json");
    String compact = "{\"profile\":\"classical\",\"hashes\":[\"SHA256\"],"
        + "\"kex_preferences\":[\"ECDH256\"],\"cipher_preferences\":[\"A128GCM\"],"
        + "\"minimum_security_bits\":128,\"require_pq_kex\":false,"
        + "\"allow_classical_fallback\":false}";
    Files.writeString(file, compact);
    To2Algorithms.Policy policy = registry.loadPolicy(file);
    Assertions.assertThrows(IOException.class, () -> policy.chooseHash(java.util.Set.of(-43)));
    Files.writeString(file, compact + "{}");
    Assertions.assertThrows(IOException.class, () -> registry.loadPolicy(file));
    Files.writeString(file, compact.replace("\"profile\":\"classical\"",
        "\"profile\":\"classical\",\"profile\":\"classical\""));
    Assertions.assertThrows(IOException.class, () -> registry.loadPolicy(file));
    String root = System.getProperty("to2.fixtures");
    Assumptions.assumeTrue(root != null, "paired fixture input required");
    Path source = Path.of(root, "source-p384");
    To2OwnerFixtures fixtures = new To2OwnerFixtures(source.resolve("owner"),
        source.resolve("public/device-ca.der"), Files.createTempDirectory("to2-incompatible-"));
    Assertions.assertThrows(IOException.class, () -> fixtures.validatePolicy(policy));
    }

    @Test
    public void registriesSelectInstalledPolicyAndRejectInvalidConfiguration() throws Exception {
    To2Algorithms registry = To2Algorithms.classical();
    To2Algorithms.Policy policy = registry.policy(java.util.List.of("SHA256", "SHA384"),
        java.util.List.of("ECDH256"), java.util.List.of("A128GCM", "A256GCM"), 128);
    Assertions.assertEquals(-16, policy.chooseHash(java.util.Set.of(-43, -16))
        .descriptor().wireId);
    Assertions.assertEquals(1, policy.ciphers().get(0).descriptor().wireId);
    Assertions.assertEquals("FDO-HMAC-SHA256", registry.cipher(3).kdfName());
    Assertions.assertThrows(IOException.class, () -> registry.policy(
        java.util.List.of("SHA256"), java.util.List.of("UNKNOWN"),
        java.util.List.of("A128GCM"), 128));
    Assertions.assertThrows(IOException.class, () -> registry.policy(
        java.util.List.of("SHA256", "SHA256"), java.util.List.of("ECDH256"),
        java.util.List.of("A128GCM"), 128));
    Assertions.assertThrows(IOException.class, () -> registry.policy(
        java.util.List.of("SHA256"), java.util.List.of("ECDH256"),
        java.util.List.of("A128GCM"), 192));
    Assertions.assertThrows(IOException.class, () -> registry.policy(
        java.util.List.of("SHA384"), java.util.List.of("ECDH384"),
        java.util.List.of("A256GCM"), 256));
    Assertions.assertThrows(IOException.class, () -> registry.cipher(2));
    Assertions.assertThrows(IOException.class, () -> new To2Algorithms(
        java.util.List.of(registry.hash(-16), registry.hash(-16)), java.util.List.of(),
        java.util.List.of(), java.util.List.of(), java.util.List.of()));
    }

    @Test
    public void cipherKdfRetainsIndependentPrfAndOutputLength() throws Exception {
    byte[] deviceRandom = new byte[16];
    byte[] ownerRandom = new byte[16];
    for (int index = 0; index < 16; index++) {
        deviceRandom[index] = (byte) index;
        ownerRandom[index] = (byte) (128 + index);
    }
    byte[] shared = Hex.decodeHex(
        "7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978");
    byte[] secret = To2Crypto.concat(shared, deviceRandom, ownerRandom);
    Assertions.assertArrayEquals(Hex.decodeHex("1301fd8cbfdae5f096a5e1547d2c3d1b"),
        To2Crypto.counterKdf(secret, "HmacSHA256", 16));
    Assertions.assertArrayEquals(Hex.decodeHex(
        "7ed133096b3d487ff4ec4a882d759fa1330dc9e0139c26b68f534605a94fedd9"),
        To2Crypto.counterKdf(secret, "HmacSHA256", 32));
    Assertions.assertFalse(Arrays.equals(To2Crypto.derive(secret, 1),
        Arrays.copyOf(To2Crypto.derive(secret, 3), 16)));
    Assertions.assertThrows(IOException.class,
        () -> To2Crypto.counterKdf(secret, "SHA384", 32));
    Assertions.assertThrows(IOException.class,
        () -> To2Crypto.counterKdf(secret, "HmacSHA256", 0));
    }

    @Test
    public void fixtureLoaderRejectsWrongTrustKeySignatureAndSymlinks() throws Exception {
    String root = System.getProperty("to2.fixtures");
    Assumptions.assumeTrue(root != null, "paired fixture input required");
    Path source = Path.of(root, "source-p256");
    Path output = Files.createTempDirectory("to2-trust-out-");
    Assertions.assertThrows(IOException.class, () -> new To2OwnerFixtures(
        source.resolve("owner"), source.resolve("public/est-ca.der"), output));
    Path directory = Files.createTempDirectory("to2-bad-owner-");
    for (String name : new String[] {"index.json", "voucher.cbor", "owner-key.pem",
        "replacement.cbor", "replacement-key.pem"}) {
        Files.copy(source.resolve("owner").resolve(name), directory.resolve(name));
        Files.setPosixFilePermissions(directory.resolve(name),
            PosixFilePermissions.fromString("rw-------"));
    }
    Path trust = source.resolve("public/device-ca.der");
    Files.copy(directory.resolve("replacement-key.pem"), directory.resolve("owner-key.pem"),
        java.nio.file.StandardCopyOption.REPLACE_EXISTING);
    Assertions.assertThrows(IOException.class, () -> new To2OwnerFixtures(
        directory, trust, output));
    Files.copy(source.resolve("owner/owner-key.pem"), directory.resolve("owner-key.pem"),
        java.nio.file.StandardCopyOption.REPLACE_EXISTING);
    Files.setPosixFilePermissions(directory.resolve("owner-key.pem"),
        PosixFilePermissions.fromString("rw-------"));
    CBORObject voucher = To2Codec.decodeObject(Files.readAllBytes(
        directory.resolve("voucher.cbor")));
    CBORObject entry = voucher.get(4).get(0).Untag();
    byte[] signature = entry.get(3).GetByteString();
    signature[0] ^= 1;
    entry.set(3, CBORObject.FromObject(signature));
    Files.write(directory.resolve("voucher.cbor"), voucher.EncodeToBytes());
    Assertions.assertThrows(IOException.class, () -> new To2OwnerFixtures(
        directory, trust, output));
    Files.delete(directory.resolve("voucher.cbor"));
    Files.createSymbolicLink(directory.resolve("voucher.cbor"),
        source.resolve("owner/voucher.cbor"));
    Assertions.assertThrows(IOException.class, () -> new To2OwnerFixtures(
        directory, trust, output));
    }

    @Test
    public void terminalCacheExpiresAndChannelCannotBeReused() throws Exception {
    AtomicLong clock = new AtomicLong(100);
    AtomicInteger destroyed = new AtomicInteger();
    try (To2SessionStore<AutoCloseable> store = new To2SessionStore<>(2, 50, clock::get)) {
        String token = store.create(destroyed::incrementAndGet);
        store.shorten(token, 10);
        clock.set(109);
        Assertions.assertEquals(Boolean.TRUE, store.execute(token, value -> true));
        clock.set(110);
        store.expire();
        Assertions.assertEquals(1, destroyed.get());
        Assertions.assertThrows(IOException.class, () -> store.execute(token, value -> true));
    }
    To2Crypto.Channel channel = new To2Crypto.Channel(3, To2Crypto.random(32));
    channel.close();
    Assertions.assertThrows(IOException.class, () -> channel.encrypt(new byte[] {1}));
    }

    @Test
    public void ownerExpiryReleasesGuidAndMalformedErrorTerminates() throws Exception {
    String root = System.getProperty("to2.fixtures");
    Assumptions.assumeTrue(root != null, "paired fixture input required");
    Path source = Path.of(root, "source-p256");
    To2OwnerFixtures fixtures = new To2OwnerFixtures(source.resolve("owner"),
        source.resolve("public/device-ca.der"), Files.createTempDirectory("to2-expiry-"));
    CBORObject voucher = To2Codec.decodeObject(Files.readAllBytes(
        source.resolve("owner/voucher.cbor")));
    byte[] guid = To2Codec.decodeObject(voucher.get(1).GetByteString()).get(1).GetByteString();
    AtomicLong clock = new AtomicLong();
    try (To2V2Dispatcher owner = new To2V2Dispatcher(fixtures, clock::get, false)) {
        DispatchMessage probe = HttpUtils.getMessageFromUri("/fdo/200/msg/80");
        probe.setMessage(To2Crypto.array(new byte[] {4},
            To2Crypto.array(To2V2Dispatcher.CONTRACT_CAPABILITY), guid, 16384,
            To2Crypto.array(-16), To2Crypto.random(16)).EncodeToBytes());
        DispatchMessage ack = owner.dispatch(probe).get();
        Assertions.assertEquals(MsgType.TO2_HELLO_DEVICE_ACK20, ack.getMsgType());
        clock.set(java.util.concurrent.TimeUnit.SECONDS.toNanos(601));
        DispatchMessage late = HttpUtils.getMessageFromUri("/fdo/200/msg/82");
        late.setAuthToken(ack.getAuthToken().get());
        late.setMessage(new byte[] {0});
        Assertions.assertEquals(1,
            To2Codec.decodeObject(owner.dispatch(late).get().getMessage()).get(0).AsInt32());
        DispatchMessage fresh = owner.dispatch(probe).get();
        Assertions.assertEquals(MsgType.TO2_HELLO_DEVICE_ACK20, fresh.getMsgType());
        DispatchMessage error = HttpUtils.getMessageFromUri("/fdo/200/msg/255");
        error.setAuthToken(fresh.getAuthToken().get());
        error.setMessage(new byte[] {0});
        Assertions.assertTrue(owner.dispatch(error).isEmpty());
        Assertions.assertEquals(MsgType.TO2_HELLO_DEVICE_ACK20,
            owner.dispatch(probe).get().getMsgType());
    }
    }

    @Test
    public void zeroEntryVoucherSkipsEntryTransferDeliberately() throws Exception {
    String root = System.getProperty("to2.fixtures");
    Assumptions.assumeTrue(root != null, "paired fixture input required");
    Path source = Path.of(root, "source-p256");
    Path directory = Files.createTempDirectory("to2-zero-");
    for (String name : new String[] {"owner-key.pem", "replacement-key.pem", "replacement.cbor"}) {
        Files.copy(source.resolve("owner").resolve(name), directory.resolve(name));
        Files.setPosixFilePermissions(directory.resolve(name),
            PosixFilePermissions.fromString("rw-------"));
    }
    CBORObject original = To2Codec.decodeObject(Files.readAllBytes(
        source.resolve("owner/voucher.cbor")));
    CBORObject header = To2Codec.decodeObject(original.get(1).GetByteString());
    CBORObject finalEntry = To2Codec.decodeObject(
        original.get(4).get(1).Untag().get(2).GetByteString());
    header.set(4, finalEntry.get(3));
    CBORObject synthetic = To2Crypto.array(200, header.EncodeToBytes(), original.get(2),
        original.get(3), CBORObject.NewArray());
    Files.write(directory.resolve("voucher.cbor"), synthetic.EncodeToBytes());
    Files.copy(source.resolve("owner/index.json"), directory.resolve("index.json"));
    To2OwnerFixtures fixtures = new To2OwnerFixtures(directory,
        source.resolve("public/device-ca.der"), Files.createTempDirectory("to2-zero-out-"));
    try (To2V2Dispatcher owner = new To2V2Dispatcher(fixtures)) {
        DispatchMessage probe = HttpUtils.getMessageFromUri("/fdo/200/msg/80");
        byte[] guid = header.get(1).GetByteString();
        probe.setMessage(To2Crypto.array(new byte[] {4},
            To2Crypto.array(To2V2Dispatcher.CONTRACT_CAPABILITY), guid, 16384,
            To2Crypto.array(-16), To2Crypto.random(16)).EncodeToBytes());
        DispatchMessage ack = owner.dispatch(probe).get();
        CBORObject ackBody = To2Codec.decodeObject(ack.getMessage());
        java.security.KeyPairGenerator generator = java.security.KeyPairGenerator.getInstance("EC");
        generator.initialize(new java.security.spec.ECGenParameterSpec("secp256r1"));
        java.security.interfaces.ECPublicKey ephemeral =
            (java.security.interfaces.ECPublicKey) generator.generateKeyPair().getPublic();
        byte[] contribution = java.nio.ByteBuffer.allocate(86).putShort((short) 32)
            .put(To2Crypto.fixed(ephemeral.getW().getAffineX(), 32)).putShort((short) 32)
            .put(To2Crypto.fixed(ephemeral.getW().getAffineY(), 32)).putShort((short) 16)
            .put(To2Crypto.random(16)).array();
        java.security.PrivateKey device = To2Crypto.privateKey(Files.readAllBytes(
            source.resolve("device/device-key.pem")));
        java.security.PublicKey devicePublic = java.security.cert.CertificateFactory
            .getInstance("X.509").generateCertificate(new java.io.ByteArrayInputStream(
                original.get(3).get(0).GetByteString())).getPublicKey();
        CBORObject selection = To2Crypto.array("ECDH256", 3, contribution,
            To2Crypto.random(16), To2Crypto.hash(-16, ack.getMessage()));
        CBORObject eat = CBORObject.NewMap().Add(10, ackBody.get(6))
            .Add(256, To2Crypto.concat(new byte[] {1}, guid)).Add(-257, selection);
        DispatchMessage proof = HttpUtils.getMessageFromUri("/fdo/200/msg/82");
        proof.setAuthToken(ack.getAuthToken().get());
        proof.setMessage(To2Crypto.sign(eat, device, devicePublic,
            "FDO-TO2-ProveDevice-v1").EncodeToBytes());
        DispatchMessage response = owner.dispatch(proof).get();
        Assertions.assertEquals(MsgType.TO2_PROVE_OV_HDR20, response.getMsgType());
        Assertions.assertEquals(0, To2Codec.decodeObject(To2Codec.decodeObject(
            response.getMessage()).Untag().get(2).GetByteString()).get(1).AsInt32());
        DispatchMessage ready = HttpUtils.getMessageFromUri("/fdo/200/msg/86");
        ready.setAuthToken(ack.getAuthToken().get());
        ready.setMessage(new byte[] {0});
        Assertions.assertTrue(To2Codec.decodeObject(owner.dispatch(ready).get().getMessage())
            .HasOneTag(16));
    }
    }

    @Test
    public void javaAuthenticatesOwnerOnlyFixtures() throws Exception {
    String root = System.getProperty("to2.fixtures");
    Assumptions.assumeTrue(root != null, "paired fixture input required");
    for (String profile : new String[] {"source-p256", "source-p384"}) {
        Path output = Files.createTempDirectory("to2-owner-");
        Path source = Path.of(root, profile);
        To2OwnerFixtures fixtures = new To2OwnerFixtures(source.resolve("owner"),
            source.resolve("public/device-ca.der"), output);
        CBORObject voucher = To2Codec.decodeObject(Files.readAllBytes(
            source.resolve("owner/voucher.cbor")));
        byte[] guid = To2Codec.decodeObject(voucher.get(1).GetByteString())
            .get(1).GetByteString();
        To2OwnerFixtures.Identity identity = fixtures.reserve(guid);
        Assertions.assertEquals(2, identity.voucher.get(4).size());
        Assertions.assertThrows(IOException.class, () -> fixtures.reserve(guid));
        fixtures.release(guid);
        Assertions.assertNotNull(fixtures.reserve(guid));
        byte[] invalid = identity.voucher.get(4).get(0).Untag().get(3).GetByteString();
        invalid[0] ^= 1;
        CBORObject bad = To2Codec.decodeObject(identity.voucher.get(4).get(0).EncodeToBytes());
        bad.Untag().set(3, CBORObject.FromObject(invalid));
        Assertions.assertThrows(IOException.class, () -> To2Crypto.verify(
            bad, To2Crypto.publicKey(identity.header.get(4)), "FDO-OVEntry-v1"));
        Assertions.assertThrows(IOException.class, () -> To2Crypto.verify(
            identity.voucher.get(4).get(0), To2Crypto.publicKey(identity.header.get(4)),
            "FDO-TO2-ProveDevice-v1"));
    }
    }

    @Test
    public void sessionsAreBoundedIsolatedAndDestroyed() throws Exception {
        AtomicLong clock = new AtomicLong(100);
        AtomicInteger destroyed = new AtomicInteger();
        try (To2SessionStore<AutoCloseable> store = new To2SessionStore<>(2, 50, clock::get)) {
            String first = store.create(destroyed::incrementAndGet);
            String second = store.create(destroyed::incrementAndGet);
            Assertions.assertNotEquals(first, second);
            Assertions.assertEquals(43, first.length());
            Assertions.assertThrows(IOException.class, () -> store.create(() -> { }));
            Assertions.assertThrows(IOException.class, () -> store.execute("foreign", value -> true));
            store.remove(first);
            Assertions.assertEquals(1, destroyed.get());
            Assertions.assertEquals(Boolean.TRUE, store.execute(second, value -> true));
            clock.set(150);
            Assertions.assertThrows(IOException.class, () -> store.execute(second, value -> true));
            Assertions.assertEquals(2, destroyed.get());
            store.remove(second);
            Assertions.assertEquals(2, destroyed.get());
        }
    }

    @Test
    public void pythonVectorsForEveryMessage() throws Exception {
        String input = System.getProperty("to2.vectors");
        Assumptions.assumeTrue(input != null, "paired vector file is supplied by the Docker check");
        CBORObject root = CBORObject.FromJSONString(Files.readString(Path.of(input)));
        Assertions.assertEquals(13, root.get("messages").size());
        for (CBORObject item : root.get("messages").getValues()) {
            MsgType type = MsgType.fromNumber(item.get("type").AsInt32());
            byte[] plaintext = Hex.decodeHex(item.get("plaintext_hex").AsString());
            byte[] wire = Hex.decodeHex(item.get("wire_hex").AsString());
            To2Messages.Message model = To2Codec.decodePlaintext(type, plaintext);
            Assertions.assertEquals(type, model.getType());
            Assertions.assertArrayEquals(plaintext, model.getRaw());
            Assertions.assertArrayEquals(plaintext, To2Codec.encodePlaintext(type, model.getValue()));
            Assertions.assertArrayEquals(wire, To2Codec.decodeWire(type, wire).getRaw());
        }
    }

    @Test
    public void versionRouterAndUnimplementedStateMachineFailClosed() throws Exception {
        byte[] probe = Hex.decodeHex("8641048050000102030405060708090a0b0c0d0e0f19400082382a2f50101112131415161718191a1b1c1d1e1f");
        DispatchMessage request = HttpUtils.getMessageFromUri("/fdo/200/msg/80");
        request.setMessage(probe);
        VersionMessageDispatcher router = new VersionMessageDispatcher(
                legacy -> {
                    Assertions.assertEquals(ProtocolVersion.V101, legacy.getProtocolVersion());
                    return Optional.empty();
                }, new To2V2Dispatcher());
        DispatchMessage result = router.dispatch(request).get();
        Assertions.assertEquals(ProtocolVersion.V200, result.getProtocolVersion());
        Assertions.assertEquals(MsgType.ERROR, result.getMsgType());
        Assertions.assertEquals(103, To2Codec.decodeObject(result.getMessage()).get(0).AsInt32());
        CBORObject delegated = To2Codec.decodeObject(probe);
        delegated.set(0, CBORObject.FromObject(new byte[] {(byte) 0x84}));
        request.setMessage(delegated.EncodeToBytes());
        Assertions.assertEquals(103,
            To2Codec.decodeObject(router.dispatch(request).get().getMessage()).get(0).AsInt32());
        Assertions.assertTrue(router.dispatch(HttpUtils.getMessageFromUri("/fdo/101/msg/60"))
                .isEmpty());
        Assertions.assertThrows(IOException.class, () -> router.dispatch(
                HttpUtils.getMessageFromUri("/fdo/101/msg/80")));
        Assertions.assertThrows(IOException.class, () -> router.dispatch(
                HttpUtils.getMessageFromUri("/fdo/200/msg/60")));
        Assertions.assertTrue(router.dispatch(HttpUtils.getMessageFromUri("/fdo/200/msg/255"))
                .isEmpty());
    }

  @Test
  public void exactProbeBytesAndStrictDecode() throws Exception {
    byte[] raw = Hex.decodeHex("8641048050000102030405060708090a0b0c0d0e0f19400082382a2f50101112131415161718191a1b1c1d1e1f");
    To2Messages.Message model = To2Codec.decodeWire(MsgType.TO2_HELLO_DEVICE_PROBE, raw);
    Assertions.assertInstanceOf(To2Messages.HelloDeviceProbe.class, model);
    Assertions.assertArrayEquals(raw, model.getRaw());
    Assertions.assertArrayEquals(raw,
        To2Codec.encodePlaintext(MsgType.TO2_HELLO_DEVICE_PROBE, model.getValue()));
    Assertions.assertThrows(IOException.class, () -> To2Codec.decodeWire(
        MsgType.TO2_HELLO_DEVICE_PROBE, Arrays.copyOf(raw, raw.length + 1)));
    Assertions.assertThrows(IOException.class, () -> To2Codec.decodeObject(
        Hex.decodeHex("a201000101")));
    Assertions.assertThrows(IOException.class, () -> To2Codec.decodePlaintext(
        MsgType.TO2_DEVICE_SVC_INFO20, Hex.decodeHex("82f480")));
    Assertions.assertThrows(IOException.class, () -> To2Codec.decodePlaintext(
        MsgType.TO2_OWNER_SVC_INFO20, Hex.decodeHex("8300f580")));
  }

  @Test
  public void encryptionIsNotPlaintextAndErrorsAreV2() throws Exception {
    byte[] plaintext = Hex.decodeHex("83f619200050404142434445464748494a4b4c4d4e4f");
    Assertions.assertNotNull(To2Codec.decodePlaintext(MsgType.TO2_DEVICE_SERVICE_INFO_RDY20,
        plaintext));
    Assertions.assertThrows(IOException.class, () -> To2Codec.decodeWire(
        MsgType.TO2_DEVICE_SERVICE_INFO_RDY20, plaintext));
    CBORObject error = To2Codec.decodeObject(To2Codec.error(103, 80));
    Assertions.assertEquals(5, error.size());
    Assertions.assertEquals(103, error.get(0).AsInt32());
    Assertions.assertTrue(error.get(3).isNull());
  }

    @Test
    public void preservesNoncanonicalInputAndBoundsShapes() throws Exception {
        byte[] raw = Hex.decodeHex("980641048050000102030405060708090a0b0c0d0e0f19400082382a2f50101112131415161718191a1b1c1d1e1f");
        Assertions.assertArrayEquals(raw,
                To2Codec.decodeWire(MsgType.TO2_HELLO_DEVICE_PROBE, raw).getRaw());
        Assertions.assertThrows(IOException.class, () -> To2Codec.decodeObject(
                new byte[To2Codec.MAX_MESSAGE_BYTES + 1]));
        CBORObject nested = CBORObject.Null;
        for (int index = 0; index < 40; index++) {
            nested = CBORObject.NewArray().Add(nested);
        }
        byte[] deep = nested.EncodeToBytes();
        Assertions.assertThrows(IOException.class, () -> To2Codec.decodeObject(deep));
        Assertions.assertThrows(IOException.class, () -> To2Codec.decodePlaintext(
                MsgType.TO2_DEVICE_SERVICE_INFO_RDY20,
                Hex.decodeHex("83c0f619200050404142434445464748494a4b4c4d4e4f")));
        Assertions.assertThrows(IOException.class, () -> To2Codec.decodePlaintext(
                MsgType.TO2_GET_OV_NEXT_ENTRY20, Hex.decodeHex("81f93c00")));
        Assertions.assertThrows(IOException.class, () -> To2Codec.decodeWire(
                MsgType.TO2_DEVICE_SVC_INFO20, Hex.decodeHex("83f6f480")));
    }

    @Test
    public void generatedPythonVoucherStructures() throws Exception {
        String root = System.getProperty("to2.fixtures");
        Assumptions.assumeTrue(root != null, "fixture volume is supplied by the Docker check");
        for (String profile : new String[] {"source-p256", "source-p384"}) {
            CBORObject voucher = To2Codec.decodeObject(Files.readAllBytes(
                    Path.of(root, profile, "owner", "voucher.cbor")));
            Assertions.assertEquals(200, voucher.get(0).AsInt32());
            To2Codec.voucherHeader(To2Codec.decodeObject(voucher.get(1).GetByteString()));
            Assertions.assertEquals(2, voucher.get(4).size());
            for (CBORObject entry : voucher.get(4).getValues()) {
                To2Codec.voucherEntry(entry);
            }
        }
    }
}