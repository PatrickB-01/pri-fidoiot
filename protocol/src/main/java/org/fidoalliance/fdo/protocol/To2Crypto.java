package org.fidoalliance.fdo.protocol;

import com.upokecenter.cbor.CBORObject;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.interfaces.ECKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECFieldFp;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashSet;
import java.util.Set;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.fidoalliance.fdo.protocol.message.v200.To2Codec;

final class To2Crypto {

  private static final SecureRandom RANDOM = new SecureRandom();

  static void require(boolean condition) throws IOException {
    if (!condition) {
      throw new IOException("v200 validation failed");
    }
  }

  static CBORObject array(Object... values) {
    CBORObject result = CBORObject.NewArray();
    for (Object value : values) {
      result.Add(value == null ? CBORObject.Null : CBORObject.FromObject(value));
    }
    return result;
  }

  static byte[] random(int size) {
    byte[] value = new byte[size];
    RANDOM.nextBytes(value);
    return value;
  }

  static byte[] concat(byte[]... parts) {
    int size = Arrays.stream(parts).mapToInt(part -> part.length).sum();
    ByteBuffer result = ByteBuffer.allocate(size);
    for (byte[] part : parts) {
      result.put(part);
    }
    return result.array();
  }

  static CBORObject hash(int id, byte[]... parts) throws GeneralSecurityException, IOException {
    return To2Algorithms.classical().hash(id).digest(parts);
  }

  static void equalHash(CBORObject expected, CBORObject actual) throws IOException {
    require(expected.get(0).equals(actual.get(0)) && MessageDigest.isEqual(
        expected.get(1).GetByteString(), actual.get(1).GetByteString()));
  }

  static int width(PublicKey key) throws GeneralSecurityException, IOException {
    require(key instanceof ECPublicKey);
    ECParameterSpec actual = ((ECKey) key).getParams();
    int width = actual.getOrder().bitLength() / 8;
    require(width == 32 || width == 48);
    AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
    parameters.init(new ECGenParameterSpec(width == 32 ? "secp256r1" : "secp384r1"));
    ECParameterSpec named = parameters.getParameterSpec(ECParameterSpec.class);
    require(actual.getCurve().equals(named.getCurve())
        && actual.getGenerator().equals(named.getGenerator())
        && actual.getOrder().equals(named.getOrder())
        && actual.getCofactor() == named.getCofactor());
    return width;
  }

  static PublicKey publicKey(CBORObject object) throws GeneralSecurityException, IOException {
    PublicKey key = KeyFactory.getInstance("EC").generatePublic(
        new X509EncodedKeySpec(object.get(2).GetByteString()));
    int width = width(key);
    require(object.get(0).AsInt32() == (width == 32 ? 10 : 11)
        && object.get(1).AsInt32() == 1);
    return key;
  }

  static PrivateKey privateKey(byte[] pem) throws GeneralSecurityException, IOException {
    try (PemReader reader = new PemReader(new InputStreamReader(
        new ByteArrayInputStream(pem), StandardCharsets.US_ASCII))) {
      PemObject object = reader.readPemObject();
      require(object != null && "PRIVATE KEY".equals(object.getType())
          && reader.readPemObject() == null);
      byte[] der = object.getContent();
      try {
        return KeyFactory.getInstance("EC").generatePrivate(new PKCS8EncodedKeySpec(der));
      } finally {
        Arrays.fill(der, (byte) 0);
      }
    } finally {
      Arrays.fill(pem, (byte) 0);
    }
  }

  static byte[] signatureInput(byte[] protectedBytes, byte[] payload, String domain) {
    return array("Signature1", protectedBytes, array(domain).EncodeToBytes(), payload)
        .EncodeToBytes();
  }

  static CBORObject sign(CBORObject payload, PrivateKey privateKey, PublicKey publicKey,
                        String domain) throws GeneralSecurityException, IOException {
    To2Algorithms.SignatureAdapter adapter = To2Algorithms.classical().signature(publicKey);
    return adapter.sign(payload, privateKey, publicKey, domain);
  }

  static CBORObject signWith(CBORObject payload, PrivateKey privateKey, PublicKey publicKey,
                            String domain, int algorithm, String jcaName)
      throws GeneralSecurityException, IOException {
    final int width = width(publicKey);
    checkDomain(domain);
    byte[] protectedBytes = CBORObject.NewMap().Add(1, algorithm).EncodeToBytes();
    byte[] raw = payload.EncodeToBytes();
    Signature signer = Signature.getInstance(jcaName);
    signer.initSign(privateKey, RANDOM);
    signer.update(signatureInput(protectedBytes, raw, domain));
    ASN1Sequence signature = ASN1Sequence.getInstance(signer.sign());
    byte[] encoded = concat(
      fixed(ASN1Integer.getInstance(signature.getObjectAt(0)).getValue(), width),
        fixed(ASN1Integer.getInstance(signature.getObjectAt(1)).getValue(), width));
    return array(protectedBytes, CBORObject.NewMap(), raw, encoded).WithTag(18);
  }

  static CBORObject verify(CBORObject signed, PublicKey key, String domain)
      throws GeneralSecurityException, IOException {
    return To2Algorithms.classical().signature(key).verify(signed, key, domain);
  }

  static void checkDomain(String domain) throws IOException {
    require(Set.of("FDO-TO2-ProveDevice-v1", "FDO-TO2-ProveOVHdr-v1",
        "FDO-TO2-SetupDevice-v1", "FDO-OVEntry-v1").contains(domain));
  }

  static CBORObject verifyWith(CBORObject signed, PublicKey key, String domain,
                              int algorithm, String jcaName)
      throws GeneralSecurityException, IOException {
    checkDomain(domain);
    require(signed.HasOneTag(18));
    CBORObject body = signed.Untag();
    require(body.size() == 4 && body.get(1).size() == 0);
    byte[] protectedBytes = body.get(0).GetByteString();
    CBORObject headers = To2Codec.decodeObject(protectedBytes);
    int width = width(key);
    int receivedAlgorithm = headers.get(CBORObject.FromObject(1)).AsInt32();
    require(headers.size() == 1 && receivedAlgorithm == algorithm);
    byte[] signature = body.get(3).GetByteString();
    require(signature.length == width * 2);
    BigInteger first = new BigInteger(1, Arrays.copyOfRange(signature, 0, width));
    BigInteger second = new BigInteger(1, Arrays.copyOfRange(signature, width, width * 2));
    Signature verifier = Signature.getInstance(jcaName);
    verifier.initVerify(key);
    byte[] payload = body.get(2).GetByteString();
    verifier.update(signatureInput(protectedBytes, payload, domain));
    require(verifier.verify(new DERSequence(new ASN1Integer[] {
        new ASN1Integer(first), new ASN1Integer(second)}).getEncoded()));
    return To2Codec.decodeObject(payload);
  }

  static byte[] fixed(BigInteger number, int width) throws IOException {
    require(number.signum() >= 0 && number.bitLength() <= width * 8);
    byte[] encoded = number.toByteArray();
    byte[] result = new byte[width];
    int size = Math.min(width, encoded.length);
    System.arraycopy(encoded, encoded.length - size, result, width - size, size);
    return result;
  }

  static byte[][] exchange(byte[] peer, PublicKey owner, int cipher)
      throws GeneralSecurityException, IOException {
    int width = width(owner);
    int randomSize = width == 32 ? 16 : 48;
    String curve = width == 32 ? "secp256r1" : "secp384r1";
    try (EcdhState state = new EcdhState(owner, width, randomSize, curve, false)) {
      byte[] secret = state.complete(peer);
      try {
        return new byte[][] {state.contribution(), derive(secret, cipher)};
      } finally {
        Arrays.fill(secret, (byte) 0);
      }
    }
  }

  static PublicKey peerKey(byte[] peer, PublicKey owner, int width, int randomSize)
      throws GeneralSecurityException, IOException {
    require(peer.length == width * 2 + randomSize + 6);
    ByteBuffer input = ByteBuffer.wrap(peer);
    require(Short.toUnsignedInt(input.getShort()) == width);
    byte[] first = new byte[width];
    input.get(first);
    require(Short.toUnsignedInt(input.getShort()) == width);
    byte[] second = new byte[width];
    input.get(second);
    require(Short.toUnsignedInt(input.getShort()) == randomSize);
    byte[] deviceRandom = new byte[randomSize];
    input.get(deviceRandom);
    ECParameterSpec parameters = ((ECPublicKey) owner).getParams();
    BigInteger pointX = new BigInteger(1, first);
    BigInteger pointY = new BigInteger(1, second);
    BigInteger prime = ((ECFieldFp) parameters.getCurve().getField()).getP();
    require(pointX.compareTo(prime) < 0 && pointY.compareTo(prime) < 0
        && pointY.modPow(BigInteger.TWO, prime).equals(pointX.modPow(BigInteger.valueOf(3), prime)
            .add(parameters.getCurve().getA().multiply(pointX))
            .add(parameters.getCurve().getB()).mod(prime)));
    ECPublicKeySpec peerSpec = new ECPublicKeySpec(new ECPoint(pointX, pointY), parameters);
    return KeyFactory.getInstance("EC").generatePublic(peerSpec);
  }

  static byte[] sharedX(PrivateKey privateKey, PublicKey peerKey, int width)
      throws GeneralSecurityException, IOException {
    KeyAgreement agreement = KeyAgreement.getInstance("ECDH");
    agreement.init(privateKey);
    agreement.doPhase(peerKey, true);
    byte[] shared = agreement.generateSecret();
    try {
      return fixed(new BigInteger(1, shared), width);
    } finally {
      Arrays.fill(shared, (byte) 0);
    }
  }

  static final class EcdhState implements To2Algorithms.KexState {
    private KeyPair ephemeral;
    private final PublicKey owner;
    private final int width;
    private final int randomSize;
    private final boolean device;
    private final byte[] roleRandom;
    private final byte[] contribution;
    private boolean used;

    EcdhState(PublicKey owner, int width, int randomSize, String curve, boolean device)
        throws GeneralSecurityException, IOException {
      this.owner = owner;
      this.width = width;
      this.randomSize = randomSize;
      this.device = device;
      require(To2Crypto.width(owner) == width);
      roleRandom = random(randomSize);
      KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
      ECGenParameterSpec parameters = new ECGenParameterSpec(curve);
      generator.initialize(parameters, RANDOM);
      ephemeral = generator.generateKeyPair();
      ECPoint point = ((ECPublicKey) ephemeral.getPublic()).getW();
      contribution = ByteBuffer.allocate(width * 2 + randomSize + 6).putShort((short) width)
          .put(fixed(point.getAffineX(), width)).putShort((short) width)
          .put(fixed(point.getAffineY(), width)).putShort((short) randomSize)
          .put(roleRandom).array();
    }

    @Override
    public byte[] contribution() throws IOException {
      require(ephemeral != null);
      return contribution.clone();
    }

    @Override
    public byte[] complete(byte[] peer) throws GeneralSecurityException, IOException {
      require(ephemeral != null && !used);
      used = true;
      PublicKey publicKey = peerKey(peer, owner, width, randomSize);
      byte[] shared = sharedX(ephemeral.getPrivate(), publicKey, width);
      byte[] remoteRandom = Arrays.copyOfRange(peer, peer.length - randomSize, peer.length);
      try {
        return device ? concat(shared, roleRandom, remoteRandom)
          : concat(shared, remoteRandom, roleRandom);
      } finally {
        Arrays.fill(shared, (byte) 0);
      }
    }

    @Override
    public void close() {
      ephemeral = null;
      Arrays.fill(roleRandom, (byte) 0);
      Arrays.fill(contribution, (byte) 0);
    }
  }

  static byte[] derive(byte[] secret, int cipher) throws GeneralSecurityException, IOException {
    To2Algorithms registry = To2Algorithms.classical();
    To2Algorithms.CipherAdapter adapter = registry.cipher(cipher);
    return registry.kdf(adapter.kdfName()).derive(secret, adapter.keyBytes());
  }

  static byte[] counterKdf(byte[] secret, String prf, int size)
      throws GeneralSecurityException, IOException {
    require(secret != null && secret.length > 0 && size > 0 && size <= 512
        && ("HmacSHA256".equals(prf) || "HmacSHA384".equals(prf)));
    Mac mac = Mac.getInstance(prf);
    mac.init(new SecretKeySpec(secret, prf));
    byte[] suffix = concat("FIDO-KDF".getBytes(StandardCharsets.US_ASCII),
        new byte[] {0}, "AutomaticOnboardTunnel".getBytes(StandardCharsets.US_ASCII),
        ByteBuffer.allocate(2).putShort((short) (size * 8)).array());
    byte[] result = new byte[size];
    int offset = 0;
    for (int counter = 1; offset < size; counter++) {
      byte[] block = mac.doFinal(concat(new byte[] {(byte) counter}, suffix));
      int count = Math.min(block.length, size - offset);
      System.arraycopy(block, 0, result, offset, count);
      offset += count;
      Arrays.fill(block, (byte) 0);
    }
    return result;
  }

  static final class Channel implements To2Algorithms.Channel {
    private final int algorithm;
    private final byte[] key;
    private final Set<String> nonces = new HashSet<>();
    private boolean closed;

    Channel(int algorithm, byte[] key) throws IOException {
      require((algorithm == 1 && key.length == 16) || (algorithm == 3 && key.length == 32));
      this.algorithm = algorithm;
      this.key = key.clone();
    }

    @Override
    public void validate(byte[] wire) throws IOException {
      To2Codec.decodeWire(
          org.fidoalliance.fdo.protocol.message.MsgType.TO2_DEVICE_SVC_INFO20, wire);
    }

    @Override
    public byte[] encrypt(byte[] plaintext) throws GeneralSecurityException, IOException {
      byte[] nonce;
      do {
        nonce = random(12);
      } while (nonces.contains(Base64.getEncoder().encodeToString(nonce)));
      byte[] protectedBytes = CBORObject.NewMap().Add(1, algorithm).EncodeToBytes();
      byte[] ciphertext = crypt(Cipher.ENCRYPT_MODE, nonce, protectedBytes, plaintext);
      return array(protectedBytes, CBORObject.NewMap().Add(5, nonce), ciphertext)
          .WithTag(16).EncodeToBytes();
    }

    @Override
    public byte[] decrypt(byte[] wire) throws GeneralSecurityException, IOException {
      CBORObject value = To2Codec.decodeWire(
          org.fidoalliance.fdo.protocol.message.MsgType.TO2_DEVICE_SVC_INFO20, wire).getValue();
      CBORObject body = value.Untag();
      byte[] protectedBytes = body.get(0).GetByteString();
      require(To2Codec.decodeObject(protectedBytes).get(CBORObject.FromObject(1)).AsInt32()
          == algorithm);
      return crypt(Cipher.DECRYPT_MODE, body.get(1).get(CBORObject.FromObject(5)).GetByteString(),
          protectedBytes, body.get(2).GetByteString());
    }

    private byte[] crypt(int mode, byte[] nonce, byte[] protectedBytes, byte[] input)
        throws GeneralSecurityException, IOException {
      require(!closed && nonces.size() < 512 && nonce.length == 12);
      require(nonces.add(Base64.getEncoder().encodeToString(nonce)));
      Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
      cipher.init(mode, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, nonce));
      cipher.updateAAD(array("Encrypt0", protectedBytes, new byte[0]).EncodeToBytes());
      return cipher.doFinal(input);
    }

    @Override
    public void close() {
      closed = true;
      Arrays.fill(key, (byte) 0);
      nonces.clear();
    }
  }
}