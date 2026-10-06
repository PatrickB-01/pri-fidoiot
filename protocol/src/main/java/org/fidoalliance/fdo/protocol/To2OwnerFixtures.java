package org.fidoalliance.fdo.protocol;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertPathValidator;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.apache.commons.codec.binary.Hex;
import org.fidoalliance.fdo.protocol.message.v200.To2Codec;

final class To2OwnerFixtures {

  static final class Identity {
    final CBORObject voucher;
    final CBORObject header;
    final CBORObject ownerPublic;
    final CBORObject replacement;
    final PrivateKey ownerKey;
    final PrivateKey replacementKey;
    final PublicKey deviceKey;
    final X509Certificate leaf;
    final X509Certificate root;
    final int identityHash;

    Identity(CBORObject voucher, CBORObject replacement, PrivateKey ownerKey,
             PrivateKey replacementKey, X509Certificate trusted)
        throws IOException, GeneralSecurityException {
      this.voucher = voucher;
      this.header = To2Codec.decodeObject(voucher.get(1).GetByteString());
      To2Codec.voucherHeader(header);
      this.identityHash = header.get(4).get(0).AsInt32() == 10 ? -16 : -43;
      this.ownerPublic = validateEntries(voucher, header, identityHash);
      this.ownerKey = ownerKey;
      this.replacement = replacement;
      this.replacementKey = replacementKey;
      CBORObject chain = voucher.get(3);
      To2Crypto.require(chain.getType() == CBORType.Array && chain.size() == 2);
      this.leaf = certificate(chain.get(0).GetByteString());
      this.root = certificate(chain.get(1).GetByteString());
      To2Crypto.require(Arrays.equals(root.getEncoded(), trusted.getEncoded()));
      this.deviceKey = leaf.getPublicKey();
      To2Crypto.width(deviceKey);
      To2Crypto.equalHash(header.get(5), To2Crypto.hash(identityHash,
          chain.get(0).GetByteString(), chain.get(1).GetByteString()));
      validateCertificate();
      bind(ownerKey, To2Crypto.publicKey(ownerPublic));
      To2Crypto.require(replacement.getType() == CBORType.Map && replacement.size() == 3);
      CBORObject newHeader = replacementHeader();
      To2Codec.voucherHeader(newHeader);
      To2Crypto.require(!newHeader.get(1).equals(header.get(1))
          && replacement.get("public_key").get(0).equals(header.get(4).get(0)));
      bind(replacementKey, To2Crypto.publicKey(replacement.get("public_key")));
    }

    void validateCertificate() throws GeneralSecurityException, IOException {
      leaf.checkValidity();
      root.checkValidity();
      root.verify(root.getPublicKey());
      To2Crypto.require(root.getBasicConstraints() >= 0 && leaf.getBasicConstraints() < 0
          && leaf.getKeyUsage() != null && leaf.getKeyUsage()[0]
          && leaf.getExtendedKeyUsage() != null
          && leaf.getExtendedKeyUsage().contains("1.3.6.1.5.5.7.3.2"));
      PKIXParameters policy = new PKIXParameters(Set.of(new TrustAnchor(root, null)));
      policy.setRevocationEnabled(false);
      CertificateFactory factory = CertificateFactory.getInstance("X.509");
      CertPathValidator.getInstance("PKIX").validate(
          factory.generateCertPath(List.of(leaf)), policy);
    }

    CBORObject replacementHeader() {
      return To2Crypto.array(200, replacement.get("guid"), replacement.get("rv_info"),
          header.get(3), replacement.get("public_key"), header.get(5));
    }
  }

  private final Map<String, Identity> identities = new HashMap<>();
  private final Set<String> reserved = new HashSet<>();
  private final Path output;

  To2OwnerFixtures(Path directory, Path trustedCa, Path output)
      throws IOException, GeneralSecurityException {
    Path source = directory.toAbsolutePath().normalize();
    this.output = output.toAbsolutePath().normalize();
    To2Crypto.require(source.equals(source.toRealPath())
        && this.output.equals(this.output.toRealPath())
        && !this.output.startsWith(source) && !source.startsWith(this.output)
        && Files.isDirectory(this.output));
    To2Crypto.require(Files.getPosixFilePermissions(this.output).stream()
        .allMatch(permission -> permission.name().startsWith("OWNER_")));
    X509Certificate trusted = certificate(read(trustedCa, false));
    ObjectMapper json = new ObjectMapper().enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION);
    JsonNode index = json.readTree(read(source.resolve("index.json"), false));
    To2Crypto.require(index.isObject() && index.size() > 0 && index.size() <= 128);
    var names = index.fieldNames();
    while (names.hasNext()) {
      String guid = names.next();
      To2Crypto.require(guid.matches("[0-9a-f]{32}"));
      JsonNode record = index.get(guid);
      To2Crypto.require(record.isObject() && record.size() == 4);
      CBORObject voucher = To2Codec.decodeObject(read(
          indexed(source, record, "voucher"), false));
      To2Crypto.require(voucher.getType() == CBORType.Array && voucher.size() == 5
          && voucher.get(0).AsInt32() == 200 && voucher.get(4).getType() == CBORType.Array
          && voucher.get(4).size() <= 255);
      CBORObject replacement = To2Codec.decodeObject(read(
          indexed(source, record, "replacement"), false));
      PrivateKey ownerKey = To2Crypto.privateKey(read(indexed(source, record, "owner_key"), true));
      PrivateKey newKey = To2Crypto.privateKey(read(
          indexed(source, record, "replacement_key"), true));
      Identity identity = new Identity(voucher, replacement, ownerKey, newKey, trusted);
      To2Crypto.require(guid.equals(Hex.encodeHexString(identity.header.get(1).GetByteString())));
      identities.put(guid, identity);
    }
  }

  synchronized Identity reserve(byte[] guid) throws IOException, GeneralSecurityException {
    String name = Hex.encodeHexString(guid);
    Identity identity = identities.get(name);
    To2Crypto.require(identity != null && !Files.exists(output.resolve(name + ".cbor"))
        && !reserved.contains(name));
    identity.validateCertificate();
    reserved.add(name);
    return identity;
  }

  void validatePolicy(To2Algorithms.Policy policy) throws IOException, GeneralSecurityException {
    for (Identity identity : identities.values()) {
      PublicKey owner = To2Crypto.publicKey(identity.ownerPublic);
      policy.validateIdentity(owner);
      policy.validateIdentity(identity.deviceKey);
      policy.validateIdentity(To2Crypto.publicKey(identity.replacement.get("public_key")));
      policy.exchanges(owner);
    }
  }

  synchronized void release(byte[] guid) {
    reserved.remove(Hex.encodeHexString(guid));
  }

  void complete(Identity identity, CBORObject mac) throws IOException {
    byte[] voucher = To2Crypto.array(200, identity.replacementHeader().EncodeToBytes(), mac,
        identity.voucher.get(3), CBORObject.NewArray()).EncodeToBytes();
    Path destination = output.resolve(
        Hex.encodeHexString(identity.header.get(1).GetByteString()) + ".cbor");
    Path temporary = Files.createTempFile(output, ".pending-", ".cbor",
        PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
    try {
      try (FileChannel channel = FileChannel.open(temporary, StandardOpenOption.WRITE)) {
        ByteBuffer buffer = ByteBuffer.wrap(voucher);
        while (buffer.hasRemaining()) {
          channel.write(buffer);
        }
        channel.force(true);
      }
      Files.createLink(destination, temporary);
      try (FileChannel directory = FileChannel.open(output, StandardOpenOption.READ)) {
        directory.force(true);
      }
    } finally {
      Files.deleteIfExists(temporary);
    }
  }

  private static Path indexed(Path directory, JsonNode record, String field) throws IOException {
    JsonNode value = record.get(field);
    To2Crypto.require(value != null && value.isTextual()
        && value.asText().matches("[a-z0-9][a-z0-9.-]{0,63}"));
    return directory.resolve(value.asText());
  }

  static byte[] read(Path path, boolean secret) throws IOException {
    To2Crypto.require(path.toAbsolutePath().normalize().equals(path.toRealPath())
        && Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS));
    if (secret) {
      To2Crypto.require(Files.getPosixFilePermissions(path).stream()
          .allMatch(permission -> permission.name().startsWith("OWNER_")));
    }
    try (InputStream input = Files.newInputStream(path, LinkOption.NOFOLLOW_LINKS)) {
      byte[] raw = input.readNBytes(To2Codec.MAX_MESSAGE_BYTES + 1);
      To2Crypto.require(raw.length > 0 && raw.length <= To2Codec.MAX_MESSAGE_BYTES);
      return raw;
    }
  }

  private static X509Certificate certificate(byte[] der)
      throws IOException, GeneralSecurityException {
    X509Certificate certificate = (X509Certificate) CertificateFactory.getInstance("X.509")
        .generateCertificate(new ByteArrayInputStream(der));
    To2Crypto.require(Arrays.equals(der, certificate.getEncoded()));
    return certificate;
  }

  private static void bind(PrivateKey privateKey, PublicKey publicKey)
      throws IOException, GeneralSecurityException {
    CBORObject proof = To2Crypto.sign(To2Crypto.array(To2Crypto.random(32)), privateKey, publicKey,
        "FDO-TO2-ProveOVHdr-v1");
    To2Crypto.verify(proof, publicKey, "FDO-TO2-ProveOVHdr-v1");
  }

  private static CBORObject validateEntries(CBORObject voucher, CBORObject header, int hash)
      throws IOException, GeneralSecurityException {
    CBORObject mac = voucher.get(2);
    To2Crypto.require(mac.getType() == CBORType.Array && mac.size() == 2
        && mac.get(0).AsInt32() == (hash == -16 ? 5 : 6)
        && mac.get(1).GetByteString().length == (hash == -16 ? 32 : 48));
    CBORObject key = header.get(4);
    byte[] previous = To2Crypto.concat(voucher.get(1).GetByteString(), mac.EncodeToBytes());
    CBORObject infoHash = To2Crypto.hash(hash,
        header.get(1).EncodeToBytes(), header.get(3).EncodeToBytes());
    for (CBORObject entry : voucher.get(4).getValues()) {
      To2Codec.voucherEntry(entry);
      CBORObject payload = To2Crypto.verify(entry, To2Crypto.publicKey(key), "FDO-OVEntry-v1");
      To2Crypto.equalHash(To2Crypto.hash(hash, previous), payload.get(0));
      To2Crypto.equalHash(infoHash, payload.get(1));
      key = payload.get(3);
      To2Crypto.require(key.get(0).equals(header.get(4).get(0)));
      previous = entry.EncodeToBytes();
    }
    return key;
  }
}