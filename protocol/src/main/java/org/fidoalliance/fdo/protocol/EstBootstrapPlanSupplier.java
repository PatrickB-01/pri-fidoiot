package org.fidoalliance.fdo.protocol;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.upokecenter.cbor.CBOREncodeOptions;
import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import org.apache.commons.codec.binary.Hex;
import org.fidoalliance.fdo.protocol.message.v200.To2Codec;

final class EstBootstrapPlanSupplier {
  private final Path directory;
  private final Path authorization;
  private final Map<String, Path> plans = new HashMap<>();

  EstBootstrapPlanSupplier(Path directory, Path authorization) throws IOException {
    this.directory = directory.toAbsolutePath().normalize();
    this.authorization = authorization.toAbsolutePath().normalize();
    To2Crypto.require(this.directory.equals(this.directory.toRealPath())
        && this.authorization.equals(this.authorization.toRealPath())
        && !this.directory.startsWith(this.authorization)
        && !this.authorization.startsWith(this.directory));
    for (Path folder : java.util.List.of(this.directory, this.authorization)) {
      To2Crypto.require(Files.isDirectory(folder));
      boolean privateFolder = Files.getPosixFilePermissions(folder).stream()
          .allMatch(permission -> permission.name().startsWith("OWNER_"));
      To2Crypto.require(privateFolder);
    }
    ObjectMapper json = new ObjectMapper().enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION);
    byte[] raw = To2OwnerFixtures.read(this.directory.resolve("index.json"), false);
    JsonNode index;
    try (JsonParser parser = json.createParser(raw)) {
      index = json.readTree(parser);
      To2Crypto.require(parser.nextToken() == null);
    }
    To2Crypto.require(index != null && index.isObject() && index.size() > 0 && index.size() <= 128);
    var names = index.fieldNames();
    while (names.hasNext()) {
      String guid = names.next();
      To2Crypto.require(guid.matches("[0-9a-f]{32}") && index.get(guid).isTextual());
      Path path = local(index.get(guid).asText());
      CBORObject plan = To2Codec.decodeObject(To2OwnerFixtures.read(path, true));
      fields(plan, Set.of("configuration", "expected_revision", "mode", "remove_fields"));
      To2Crypto.require(plan.get("configuration").getType() == CBORType.Map
          && plan.get("expected_revision").getType() == CBORType.Integer
          && plan.get("expected_revision").AsInt64() >= 0
          && plan.get("expected_revision").AsInt64() <= 2147483647L
          && plan.get("mode").getType() == CBORType.TextString
          && Set.of("merge", "replace").contains(plan.get("mode").AsString())
          && plan.get("remove_fields").getType() == CBORType.Array
          && plan.get("remove_fields").size() <= 1);
      for (CBORObject field : plan.get("remove_fields").getValues()) {
        To2Crypto.require(field.equals(CBORObject.FromObject("label"))
            && !plan.get("configuration").ContainsKey("label"));
      }
      plans.put(guid, path);
    }
  }

  private Path local(String filename) throws IOException {
    To2Crypto.require(filename.matches("[a-z0-9][a-z0-9.-]{0,95}"));
    return directory.resolve(filename);
  }

  boolean contains(byte[] guid) {
    return plans.containsKey(Hex.encodeHexString(guid));
  }

  CBORObject authenticatedPlan(byte[] guid) throws IOException {
    try {
      Path path = plans.get(Hex.encodeHexString(guid));
      To2Crypto.require(path != null);
      CBORObject plan = To2Codec.decodeObject(To2OwnerFixtures.read(path, true));
      fields(plan, Set.of("configuration", "expected_revision", "mode", "remove_fields"));
      CBORObject config = plan.get("configuration");
      CBORObject authentication = config.get("authentication");
      fields(authentication, Set.of("method", "username", "password_ref"));
      To2Crypto.require(authentication.get("method").equals(CBORObject.FromObject("basic")));
      Path passwordPath = local(authentication.get("password_ref").AsString());
      byte[] password = To2OwnerFixtures.read(passwordPath, true);
      try {
        To2Crypto.require(password.length >= 16 && password.length <= 256);
        for (byte character : password) {
          To2Crypto.require(character >= 33 && character <= 126);
        }
        authentication.Remove(CBORObject.FromObject("password_ref"));
        authentication.Add("password", new String(password, StandardCharsets.US_ASCII));
      } finally {
        java.util.Arrays.fill(password, (byte) 0);
      }
      CBORObject references = config.get("trust_anchor_files");
      To2Crypto.require(references != null && references.getType() == CBORType.Array
          && references.size() >= 1 && references.size() <= 8);
      CBORObject anchors = CBORObject.NewArray();
      int total = 0;
      for (CBORObject reference : references.getValues()) {
        byte[] certificate = To2OwnerFixtures.read(local(reference.AsString()), false);
        total += certificate.length;
        To2Crypto.require(certificate.length <= 8192 && total <= 32768);
        anchors.Add(certificate);
      }
      config.Remove(CBORObject.FromObject("trust_anchor_files"));
      config.Add("trust_anchors_der", anchors);
      To2Crypto.require(canonical(config).length <= 65536
          && config.get("revision").AsInt64() > plan.get("expected_revision").AsInt64()
          && config.get("expires_at").AsInt64() > java.time.Instant.now().getEpochSecond());
      CBORObject control = To2Codec.decodeObject(To2OwnerFixtures.read(
          authorization.resolve(Hex.encodeHexString(guid) + ".cbor"), true));
      fields(control, Set.of("guid", "origin", "label", "username", "password_sha256",
          "csr_key_policy", "csr_subject_policy", "expires_at"));
      CBORObject label = config.ContainsKey("label") ? config.get("label") : CBORObject.Null;
      To2Crypto.require(control.get("guid").equals(CBORObject.FromObject(guid))
          && control.get("username").equals(authentication.get("username"))
          && control.get("origin").equals(config.get("origin"))
          && control.get("label").equals(label)
          && control.get("csr_key_policy").equals(config.get("csr_key_policy"))
          && control.get("csr_subject_policy").equals(config.get("csr_subject_policy"))
          && control.get("expires_at").equals(config.get("expires_at")));
      byte[] expected = MessageDigest.getInstance("SHA-256").digest(
          authentication.get("password").AsString().getBytes(StandardCharsets.US_ASCII));
      byte[] authorizedHash = control.get("password_sha256").GetByteString();
      To2Crypto.require(MessageDigest.isEqual(expected, authorizedHash));
      return plan;
    } catch (GeneralSecurityException | RuntimeException exception) {
      throw new IOException("EST plan unavailable");
    }
  }

  static void fields(CBORObject value, Set<String> expected) throws IOException {
    To2Crypto.require(value != null && value.getType() == CBORType.Map);
    To2Crypto.require(value.size() == expected.size());
    for (String field : expected) {
      To2Crypto.require(value.ContainsKey(field));
    }
  }

  static byte[] canonical(CBORObject value) {
    return value.EncodeToBytes(new CBOREncodeOptions("ctap2canonical=true"));
  }
}