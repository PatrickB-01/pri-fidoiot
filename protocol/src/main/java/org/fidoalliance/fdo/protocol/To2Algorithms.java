package org.fidoalliance.fdo.protocol;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.upokecenter.cbor.CBORObject;
import java.io.IOException;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;

public final class To2Algorithms {

  public static final class Descriptor {
    public final String name;
    public final Object wireId;
    public final int securityBits;
    public final String parameterSet;
    public final String vendorCapability;

    /**
     * Describes an installed operation, not arbitrary configuration-supplied code.
     * @param name local configuration identifier
     * @param wireId exact integer or text identifier
     * @param securityBits classical security strength
     * @param parameterSet fixed parameters
     * @param vendorCapability required vendor profile, or null for standard algorithms
     */
    public Descriptor(String name, Object wireId, int securityBits, String parameterSet,
                      String vendorCapability) {
      this.name = name;
      this.wireId = wireId;
      this.securityBits = securityBits;
      this.parameterSet = parameterSet;
      this.vendorCapability = vendorCapability;
    }
  }

  public interface Adapter {
    Descriptor descriptor();

    void checkAvailable() throws GeneralSecurityException, IOException;
  }

  public interface HashAdapter extends Adapter {
    CBORObject digest(byte[]... parts) throws GeneralSecurityException, IOException;
  }

  public interface SignatureAdapter extends Adapter {
    boolean compatible(PublicKey key) throws GeneralSecurityException, IOException;

    CBORObject sign(CBORObject payload, PrivateKey privateKey, PublicKey publicKey, String domain)
        throws GeneralSecurityException, IOException;

    CBORObject verify(CBORObject signed, PublicKey publicKey, String domain)
        throws GeneralSecurityException, IOException;
  }

  public interface KexState extends AutoCloseable {
    byte[] contribution() throws IOException;

    byte[] complete(byte[] peer) throws GeneralSecurityException, IOException;

    @Override
    void close();
  }

  public interface KexAdapter extends Adapter {
    boolean compatible(PublicKey owner) throws GeneralSecurityException, IOException;

    int publicMessageBytes();

    String roles();

    KexState initiate(PublicKey owner) throws GeneralSecurityException, IOException;

    KexState respond(PublicKey owner) throws GeneralSecurityException, IOException;
  }

  public interface KdfAdapter extends Adapter {
    byte[] derive(byte[] shared, int keyBytes) throws GeneralSecurityException, IOException;
  }

  public interface Channel extends AutoCloseable {
    void validate(byte[] wire) throws IOException;

    byte[] encrypt(byte[] plaintext) throws GeneralSecurityException, IOException;

    byte[] decrypt(byte[] wire) throws GeneralSecurityException, IOException;

    @Override
    void close();
  }

  public interface CipherAdapter extends Adapter {
    int keyBytes();

    int nonceBytes();

    int tagBytes();

    String framing();

    String kdfName();

    Channel open(byte[] key) throws GeneralSecurityException, IOException;
  }

  private abstract static class Installed implements Adapter {
    private final Descriptor descriptor;

    Installed(String name, Object wireId, int strength, String parameters) {
      descriptor = new Descriptor(name, wireId, strength, parameters, null);
    }

    @Override
    public Descriptor descriptor() {
      return descriptor;
    }
  }

  private static final class Digest extends Installed implements HashAdapter {
    private final String jcaName;

    Digest(String name, int id, int strength, String jcaName) {
      super(name, id, strength, jcaName);
      this.jcaName = jcaName;
    }

    @Override
    public void checkAvailable() throws GeneralSecurityException {
      MessageDigest.getInstance(jcaName).digest(new byte[] {1});
    }

    @Override
    public CBORObject digest(byte[]... parts) throws GeneralSecurityException {
      MessageDigest digest = MessageDigest.getInstance(jcaName);
      for (byte[] part : parts) {
        digest.update(part);
      }
      return To2Crypto.array(descriptor().wireId, digest.digest());
    }
  }

  private static final class Ecdsa extends Installed implements SignatureAdapter {
    private final int width;
    private final String jcaName;

    Ecdsa(String name, int id, int width, String jcaName) {
      super(name, id, width * 4, "raw-RS; domain-separated-Sign1");
      this.width = width;
      this.jcaName = jcaName;
    }

    @Override
    public void checkAvailable() throws GeneralSecurityException {
      Signature.getInstance(jcaName);
    }

    @Override
    public boolean compatible(PublicKey key) throws GeneralSecurityException, IOException {
      return To2Crypto.width(key) == width;
    }

    @Override
    public CBORObject sign(CBORObject payload, PrivateKey privateKey, PublicKey publicKey,
                           String domain) throws GeneralSecurityException, IOException {
      To2Crypto.require(compatible(publicKey));
      return To2Crypto.signWith(payload, privateKey, publicKey, domain,
          (Integer) descriptor().wireId, jcaName);
    }

    @Override
    public CBORObject verify(CBORObject signed, PublicKey publicKey, String domain)
        throws GeneralSecurityException, IOException {
      To2Crypto.require(compatible(publicKey));
      return To2Crypto.verifyWith(signed, publicKey, domain,
          (Integer) descriptor().wireId, jcaName);
    }
  }

  private static final class Ecdh extends Installed implements KexAdapter {
    private final int width;
    private final int randomBytes;
    private final String curve;

    Ecdh(String name, int width, int randomBytes, String curve) {
      super(name, name, width * 4, curve);
      this.width = width;
      this.randomBytes = randomBytes;
      this.curve = curve;
    }

    @Override
    public void checkAvailable() throws GeneralSecurityException {
      KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
      generator.initialize(new ECGenParameterSpec(curve));
      generator.generateKeyPair();
      KeyAgreement.getInstance("ECDH");
    }

    @Override
    public boolean compatible(PublicKey owner) throws GeneralSecurityException, IOException {
      return To2Crypto.width(owner) == width;
    }

    @Override
    public int publicMessageBytes() {
      return width * 2 + randomBytes + 6;
    }

    @Override
    public String roles() {
      return "Device=xA;Owner=xB;DeviceRandom||OwnerRandom";
    }

    @Override
    public KexState initiate(PublicKey owner) throws GeneralSecurityException, IOException {
      To2Crypto.require(compatible(owner));
      return new To2Crypto.EcdhState(owner, width, randomBytes, curve, true);
    }

    @Override
    public KexState respond(PublicKey owner) throws GeneralSecurityException, IOException {
      To2Crypto.require(compatible(owner));
      return new To2Crypto.EcdhState(owner, width, randomBytes, curve, false);
    }
  }

  private static final class CounterKdf extends Installed implements KdfAdapter {
    CounterKdf() {
      super("FDO-HMAC-SHA256", "FDO-HMAC-SHA256", 256,
          "counter8;FIDO-KDF;AutomaticOnboardTunnel;L16be");
    }

    @Override
    public void checkAvailable() throws GeneralSecurityException {
      Mac.getInstance("HmacSHA256");
    }

    @Override
    public byte[] derive(byte[] shared, int keyBytes) throws GeneralSecurityException, IOException {
      return To2Crypto.counterKdf(shared, "HmacSHA256", keyBytes);
    }
  }

  private static final class Gcm extends Installed implements CipherAdapter {
    private final int keyBytes;

    Gcm(String name, int id, int keyBytes) {
      super(name, id, keyBytes * 8, "AES-GCM;IV96;tag128");
      this.keyBytes = keyBytes;
    }

    @Override
    public void checkAvailable() throws GeneralSecurityException, IOException {
      Cipher.getInstance("AES/GCM/NoPadding");
      byte[] key = To2Crypto.random(keyBytes);
      try (Channel sender = open(key); Channel receiver = open(key)) {
        byte[] plaintext = new byte[] {1, 2, 3};
        To2Crypto.require(java.util.Arrays.equals(plaintext,
            receiver.decrypt(sender.encrypt(plaintext))));
      } finally {
        java.util.Arrays.fill(key, (byte) 0);
      }
    }

    @Override
    public int keyBytes() {
      return keyBytes;
    }

    @Override
    public int nonceBytes() {
      return 12;
    }

    @Override
    public int tagBytes() {
      return 16;
    }

    @Override
    public String framing() {
      return "COSE_Encrypt0;tag16;protected-bstr;ciphertext||tag";
    }

    @Override
    public String kdfName() {
      return "FDO-HMAC-SHA256";
    }

    @Override
    public Channel open(byte[] key) throws IOException {
      return new To2Crypto.Channel((Integer) descriptor().wireId, key);
    }
  }

  private final Map<String, HashAdapter> hashes;
  private final Map<String, SignatureAdapter> signatures;
  private final Map<String, KexAdapter> exchanges;
  private final Map<String, KdfAdapter> kdfs;
  private final Map<String, CipherAdapter> ciphers;

  /**
   * Registers installed implementations and rejects ambiguous local or wire IDs.
   * @param hashes transcript digests
   * @param signatures identity signing adapters
   * @param exchanges role-aware KEX adapters
   * @param kdfs key derivation adapters
   * @param ciphers message encryption adapters
   * @throws IOException invalid metadata or duplicate registrations
   */
  public To2Algorithms(Collection<HashAdapter> hashes, Collection<SignatureAdapter> signatures,
                       Collection<KexAdapter> exchanges, Collection<KdfAdapter> kdfs,
                       Collection<CipherAdapter> ciphers) throws IOException {
    this.hashes = register(hashes, Integer.class);
    this.signatures = register(signatures, Integer.class);
    this.exchanges = register(exchanges, String.class);
    this.kdfs = register(kdfs, String.class);
    this.ciphers = register(ciphers, Integer.class);
    for (CipherAdapter cipher : ciphers) {
      To2Crypto.require(cipher.keyBytes() > 0 && cipher.keyBytes() <= 512
          && cipher.nonceBytes() > 0 && cipher.nonceBytes() <= 32
          && cipher.tagBytes() > 0 && cipher.tagBytes() <= 64
          && this.kdfs.containsKey(cipher.kdfName()) && cipher.framing() != null);
    }
  }

  private static <T extends Adapter> Map<String, T> register(Collection<T> adapters,
                                                            Class<?> wireType) throws IOException {
    Map<String, T> result = new LinkedHashMap<>();
    Set<Object> ids = new HashSet<>();
    To2Crypto.require(adapters != null && adapters.size() <= 32);
    for (T adapter : adapters) {
      To2Crypto.require(adapter != null && adapter.descriptor() != null);
      Descriptor value = adapter.descriptor();
      To2Crypto.require(value.name != null && value.name.matches("[A-Za-z0-9._-]{1,128}"));
      To2Crypto.require(wireType.isInstance(value.wireId) && value.securityBits >= 128);
      To2Crypto.require(value.parameterSet != null && !value.parameterSet.isEmpty()
          && value.parameterSet.length() <= 256);
      To2Crypto.require(!(value.wireId instanceof String)
          || ((String) value.wireId).matches("[A-Za-z0-9._-]{1,128}"));
      To2Crypto.require(value.vendorCapability == null
          || value.vendorCapability.matches("[A-Za-z0-9._-]{1,128}"));
      To2Crypto.require(!result.containsKey(value.name) && ids.add(value.wireId));
      if (adapter instanceof KexAdapter) {
        KexAdapter exchange = (KexAdapter) adapter;
        To2Crypto.require(exchange.publicMessageBytes() > 0
            && exchange.publicMessageBytes() <= 16384 && exchange.roles() != null);
      }
      result.put(value.name, adapter);
    }
    return java.util.Collections.unmodifiableMap(result);
  }

  /**
   * Builds the bounded classical registry without enabling experimental suites.
   * @return installed NIST ECDSA/ECDH, SHA and GCM operations
   * @throws IOException invalid built-in metadata
   */
  public static To2Algorithms classical() throws IOException {
    return new To2Algorithms(List.of(new Digest("SHA256", -16, 128, "SHA-256"),
        new Digest("SHA384", -43, 192, "SHA-384")),
        List.of(new Ecdsa("ES256", -7, 32, "SHA256withECDSA"),
            new Ecdsa("ES384", -35, 48, "SHA384withECDSA")),
        List.of(new Ecdh("ECDH256", 32, 16, "secp256r1"),
            new Ecdh("ECDH384", 48, 48, "secp384r1")),
        List.of(new CounterKdf()),
        List.of(new Gcm("A128GCM", 1, 16), new Gcm("A256GCM", 3, 32)));
  }

  public HashAdapter hash(int wireId) throws IOException {
    return byWire(hashes, wireId);
  }

  public CipherAdapter cipher(int wireId) throws IOException {
    return byWire(ciphers, wireId);
  }

  public KexAdapter exchange(String wireId) throws IOException {
    return byWire(exchanges, wireId);
  }

  public KdfAdapter kdf(String name) throws IOException {
    return named(kdfs, name);
  }

  /**
   * Selects an identity operation from the validated named curve, never transcript preference.
   * @param key identity public key
   * @return matching installed signature adapter
   * @throws IOException unsupported identity
   * @throws GeneralSecurityException invalid curve parameters
   */
  public SignatureAdapter signature(PublicKey key) throws IOException, GeneralSecurityException {
    for (SignatureAdapter adapter : signatures.values()) {
      if (adapter.compatible(key)) {
        return adapter;
      }
    }
    throw new IOException("identity signature adapter unavailable");
  }

  private static <T extends Adapter> T named(Map<String, T> installed, String name)
      throws IOException {
    T adapter = installed.get(name);
    To2Crypto.require(adapter != null);
    return adapter;
  }

  private static <T extends Adapter> T byWire(Map<String, T> installed, Object id)
      throws IOException {
    for (T adapter : installed.values()) {
      if (adapter.descriptor().wireId.equals(id)) {
        return adapter;
      }
    }
    throw new IOException("algorithm not installed");
  }

  public final class Policy {
    private final List<HashAdapter> hashes;
    private final List<KexAdapter> exchanges;
    private final List<CipherAdapter> ciphers;
    private final int minimum;
    private final boolean hybrid;

    private Policy(List<String> hashNames, List<String> kexNames, List<String> cipherNames,
             int minimum, boolean hybrid) throws IOException, GeneralSecurityException {
      To2Crypto.require(minimum == 128 || minimum == 192);
      this.minimum = minimum;
      this.hybrid = hybrid;
      boolean bound = hashNames.equals(List.of("SHA384"))
          && kexNames.equals(List.of(To2HybridKex.NAME))
          && cipherNames.equals(List.of("A256GCM"));
      To2Crypto.require(!hybrid || bound);
      hashes = allowed(To2Algorithms.this.hashes, hashNames, minimum, false);
      exchanges = allowed(To2Algorithms.this.exchanges, kexNames, minimum, hybrid);
      ciphers = allowed(To2Algorithms.this.ciphers, cipherNames, minimum, false);
      for (CipherAdapter cipher : ciphers) {
        kdf(cipher.kdfName()).checkAvailable();
      }
    }

    /**
     * Selects the first permitted advertised transcript digest.
     * @param advertised Device hash IDs
     * @return matching digest adapter
     * @throws IOException disjoint policy
     */
    public HashAdapter chooseHash(Set<Integer> advertised) throws IOException {
      for (HashAdapter adapter : hashes) {
        if (advertised.contains(adapter.descriptor().wireId)) {
          return adapter;
        }
      }
      throw new IOException("no permitted transcript hash");
    }

    /**
     * Filters operational exchanges by Owner-key compatibility.
     * @param owner verified Owner key
     * @return ordered compatible exchanges
     * @throws IOException empty intersection
     * @throws GeneralSecurityException invalid curve parameters
     */
    public List<KexAdapter> exchanges(PublicKey owner)
        throws IOException, GeneralSecurityException {
      List<KexAdapter> result = new ArrayList<>();
      for (KexAdapter adapter : exchanges) {
        if (adapter.compatible(owner)) {
          result.add(adapter);
        }
      }
      To2Crypto.require(!result.isEmpty());
      return List.copyOf(result);
    }

    public List<CipherAdapter> ciphers() {
      return ciphers;
    }

    public boolean requiresPq() {
      return hybrid;
    }

    /**
     * Checks an identity provider and the configured strength floor.
     * @param key validated Device or Owner key
     * @throws IOException insufficient strength
     * @throws GeneralSecurityException unavailable provider
     */
    public void validateIdentity(PublicKey key) throws IOException, GeneralSecurityException {
      SignatureAdapter adapter = signature(key);
      To2Crypto.require(adapter.descriptor().securityBits >= minimum);
      adapter.checkAvailable();
    }
  }

  private static <T extends Adapter> List<T> allowed(Map<String, T> installed, List<String> names,
                                                    int minimum, boolean hybrid)
      throws IOException, GeneralSecurityException {
    To2Crypto.require(names != null && !names.isEmpty() && names.size() <= 32);
    List<T> result = new ArrayList<>();
    Set<String> unique = new HashSet<>();
    for (String name : names) {
      T adapter = named(installed, name);
      To2Crypto.require(unique.add(name) && adapter.descriptor().securityBits >= minimum
          && (adapter.descriptor().vendorCapability == null
            || (hybrid && To2HybridKex.CAPABILITY.equals(adapter.descriptor().vendorCapability))));
      adapter.checkAvailable();
      result.add(adapter);
    }
    return List.copyOf(result);
  }

  /**
   * Validates ordered allowlists over installed classical implementations.
   * @param hashes local digest identifiers
   * @param exchanges local KEX identifiers
   * @param ciphers local cipher identifiers
   * @param minimum required classical strength
   * @return immutable policy
   * @throws IOException unknown, duplicate or forbidden metadata
   * @throws GeneralSecurityException unavailable provider
   */
  public Policy policy(List<String> hashes, List<String> exchanges, List<String> ciphers,
                       int minimum) throws IOException, GeneralSecurityException {
    return new Policy(hashes, exchanges, ciphers, minimum, false);
  }

  /**
   * Loads strict public JSON policy, or the recorded classical defaults.
   * @param path policy file, or null for defaults
   * @return validated policy
   * @throws IOException invalid configuration
   * @throws GeneralSecurityException provider not operational
   */
  public Policy loadPolicy(Path path) throws IOException, GeneralSecurityException {
    if (path == null) {
      return policy(List.of("SHA384", "SHA256"), List.of("ECDH384", "ECDH256"),
          List.of("A256GCM", "A128GCM"), 128);
    }
    ObjectMapper mapper = new ObjectMapper().enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION);
    mapper.enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS);
    JsonNode json = mapper.readTree(To2OwnerFixtures.read(path, false));
    Set<String> fields = new HashSet<>();
    json.fieldNames().forEachRemaining(fields::add);
    To2Crypto.require(json.isObject() && fields.equals(Set.of("profile", "hashes",
        "kex_preferences", "cipher_preferences", "minimum_security_bits", "require_pq_kex",
        "allow_classical_fallback")));
    boolean hybrid = json.get("profile").asText().equals("hybrid-pq-v1");
    To2Crypto.require(json.get("profile").isTextual());
    To2Crypto.require(hybrid || json.get("profile").asText().equals("classical"));
    To2Crypto.require(json.get("require_pq_kex").isBoolean());
    To2Crypto.require(json.get("require_pq_kex").asBoolean() == hybrid);
    To2Crypto.require(json.get("allow_classical_fallback").isBoolean());
    To2Crypto.require(!json.get("allow_classical_fallback").asBoolean());
    To2Crypto.require(json.get("minimum_security_bits").isIntegralNumber());
    To2Crypto.require(json.get("minimum_security_bits").canConvertToInt());
    List<String> hashes = strings(json.get("hashes"));
    List<String> exchanges = strings(json.get("kex_preferences"));
    List<String> ciphers = strings(json.get("cipher_preferences"));
    int minimum = json.get("minimum_security_bits").asInt();
    return new Policy(hashes, exchanges, ciphers, minimum, hybrid);
  }

  /**
   * Adds an optional isolated PQ operation without changing the classical catalog.
   * @return installed operations; policy checks availability only when selected
   * @throws IOException invalid adapter metadata
   */
  public static To2Algorithms installed() throws IOException {
    To2Algorithms base = classical();
    List<KexAdapter> exchanges = new ArrayList<>(base.exchanges.values());
    exchanges.add(new To2HybridKex());
    return new To2Algorithms(base.hashes.values(), base.signatures.values(), exchanges,
        base.kdfs.values(), base.ciphers.values());
  }

  private static List<String> strings(JsonNode node) throws IOException {
    To2Crypto.require(node.isArray());
    List<String> result = new ArrayList<>();
    for (JsonNode value : node) {
      To2Crypto.require(value.isTextual());
      result.add(value.asText());
    }
    return result;
  }
}