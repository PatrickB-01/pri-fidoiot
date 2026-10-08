package org.fidoalliance.fdo.protocol;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import java.util.concurrent.TimeUnit;

public final class To2HybridKex implements To2Algorithms.KexAdapter {
  public static final String CAPABILITY = "com.example.fdo.pq-kex-v1";
  public static final String NAME = "com.example.ecdh384-mlkem768-v1";
  public static final int PROOF_LIMIT = 4096;
  private static final byte[] DOMAIN = ("thesis-to2-pq-v1;ECDH384;ML-KEM-768;SHA3-256;"
      + "FDO-HMAC-SHA256;SHA384;A256GCM;Device=xA;Owner=xB")
      .getBytes(StandardCharsets.US_ASCII);

  @Override
  public To2Algorithms.Descriptor descriptor() {
    return new To2Algorithms.Descriptor(NAME, NAME, 192, "P384+ML-KEM-768;SHA3-256", CAPABILITY);
  }

  @Override
  public int publicMessageBytes() {
    return 1336;
  }

  @Override
  public String roles() {
    return "Device=xA:EK;Owner=xB:ciphertext";
  }

  @Override
  public boolean compatible(PublicKey owner) throws IOException, GeneralSecurityException {
    return To2Crypto.width(owner) == 48;
  }

  @Override
  public To2Algorithms.KexState initiate(PublicKey owner)
      throws IOException, GeneralSecurityException {
    To2Crypto.require(compatible(owner));
    return new State(owner, true);
  }

  @Override
  public To2Algorithms.KexState respond(PublicKey owner)
      throws IOException, GeneralSecurityException {
    To2Crypto.require(compatible(owner));
    return new State(owner, false);
  }

  @Override
  public void checkAvailable() throws IOException, GeneralSecurityException {
    KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
    generator.initialize(new ECGenParameterSpec("secp384r1"));
    PublicKey owner = generator.generateKeyPair().getPublic();
    try (To2Algorithms.KexState device = initiate(owner);
        To2Algorithms.KexState remote = respond(owner)) {
      byte[] shared = remote.complete(device.contribution());
      byte[] other = device.complete(remote.contribution());
      try {
        To2Crypto.require(MessageDigest.isEqual(shared, other));
      } finally {
        Arrays.fill(shared, (byte) 0);
        Arrays.fill(other, (byte) 0);
      }
    }
  }

  static byte[] provider(String operation, byte[] input, int expected) throws IOException {
    String configured = System.getProperty("to2.pq.provider.directory");
    To2Crypto.require(configured != null);
    Path directory = Path.of(configured).toRealPath();
    To2Crypto.require(Files.isRegularFile(directory.resolve("MlKemProvider.class"))
        && Files.isRegularFile(directory.resolve("bcprov.jar")));
    String executable = Path.of(System.getProperty("java.home"), "bin", "java").toString();
    String classpath = directory + java.io.File.pathSeparator + directory.resolve("bcprov.jar");
    Process process = new ProcessBuilder(executable, "-Xmx32m", "-cp", classpath,
        "MlKemProvider", operation).redirectError(ProcessBuilder.Redirect.DISCARD).start();
    try {
      try (java.io.OutputStream output = process.getOutputStream()) {
        output.write(input);
      }
      To2Crypto.require(process.waitFor(10, TimeUnit.SECONDS) && process.exitValue() == 0);
      byte[] result = process.getInputStream().readNBytes(expected + 1);
      To2Crypto.require(result.length == expected);
      return result;
    } catch (InterruptedException exception) {
      Thread.currentThread().interrupt();
      throw new IOException("ML-KEM provider interrupted");
    } finally {
      process.destroyForcibly();
      process.getInputStream().close();
    }
  }

  static byte[] combine(byte[] classical, byte[] kem, byte[] device, byte[] publicKey,
                        byte[] owner, byte[] ciphertext)
      throws IOException, GeneralSecurityException {
    To2Crypto.require(classical.length == 48 && kem.length == 32 && device.length == 150
        && owner.length == 150 && publicKey.length == 1184 && ciphertext.length == 1088);
    byte[] input = To2Crypto.array(classical, kem, owner, ciphertext, device, publicKey, DOMAIN)
        .EncodeToBytes();
    try {
      return MessageDigest.getInstance("SHA3-256").digest(input);
    } finally {
      Arrays.fill(input, (byte) 0);
    }
  }

  private static byte[] pack(boolean device, byte[] classical, byte[] kem) {
    return To2Crypto.concat(new byte[] {1, (byte) (device ? 0 : 1)}, classical, kem);
  }

  private static final class State implements To2Algorithms.KexState {
    private final boolean device;
    private To2Algorithms.KexState classical;
    private byte[] privateKey;
    private byte[] publicKey;
    private byte[] wire;
    private boolean used;

    State(PublicKey owner, boolean device) throws IOException, GeneralSecurityException {
      this.device = device;
      To2Algorithms.KexAdapter adapter = To2Algorithms.classical().exchange("ECDH384");
      classical = device ? adapter.initiate(owner) : adapter.respond(owner);
      try {
        if (device) {
          byte[] pair = provider("keygen", new byte[0], 3584);
          try {
            publicKey = Arrays.copyOfRange(pair, 0, 1184);
            privateKey = Arrays.copyOfRange(pair, 1184, 3584);
          } finally {
            Arrays.fill(pair, (byte) 0);
          }
          wire = pack(true, classical.contribution(), publicKey);
        }
      } catch (IOException exception) {
        close();
        throw exception;
      }
    }

    @Override
    public byte[] contribution() throws IOException {
      To2Crypto.require(classical != null && wire != null);
      return wire.clone();
    }

    @Override
    public byte[] complete(byte[] peer) throws IOException, GeneralSecurityException {
      To2Crypto.require(classical != null && !used);
      used = true;
      To2Crypto.require(peer.length == (device ? 1240 : 1336)
          && peer[0] == 1 && peer[1] == (device ? 1 : 0));
      byte[] remote = Arrays.copyOfRange(peer, 2, 152);
      byte[] local = classical.contribution();
      byte[] shared = classical.complete(remote);
      byte[] secret = null;
      byte[] providerInput = null;
      try {
        byte[] ciphertext;
        if (device) {
          ciphertext = Arrays.copyOfRange(peer, 152, peer.length);
          providerInput = To2Crypto.concat(privateKey, ciphertext);
          secret = provider("decaps", providerInput, 32);
        } else {
          publicKey = Arrays.copyOfRange(peer, 152, peer.length);
          byte[] result = provider("encaps", publicKey, 1120);
          try {
            ciphertext = Arrays.copyOfRange(result, 0, 1088);
            secret = Arrays.copyOfRange(result, 1088, 1120);
          } finally {
            Arrays.fill(result, (byte) 0);
          }
          wire = pack(false, local, ciphertext);
        }
        return combine(Arrays.copyOf(shared, 48), secret, device ? local : remote,
            publicKey, device ? remote : local, ciphertext);
      } finally {
        Arrays.fill(shared, (byte) 0);
        if (secret != null) {
          Arrays.fill(secret, (byte) 0);
        }
        if (providerInput != null) {
          Arrays.fill(providerInput, (byte) 0);
        }
        if (privateKey != null) {
          Arrays.fill(privateKey, (byte) 0);
          privateKey = null;
        }
        classical.close();
      }
    }

    @Override
    public void close() {
      if (classical != null) {
        classical.close();
      }
      if (privateKey != null) {
        Arrays.fill(privateKey, (byte) 0);
      }
      privateKey = publicKey = wire = null;
      classical = null;
    }
  }
}