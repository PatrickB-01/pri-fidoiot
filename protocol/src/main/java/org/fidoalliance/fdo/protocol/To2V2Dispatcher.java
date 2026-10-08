package org.fidoalliance.fdo.protocol;

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;
import java.io.IOException;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.util.ArrayDeque;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import org.fidoalliance.fdo.protocol.dispatch.MessageDispatcher;
import org.fidoalliance.fdo.protocol.message.ErrorCode;
import org.fidoalliance.fdo.protocol.message.MsgType;
import org.fidoalliance.fdo.protocol.message.ProtocolVersion;
import org.fidoalliance.fdo.protocol.message.ServiceInfoKeyValuePair;
import org.fidoalliance.fdo.protocol.message.ServiceInfoModuleState;
import org.fidoalliance.fdo.protocol.message.v200.To2Codec;
import org.fidoalliance.fdo.protocol.message.v200.To2Messages;

public class To2V2Dispatcher implements MessageDispatcher, AutoCloseable {

  public static final String CONTRACT_CAPABILITY = "org.example.thesis.to2-contract-v1";
  public static final int OWNER_PROOF_LIMIT = 1300;
  private static final int SERVICE_INFO_LIMIT = 8192;
  private final To2OwnerFixtures fixtures;
  private final EstBootstrapPlanSupplier estPlans;
  private final To2Algorithms algorithms;
  private final To2Algorithms.Policy policy;
  private final To2SessionStore<Session> sessions;
  private final ScheduledExecutorService sweeper;
  private final int maxRounds;

  private final class Session implements AutoCloseable {
    private To2OwnerFixtures.Identity identity;
    private final byte[] guid;
    private byte[] probe;
    private byte[] ack;
    private byte[] challenge;
    private byte[] setupNonce;
    private final To2Algorithms.HashAdapter hash;
    private final Map<String, To2Algorithms.KexAdapter> offeredExchanges = new HashMap<>();
    private final Map<Integer, To2Algorithms.CipherAdapter> offeredCiphers = new HashMap<>();
    private final int deviceLimit;
    private int proofLimit = OWNER_PROOF_LIMIT;
    private int ownerInfoLimit;
    private int nextEntry;
    private int rounds;
    private MsgType expected = MsgType.TO2_PROVE_DEVICE20;
    private To2Algorithms.Channel channel;
    private boolean provisioning;
    private boolean firstInfo = true;
    private boolean moreOwner;
    private boolean done;
    private CBORObject replacementMac;
    private final Map<String, CBORObject> devmod = new HashMap<>();
    private final Set<String> modules = new HashSet<>();
    private final ArrayDeque<CBORObject> pending = new ArrayDeque<>();
    private int moduleOffset;
    private byte[] terminalRequest;
    private byte[] terminalResponse;
    private EstOwnerModule est;
    private ServiceInfoModuleState estState;

    private Session(To2OwnerFixtures.Identity identity, byte[] probe, int deviceLimit,
            To2Algorithms.HashAdapter hash) {
      this.identity = identity;
      this.guid = identity.header.get(1).GetByteString();
      this.probe = probe.clone();
      this.deviceLimit = deviceLimit;
      this.hash = hash;
      this.challenge = To2Crypto.random(16);
    }

    private void releaseSecrets() {
      if (est != null) {
        est.close();
        est = null;
        estState = null;
      }
      if (channel != null) {
        channel.close();
        channel = null;
      }
      identity = null;
      probe = null;
      ack = null;
      challenge = null;
      setupNonce = null;
      replacementMac = null;
      devmod.clear();
      modules.clear();
      pending.clear();
      offeredExchanges.clear();
      offeredCiphers.clear();
      fixtures.release(guid);
    }

    @Override
    public void close() {
      releaseSecrets();
      terminalRequest = null;
      terminalResponse = null;
    }
  }

  /**
   * Starts a configured Owner, or retains the unconfigured fail-closed boundary.
   * @throws IOException invalid explicit configuration
   */
  public To2V2Dispatcher() throws IOException {
    this(configuredFixtures());
  }

  /**
   * Uses a catalog supplied by trusted installed code, never by JSON class names.
   * @param installed validated adapter registry
   * @throws IOException invalid fixtures, policy or provider
   */
  public To2V2Dispatcher(To2Algorithms installed) throws IOException {
    this(configuredFixtures(), System::nanoTime, true, installed);
  }

  To2V2Dispatcher(To2OwnerFixtures fixtures) throws IOException {
    this(fixtures, System::nanoTime, true);
  }

  To2V2Dispatcher(To2OwnerFixtures fixtures, java.util.function.LongSupplier clock,
                  boolean sweep) throws IOException {
    this(fixtures, clock, sweep, To2Algorithms.installed());
  }

  private To2V2Dispatcher(To2OwnerFixtures fixtures, java.util.function.LongSupplier clock,
                          boolean sweep, To2Algorithms installed) throws IOException {
    this.fixtures = fixtures;
    String plans = System.getProperty("to2.est.plan.directory");
    String authorization = System.getProperty("to2.est.authorization.directory");
    To2Crypto.require((plans == null) == (authorization == null));
    To2Crypto.require(plans == null || fixtures != null);
    estPlans = plans == null ? null
      : new EstBootstrapPlanSupplier(Path.of(plans), Path.of(authorization));
    try {
      To2Crypto.require(installed != null);
      algorithms = installed;
      String path = System.getProperty("to2.crypto.policy");
      policy = algorithms.loadPolicy(path == null ? null : Path.of(path));
      if (fixtures != null) {
        fixtures.validatePolicy(policy);
      }
    } catch (GeneralSecurityException | RuntimeException exception) {
      throw new IOException("v200 crypto policy unavailable");
    }
    maxRounds = boundedProperty("to2.max.rounds", 100, 1, 1000);
    sessions = new To2SessionStore<>(boundedProperty("to2.max.sessions", 64, 1, 256),
        TimeUnit.SECONDS.toNanos(boundedProperty("to2.session.ttl.seconds", 300, 1, 600)),
        clock);
    if (fixtures == null || !sweep) {
      sweeper = null;
    } else {
      sweeper = Executors.newSingleThreadScheduledExecutor(task -> {
        Thread thread = new Thread(task, "to2-session-expiry");
        thread.setDaemon(true);
        return thread;
      });
      sweeper.scheduleWithFixedDelay(sessions::expire, 1, 1, TimeUnit.SECONDS);
    }
  }

  private static int boundedProperty(String name, int fallback, int minimum, int maximum) {
    int value = Integer.parseInt(System.getProperty(name, Integer.toString(fallback)));
    if (value < minimum || value > maximum) {
      throw new IllegalArgumentException("invalid Owner limit");
    }
    return value;
  }

  private static To2OwnerFixtures configuredFixtures() throws IOException {
    String directory = System.getProperty("to2.owner.directory");
    String ca = System.getProperty("to2.device.ca");
    String output = System.getProperty("to2.output.directory");
    if (directory == null && ca == null && output == null) {
      return null;
    }
    try {
      To2Crypto.require(directory != null && ca != null && output != null);
      return new To2OwnerFixtures(Path.of(directory), Path.of(ca), Path.of(output));
    } catch (Exception exception) {
      throw new IOException("invalid v200 Owner configuration");
    }
  }

  @Override
  public Optional<DispatchMessage> dispatch(DispatchMessage request) throws IOException {
    if (request.getMsgType() == MsgType.ERROR) {
      request.getAuthToken().ifPresent(sessions::remove);
      return Optional.empty();
    }
    if (request.getMsgType() == MsgType.TO2_HELLO_DEVICE_PROBE
        && request.getAuthToken().isEmpty()) {
      return probe(request);
    }
    if (request.getAuthToken().isEmpty()) {
      try {
        To2Codec.decodeWire(request.getMsgType(), request.getMessage());
      } catch (IOException exception) {
        return plainError(request, 100);
      }
      return plainError(request, 1);
    }
    try {
      return sessions.execute(request.getAuthToken().get(), session -> advance(request, session));
    } catch (IOException exception) {
      return plainError(request, 1);
    }
  }

  private Optional<DispatchMessage> probe(DispatchMessage request) throws IOException {
    CBORObject probe;
    try {
      probe = To2Codec.decodeWire(request.getMsgType(), request.getMessage()).getValue();
    } catch (Exception exception) {
      return plainError(request, 100);
    }
    byte[] flags = probe.get(0).GetByteString();
    if (flags.length == 0 || (flags[0] & 4) == 0) {
      return plainError(request, 7);
    }
    if ((flags[0] & 0x80) != 0 || probe.get(1).getValues().stream()
        .noneMatch(value -> CONTRACT_CAPABILITY.equals(value.AsString()))) {
      return plainError(request, 103);
    }
    if (fixtures == null) {
      return plainError(request, 500);
    }
    if (policy.requiresPq() && probe.get(1).getValues().stream()
        .noneMatch(value -> To2HybridKex.CAPABILITY.equals(value.AsString()))) {
      return plainError(request, 103);
    }
    Session session = null;
    try {
      int limit = probe.get(3).AsInt32();
      To2Crypto.require(limit >= OWNER_PROOF_LIMIT && limit <= To2Codec.MAX_MESSAGE_BYTES);
      Set<Integer> hashes = new HashSet<>();
      for (CBORObject value : probe.get(4).getValues()) {
        To2Crypto.require(hashes.add(value.AsInt32()));
      }
      To2Algorithms.HashAdapter hash = policy.chooseHash(hashes);
      To2OwnerFixtures.Identity identity = fixtures.reserve(probe.get(2).GetByteString());
      session = new Session(identity, request.getMessage(), limit, hash);
      CBORObject vendors = To2Crypto.array(CONTRACT_CAPABILITY);
      if (policy.requiresPq()) {
        To2Crypto.require(limit >= To2HybridKex.PROOF_LIMIT);
        session.proofLimit = To2HybridKex.PROOF_LIMIT;
        vendors.Add(To2HybridKex.CAPABILITY);
      }
      PublicKey owner = To2Crypto.publicKey(identity.ownerPublic);
      CBORObject exchanges = CBORObject.NewArray();
      for (To2Algorithms.KexAdapter adapter : policy.exchanges(owner)) {
        String name = (String) adapter.descriptor().wireId;
        exchanges.Add(name);
        session.offeredExchanges.put(name, adapter);
      }
      CBORObject ciphers = CBORObject.NewArray();
      for (To2Algorithms.CipherAdapter adapter : policy.ciphers()) {
        int id = (Integer) adapter.descriptor().wireId;
        ciphers.Add(id);
        session.offeredCiphers.put(id, adapter);
      }
      CBORObject initialHash = To2Crypto.hash(identity.identityHash,
          identity.header.get(4).EncodeToBytes());
      CBORObject ack = To2Crypto.array(new byte[] {4}, vendors,
          session.guid, To2Codec.MAX_MESSAGE_BYTES,
          exchanges, ciphers, session.challenge,
          hash.digest(session.probe, initialHash.EncodeToBytes()));
      session.ack = To2Codec.encodePlaintext(MsgType.TO2_HELLO_DEVICE_ACK20, ack);
      String token = sessions.create(session);
      return Optional.of(reply(MsgType.TO2_HELLO_DEVICE_ACK20, session.ack, token));
    } catch (Exception exception) {
      if (session != null) {
        session.close();
      }
      return plainError(request, 101);
    }
  }

  private Optional<DispatchMessage> advance(DispatchMessage request, Session session)
      throws IOException {
    String token = request.getAuthToken().get();
    if (session.terminalResponse != null) {
      if (request.getMsgType() == MsgType.TO2_DONE20 && MessageDigest.isEqual(
          request.getMessage(), session.terminalRequest)) {
        return Optional.of(reply(MsgType.TO2_DONE_ACK20, session.terminalResponse, token));
      }
      sessions.remove(token);
      return plainError(request, 101);
    }
    try {
      To2Crypto.require(request.getProtocolVersion() == ProtocolVersion.V200
          && ++session.rounds <= maxRounds
          && (request.getMsgType() == session.expected
              || (session.done && request.getMsgType() == MsgType.TO2_DEVICE_SVC_INFO20)));
      if (request.getMsgType() == MsgType.TO2_DEVICE_SERVICE_INFO_RDY20) {
        session.provisioning = true;
      }
      CBORObject body;
      try {
        if (request.getMsgType().toInteger() >= 86) {
          session.channel.validate(request.getMessage());
          body = null;
        } else {
          body = To2Codec.decodeWire(request.getMsgType(), request.getMessage()).getValue();
        }
      } catch (IOException exception) {
        return terminate(request, session, 100);
      }
      if (request.getMsgType().toInteger() >= 86) {
        byte[] plaintext = session.channel.decrypt(request.getMessage());
        try {
          body = To2Codec.decodePlaintext(request.getMsgType(), plaintext).getValue();
        } finally {
          Arrays.fill(plaintext, (byte) 0);
        }
      }
      switch (request.getMsgType()) {
        case TO2_PROVE_DEVICE20:
          return Optional.of(prove(request, session, body));
        case TO2_GET_OV_NEXT_ENTRY20:
          return Optional.of(entry(request, session, body));
        case TO2_DEVICE_SERVICE_INFO_RDY20:
          return Optional.of(setup(request, session, body));
        case TO2_DEVICE_SVC_INFO20:
          return Optional.of(serviceInfo(request, session, body));
        case TO2_DONE20:
          return Optional.of(complete(request, session, body));
        default:
          return terminate(request, session, 101);
      }
    } catch (Exception exception) {
      return terminate(request, session, 101);
    }
  }

  private DispatchMessage prove(DispatchMessage request, Session session, CBORObject signed)
      throws IOException, GeneralSecurityException {
    To2Algorithms.SignatureAdapter signature = algorithms.signature(session.identity.deviceKey);
    String deviceDomain = "FDO-TO2-ProveDevice-v1";
    CBORObject payload = signature.verify(signed, session.identity.deviceKey, deviceDomain);
    To2Crypto.require(MessageDigest.isEqual(session.challenge,
        payload.get(CBORObject.FromObject(10)).GetByteString()));
    To2Crypto.require(MessageDigest.isEqual(To2Crypto.concat(new byte[] {1}, session.guid),
        payload.get(CBORObject.FromObject(256)).GetByteString()));
    CBORObject selection = payload.get(CBORObject.FromObject(-257));
    PublicKey owner = To2Crypto.publicKey(session.identity.ownerPublic);
    To2Algorithms.KexAdapter exchange = session.offeredExchanges.get(selection.get(0).AsString());
    To2Algorithms.CipherAdapter cipher = session.offeredCiphers.get(selection.get(1).AsInt32());
    To2Crypto.require(exchange != null && cipher != null && exchange.compatible(owner));
    To2Crypto.equalHash(session.hash.digest(session.ack), selection.get(4));
    byte[] contribution;
    try (To2Algorithms.KexState state = exchange.respond(owner)) {
      byte[] shared = state.complete(selection.get(2).GetByteString());
      try {
        byte[] key = algorithms.kdf(cipher.kdfName()).derive(shared, cipher.keyBytes());
        try {
          session.channel = cipher.open(key);
        } finally {
          Arrays.fill(key, (byte) 0);
        }
        contribution = state.contribution();
      } finally {
        Arrays.fill(shared, (byte) 0);
      }
    }
    CBORObject proof = To2Crypto.array(session.identity.voucher.get(1),
        session.identity.voucher.get(4).size(), session.identity.voucher.get(2), selection.get(3),
        contribution, To2Codec.MAX_MESSAGE_BYTES, session.identity.ownerPublic, null);
    To2Algorithms.SignatureAdapter ownerSigner = algorithms.signature(owner);
    String ownerDomain = "FDO-TO2-ProveOVHdr-v1";
    CBORObject signedProof = ownerSigner.sign(proof, session.identity.ownerKey, owner, ownerDomain);
    byte[] wire = To2Codec.encodePlaintext(MsgType.TO2_PROVE_OV_HDR20, signedProof);
    To2Crypto.require(wire.length <= Math.min(session.proofLimit, session.deviceLimit));
    session.expected = session.identity.voucher.get(4).size() == 0
        ? MsgType.TO2_DEVICE_SERVICE_INFO_RDY20 : MsgType.TO2_GET_OV_NEXT_ENTRY20;
    return reply(MsgType.TO2_PROVE_OV_HDR20, wire, request.getAuthToken().get());
  }

  private DispatchMessage entry(DispatchMessage request, Session session, CBORObject body)
      throws IOException {
    To2Crypto.require(body.get(0).AsInt32() == session.nextEntry);
    CBORObject entries = session.identity.voucher.get(4);
    To2Crypto.require(session.nextEntry < entries.size());
    byte[] wire = To2Codec.encodePlaintext(MsgType.TO2_OV_NEXT_ENTRY20,
        To2Crypto.array(session.nextEntry, entries.get(session.nextEntry)));
    To2Crypto.require(wire.length <= session.deviceLimit);
    if (++session.nextEntry == entries.size()) {
      session.expected = MsgType.TO2_DEVICE_SERVICE_INFO_RDY20;
    }
    return reply(MsgType.TO2_OV_NEXT_ENTRY20, wire, request.getAuthToken().get());
  }

  private DispatchMessage setup(DispatchMessage request, Session session, CBORObject body)
      throws IOException, GeneralSecurityException {
    session.setupNonce = body.get(2).GetByteString();
    session.ownerInfoLimit = body.get(1).isNull() ? OWNER_PROOF_LIMIT : body.get(1).AsInt32();
    To2Crypto.require(session.ownerInfoLimit >= 128
        && session.ownerInfoLimit <= SERVICE_INFO_LIMIT);
    CBORObject replacement = session.identity.replacement;
    CBORObject payload = To2Crypto.array(1, To2Crypto.array(replacement.get("rv_info"),
        replacement.get("guid"), session.setupNonce, replacement.get("public_key")),
        SERVICE_INFO_LIMIT);
    PublicKey replacementKey = To2Crypto.publicKey(replacement.get("public_key"));
    To2Algorithms.SignatureAdapter signer = algorithms.signature(replacementKey);
    String setupDomain = "FDO-TO2-SetupDevice-v1";
    java.security.PrivateKey privateKey = session.identity.replacementKey;
    CBORObject signed = signer.sign(payload, privateKey, replacementKey, setupDomain);
    DispatchMessage response = encrypted(request, session, MsgType.TO2_SETUP_DEVICE20,
        signed, session.deviceLimit);
    session.expected = MsgType.TO2_DEVICE_SVC_INFO20;
    return response;
  }

  private DispatchMessage serviceInfo(DispatchMessage request, Session session, CBORObject body)
      throws IOException, GeneralSecurityException {
    To2Crypto.require(request.getMessage().length <= SERVICE_INFO_LIMIT);
    if (session.firstInfo) {
      To2Crypto.require(!body.get(0).isNull() && body.get(0).get(0).AsInt32()
          == (session.identity.identityHash == -16 ? 5 : 6));
      session.replacementMac = body.get(0);
      session.firstInfo = false;
    } else {
      To2Crypto.require(body.get(0).isNull());
    }
    boolean moreDevice = body.get(1).AsBoolean();
    if (session.moreOwner || session.done) {
      To2Crypto.require(!moreDevice && body.get(2).size() == 0);
    }
    for (CBORObject item : body.get(2).getValues()) {
      receiveServiceInfo(session, item);
    }
    CBORObject outgoing = CBORObject.NewArray();
    if (!moreDevice) {
      validateDevmod(session);
      if (estPlans != null && session.est == null && !session.done) {
        To2Crypto.require(session.modules.contains(EstOwnerModule.NAME)
            && estPlans.contains(session.guid));
        session.est = new EstOwnerModule(estPlans, session.guid);
        session.estState = new ServiceInfoModuleState();
        session.estState.setName(EstOwnerModule.NAME);
        session.estState.setMtu(Math.min(session.deviceLimit, session.ownerInfoLimit));
        session.est.prepare(session.estState);
      }
      while (!session.pending.isEmpty()) {
        CBORObject candidate = To2Codec.decodeObject(outgoing.EncodeToBytes());
        candidate.Add(session.pending.peek());
        int size = To2Crypto.array(false, false, candidate).EncodeToBytes().length + 40;
        if (size > Math.min(session.deviceLimit, session.ownerInfoLimit)) {
          To2Crypto.require(outgoing.size() > 0);
          break;
        }
        outgoing.Add(session.pending.remove());
      }
      if (session.est != null && session.pending.isEmpty()) {
        session.est.send(session.estState, item -> {
          CBORObject candidate = To2Codec.decodeObject(outgoing.EncodeToBytes());
          candidate.Add(To2Crypto.array(item.getKey(), item.getValue().clone()));
          int size = To2Crypto.array(false, false, candidate).EncodeToBytes().length + 40;
          if (size > session.estState.getMtu()) {
            To2Crypto.require(outgoing.size() > 0);
            return false;
          }
          outgoing.Add(To2Crypto.array(item.getKey(), item.getValue().clone()));
          return true;
        });
      }
    }
    boolean moreEst = session.estState != null && session.estState.isMore();
    session.moreOwner = !moreDevice && (!session.pending.isEmpty() || moreEst);
    boolean readyEst = estPlans == null
        || (session.estState != null && session.estState.isDone());
    session.done = !moreDevice && outgoing.size() == 0 && session.pending.isEmpty() && readyEst;
    if (session.done) {
      session.expected = MsgType.TO2_DONE20;
    }
    return encrypted(request, session, MsgType.TO2_OWNER_SVC_INFO20,
        To2Crypto.array(session.moreOwner, session.done, outgoing),
        Math.min(session.deviceLimit, session.ownerInfoLimit));
  }

  private void receiveServiceInfo(Session session, CBORObject item) throws IOException {
    String name = item.get(0).AsString();
    CBORObject value = To2Codec.decodeObject(item.get(1).GetByteString());
    if (name.startsWith(EstOwnerModule.NAME + ":") && estPlans != null) {
      To2Crypto.require(session.est != null && !session.done);
      ServiceInfoKeyValuePair pair = new ServiceInfoKeyValuePair();
      pair.setKeyName(name);
      pair.setValue(item.get(1).GetByteString());
      session.est.receive(session.estState, pair);
      return;
    }
    if (!name.startsWith("devmod:")) {
      To2Crypto.require(name.matches("[a-zA-Z0-9._-]{1,128}:active")
          && value.getType() == CBORType.Boolean && session.pending.size() < 128);
      if (value.AsBoolean()) {
        session.pending.add(To2Crypto.array(name, CBORObject.False.EncodeToBytes()));
      }
      return;
    }
    String field = name.substring(7);
    if (field.equals("modules")) {
      To2Crypto.require(value.getType() == CBORType.Array && value.size() >= 2
          && value.get(0).getType() == CBORType.Integer
          && value.get(1).getType() == CBORType.Integer
          && value.get(0).AsInt32() == session.moduleOffset
          && value.get(1).AsInt32() == value.size() - 2);
      for (int index = 2; index < value.size(); index++) {
        To2Crypto.require(value.get(index).getType() == CBORType.TextString
            && value.get(index).AsString().matches("[a-zA-Z0-9._-]{1,128}")
            && session.modules.size() < 128 && session.modules.add(value.get(index).AsString()));
        session.moduleOffset++;
      }
      session.devmod.put(field, CBORObject.True);
      return;
    }
    To2Crypto.require(!session.devmod.containsKey(field));
    if (field.equals("active")) {
      To2Crypto.require(value.equals(CBORObject.True));
    } else if (field.equals("nummodules")) {
      To2Crypto.require(value.getType() == CBORType.Integer
          && value.AsInt32() >= 0 && value.AsInt32() <= 128);
    } else {
      To2Crypto.require(Set.of("os", "arch", "version", "device", "sep", "bin", "sn",
          "pathsep", "nl", "tmp", "dir", "progenv", "mudurl").contains(field)
          && (value.getType() == CBORType.TextString
              || (field.equals("sn") && value.getType() == CBORType.ByteString)));
    }
    session.devmod.put(field, value);
  }

  private void validateDevmod(Session session) throws IOException {
    To2Crypto.require(session.devmod.keySet().containsAll(List.of("active", "os", "arch",
        "version", "device", "sep", "bin", "nummodules", "modules"))
        && session.devmod.get("nummodules").AsInt32() == session.moduleOffset);
  }

  private DispatchMessage complete(DispatchMessage request, Session session, CBORObject body)
      throws IOException, GeneralSecurityException {
    To2Crypto.require(session.done && session.replacementMac != null
        && MessageDigest.isEqual(session.challenge, body.get(0).GetByteString()));
    DispatchMessage response = encrypted(request, session, MsgType.TO2_DONE_ACK20,
        To2Crypto.array(session.setupNonce), session.deviceLimit);
    fixtures.complete(session.identity, session.replacementMac);
    session.terminalRequest = request.getMessage().clone();
    session.terminalResponse = response.getMessage().clone();
    session.releaseSecrets();
    sessions.shorten(request.getAuthToken().get(), TimeUnit.SECONDS.toNanos(10));
    return response;
  }

  private DispatchMessage encrypted(DispatchMessage request, Session session, MsgType type,
                                    CBORObject body, int limit)
      throws IOException, GeneralSecurityException {
    byte[] plaintext = To2Codec.encodePlaintext(type, body);
    try {
      byte[] wire = session.channel.encrypt(plaintext);
      To2Crypto.require(wire.length <= limit);
      return reply(type, wire, request.getAuthToken().get());
    } finally {
      Arrays.fill(plaintext, (byte) 0);
    }
  }

  private Optional<DispatchMessage> terminate(DispatchMessage request, Session session, int code)
      throws IOException {
    byte[] raw = To2Codec.error(code, request.getMsgType().toInteger());
    try {
      if (session.provisioning && session.channel != null) {
        raw = session.channel.encrypt(raw);
      }
      return Optional.of(reply(MsgType.ERROR, raw, request.getAuthToken().get()));
    } catch (GeneralSecurityException exception) {
      return plainError(request, code);
    } finally {
      sessions.remove(request.getAuthToken().get());
    }
  }

  /**
   * Handles transport failures through the same protection and destruction boundary.
   * @param request rejected request metadata
   * @param code sanitized error code
   * @return phase-correct Error or empty response to incoming Error
   * @throws IOException response encoding failure
   */
  public Optional<DispatchMessage> failure(DispatchMessage request, int code) throws IOException {
    if (request.getMsgType() == MsgType.ERROR) {
      request.getAuthToken().ifPresent(sessions::remove);
      return Optional.empty();
    }
    if (request.getAuthToken().isPresent()) {
      try {
        return sessions.execute(request.getAuthToken().get(),
            session -> {
              if (session.expected == MsgType.TO2_DEVICE_SERVICE_INFO_RDY20
                  && request.getMsgType() == MsgType.TO2_DEVICE_SERVICE_INFO_RDY20) {
                session.provisioning = true;
              }
              return terminate(request, session, code);
            });
      } catch (IOException exception) {
        return plainError(request, code);
      }
    }
    return plainError(request, code);
  }

  private Optional<DispatchMessage> plainError(DispatchMessage request, int code)
      throws IOException {
    return Optional.of(reply(MsgType.ERROR,
        To2Codec.error(code, request.getMsgType().toInteger()), null));
  }

  private DispatchMessage reply(MsgType type, byte[] wire, String token) {
    DispatchMessage response = new DispatchMessage();
    response.setProtocolVersion(ProtocolVersion.V200);
    response.setMsgType(type);
    response.setMessage(wire);
    response.setAuthToken(token);
    return response;
  }

  @Override
  public void close() {
    if (sweeper != null) {
      sweeper.shutdownNow();
    }
    sessions.close();
  }

  public boolean isConfigured() {
    return fixtures != null;
  }
}