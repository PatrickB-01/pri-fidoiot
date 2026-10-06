package org.fidoalliance.fdo.protocol;

import com.upokecenter.cbor.CBORObject;
import java.io.IOException;
import java.security.MessageDigest;
import java.util.ArrayDeque;
import java.util.Arrays;
import java.util.Set;
import org.apache.commons.codec.binary.Hex;
import org.fidoalliance.fdo.protocol.dispatch.ServiceInfoModule;
import org.fidoalliance.fdo.protocol.dispatch.ServiceInfoSendFunction;
import org.fidoalliance.fdo.protocol.message.ServiceInfoKeyValuePair;
import org.fidoalliance.fdo.protocol.message.ServiceInfoModuleState;
import org.fidoalliance.fdo.protocol.message.v200.To2Codec;

final class EstOwnerModule implements ServiceInfoModule, AutoCloseable {
  static final String NAME = "com.example.est-1";
  private final EstBootstrapPlanSupplier supplier;
  private final byte[] guid;
  private final ArrayDeque<ServiceInfoKeyValuePair> pending = new ArrayDeque<>();
  private final String transaction = Hex.encodeHexString(To2Crypto.random(16));
  private byte[] digest;
  private long revision;
  private long expiry;
  private boolean finishSent;

  EstOwnerModule(EstBootstrapPlanSupplier supplier, byte[] guid) {
    this.supplier = supplier;
    this.guid = guid.clone();
  }

  @Override
  public String getName() {
    return NAME;
  }

  @Override
  public void prepare(ServiceInfoModuleState state) throws IOException {
    To2Crypto.require(pending.isEmpty() && !state.getActiveSent());
    pending.add(pair("active", CBORObject.True));
  }

  @Override
  public void receive(ServiceInfoModuleState state, ServiceInfoKeyValuePair item)
      throws IOException {
    CBORObject value = To2Codec.decodeObject(item.getValue());
    if (item.getKey().equals(NAME + ":active")) {
      To2Crypto.require(state.getActiveSent() && value.equals(CBORObject.True));
      if (!state.isActive()) {
        state.setActive(true);
        load(state);
      }
      return;
    }
    To2Crypto.require(item.getKey().equals(NAME + ":status") && state.isActive() && finishSent);
    Set<String> fields = Set.of("transaction_id", "status", "revision", "digest");
    EstBootstrapPlanSupplier.fields(value, fields);
    To2Crypto.require(value.get("transaction_id").equals(CBORObject.FromObject(transaction))
        && value.get("status").equals(CBORObject.FromObject("ready"))
        && value.get("revision").equals(CBORObject.FromObject(revision))
        && MessageDigest.isEqual(digest, value.get("digest").GetByteString())
        && expiry > java.time.Instant.now().getEpochSecond());
    state.setDone(true);
  }

  private void load(ServiceInfoModuleState state) throws IOException {
    CBORObject plan = supplier.authenticatedPlan(guid);
    CBORObject config = plan.get("configuration");
    try {
      byte[] canonical = EstBootstrapPlanSupplier.canonical(config);
      digest = MessageDigest.getInstance("SHA-256").digest(canonical);
      Arrays.fill(canonical, (byte) 0);
    } catch (java.security.GeneralSecurityException exception) {
      throw new IOException("EST digest unavailable");
    }
    revision = config.get("revision").AsInt64();
    expiry = config.get("expires_at").AsInt64();
    CBORObject begin = operation();
    begin.Add("expected_revision", plan.get("expected_revision"));
    begin.Add("mode", plan.get("mode"));
    pending.add(pair("begin", begin));
    int sequence = 0;
    for (CBORObject name : config.getKeys()) {
      CBORObject put = operation();
      put.Add("sequence", sequence);
      put.Add("name", name);
      put.Add("value", config.get(name));
      ServiceInfoKeyValuePair item = pair("put", put);
      if (name.AsString().equals("trust_anchors_der") && !fits(item, state.getMtu())) {
        CBORObject anchors = config.get(name);
        for (int object = 0; object < anchors.size(); object++) {
          byte[] raw = anchors.get(object).GetByteString();
          int offset = 0;
          while (offset < raw.length) {
            CBORObject part = operation();
            part.Add("sequence", sequence);
            part.Add("name", name);
            part.Add("object_id", object);
            part.Add("offset", offset);
            part.Add("total", raw.length);
            int count = Math.min(raw.length - offset, state.getMtu());
            do {
              byte[] chunk = Arrays.copyOfRange(raw, offset, offset + count);
              part.set("data", CBORObject.FromObject(chunk));
              item = pair("blob-part", part);
              if (fits(item, state.getMtu())) {
                break;
              }
              count--;
            } while (count > 0);
            To2Crypto.require(count > 0 && sequence < 512);
            pending.add(item);
            sequence++;
            offset += count;
          }
        }
      } else {
        To2Crypto.require(fits(item, state.getMtu()) && sequence < 512);
        pending.add(item);
        sequence++;
      }
    }
    for (CBORObject name : plan.get("remove_fields").getValues()) {
      CBORObject remove = operation();
      remove.Add("sequence", sequence++);
      remove.Add("name", name);
      pending.add(pair("remove", remove));
    }
    CBORObject finish = operation();
    finish.Add("digest", digest);
    ServiceInfoKeyValuePair item = pair("finish", finish);
    To2Crypto.require(fits(item, state.getMtu()) && sequence <= 512);
    pending.add(item);
  }

  private CBORObject operation() {
    CBORObject value = CBORObject.NewMap();
    value.Add("transaction_id", transaction);
    return value;
  }

  static boolean fits(ServiceInfoKeyValuePair item, int limit) {
    CBORObject items = To2Crypto.array(To2Crypto.array(item.getKey(), item.getValue()));
    return To2Crypto.array(false, false, items).EncodeToBytes().length + 40 <= limit;
  }

  private static ServiceInfoKeyValuePair pair(String message, CBORObject value) {
    ServiceInfoKeyValuePair result = new ServiceInfoKeyValuePair();
    result.setKeyName(NAME + ":" + message);
    result.setValue(value.EncodeToBytes());
    return result;
  }

  @Override
  public void keepAlive() {
  }

  @Override
  public void send(ServiceInfoModuleState state, ServiceInfoSendFunction sender)
      throws IOException {
    while (!pending.isEmpty() && sender.apply(pending.peek())) {
      ServiceInfoKeyValuePair item = pending.remove();
      if (item.getKey().endsWith(":active")) {
        state.setActiveSent(true);
      } else if (item.getKey().endsWith(":finish")) {
        finishSent = true;
      }
      Arrays.fill(item.getValue(), (byte) 0);
    }
    state.setMore(!pending.isEmpty());
  }

  @Override
  public void close() {
    for (ServiceInfoKeyValuePair item : pending) {
      Arrays.fill(item.getValue(), (byte) 0);
    }
    pending.clear();
    digest = null;
  }
}