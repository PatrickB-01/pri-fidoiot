package org.fidoalliance.fdo.protocol.message.v200;

import com.upokecenter.cbor.CBOREncodeOptions;
import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import org.fidoalliance.fdo.protocol.message.MsgType;

public final class To2Codec {

  public static final int MAX_MESSAGE_BYTES = 16384;
  private static final CBOREncodeOptions DECODE_OPTIONS =
      new CBOREncodeOptions("allowduplicatekeys=false");

  private To2Codec() {
  }

  /**
   * Decodes one bounded object without accepting duplicate keys or trailing objects.
   * @param raw received CBOR bytes
   * @return decoded object
   * @throws IOException malformed or oversized input
   */
  public static CBORObject decodeObject(byte[] raw) throws IOException {
    check(raw != null && raw.length > 0 && raw.length <= MAX_MESSAGE_BYTES);
    try {
      ByteArrayInputStream stream = new ByteArrayInputStream(raw);
      CBORObject value = CBORObject.Read(stream, DECODE_OPTIONS);
      check(stream.available() == 0 && value != null);
      checkDepth(value, 0);
      return value;
    } catch (RuntimeException exception) {
      throw new IOException("invalid v200 CBOR");
    }
  }

  /**
   * Validates an outer wire body, without authenticating signatures or ciphertext.
   * @param type v200 message type
   * @param raw exact received body
   * @return separate v200 model retaining the original bytes
   * @throws IOException invalid envelope or shape
   */
  public static To2Messages.Message decodeWire(MsgType type, byte[] raw) throws IOException {
    int number = type.toInteger();
    if (number >= 86 && number <= 91) {
      CBORObject value = decodeObject(raw);
      encrypted(value);
      return new To2Messages.EncryptedBody(type, raw, value);
    }
    return decodePlaintext(type, raw);
  }

  /**
   * Validates plaintext; encrypted bodies may use this only after authenticated decryption.
   * @param type v200 message type
   * @param raw plaintext body
   * @return validated structural model
   * @throws IOException invalid message shape
   */
  public static To2Messages.Message decodePlaintext(MsgType type, byte[] raw)
      throws IOException {
    CBORObject value = decodeObject(raw);
    switch (type) {
      case TO2_HELLO_DEVICE_PROBE:
        array(value, 6);
        capabilities(value.get(0));
        strings(value.get(1), false);
        bytes(value.get(2), 16);
        uint(value.get(3), 65535);
        arrayList(value.get(4), true);
        for (CBORObject item : value.get(4).getValues()) {
          check(integer(item) == -16 || integer(item) == -43);
        }
        bytes(value.get(5), 16);
        return new To2Messages.HelloDeviceProbe(raw, value);
      case TO2_HELLO_DEVICE_ACK20:
        array(value, 8);
        capabilities(value.get(0));
        strings(value.get(1), false);
        bytes(value.get(2), 16);
        uint(value.get(3), 65535);
        strings(value.get(4), true);
        arrayList(value.get(5), true);
        for (CBORObject item : value.get(5).getValues()) {
          uint(item, Integer.MAX_VALUE);
        }
        bytes(value.get(6), 16);
        hash(value.get(7), false);
        return new To2Messages.HelloDeviceAck20(raw, value);
      case TO2_PROVE_DEVICE20: {
        CBORObject payload = sign1(value);
        map(payload);
        check(payload.size() == 3 && payload.ContainsKey(10)
            && payload.ContainsKey(256) && payload.ContainsKey(-257));
        bytes(payload.get(CBORObject.FromObject(10)), 16);
        byte[] ueid = bytes(payload.get(CBORObject.FromObject(256)), 17);
        check(ueid[0] == 1);
        CBORObject proof = payload.get(CBORObject.FromObject(-257));
        array(proof, 5);
        text(proof.get(0));
        uint(proof.get(1), Integer.MAX_VALUE);
        bytes(proof.get(2), -1);
        bytes(proof.get(3), 16);
        hash(proof.get(4), false);
        return new To2Messages.ProveDevice20(raw, value);
      }
      case TO2_PROVE_OV_HDR20: {
        CBORObject payload = sign1(value);
        array(payload, 8);
        voucherHeader(decodeObject(bytes(payload.get(0), -1)));
        uint(payload.get(1), 255);
        hash(payload.get(2), true);
        bytes(payload.get(3), 16);
        bytes(payload.get(4), -1);
        uint(payload.get(5), 65535);
        publicKey(payload.get(6));
        check(isNull(payload.get(7)));
        return new To2Messages.ProveOvHeader20(raw, value);
      }
      case TO2_GET_OV_NEXT_ENTRY20:
        array(value, 1);
        uint(value.get(0), 255);
        return new To2Messages.GetOvNextEntry20(raw, value);
      case TO2_OV_NEXT_ENTRY20:
        array(value, 2);
        uint(value.get(0), 255);
        voucherEntry(value.get(1));
        return new To2Messages.OvNextEntry20(raw, value);
      case TO2_DEVICE_SERVICE_INFO_RDY20:
        array(value, 3);
        check(isNull(value.get(0)));
        optionalSize(value.get(1));
        bytes(value.get(2), 16);
        return new To2Messages.DeviceServiceInfoReady20(raw, value);
      case TO2_SETUP_DEVICE20: {
        CBORObject payload = sign1(value);
        array(payload, 3);
        check(integer(payload.get(0)) == 1);
        CBORObject replacement = payload.get(1);
        array(replacement, 4);
        rendezvous(replacement.get(0));
        bytes(replacement.get(1), 16);
        bytes(replacement.get(2), 16);
        publicKey(replacement.get(3));
        optionalSize(payload.get(2));
        return new To2Messages.SetupDevice20(raw, value);
      }
      case TO2_DEVICE_SVC_INFO20:
        array(value, 3);
        if (!isNull(value.get(0))) {
          hash(value.get(0), true);
        }
        bool(value.get(1));
        serviceInfo(value.get(2));
        return new To2Messages.DeviceServiceInfo20(raw, value);
      case TO2_OWNER_SVC_INFO20:
        array(value, 3);
        bool(value.get(0));
        bool(value.get(1));
        serviceInfo(value.get(2));
        return new To2Messages.OwnerServiceInfo20(raw, value);
      case TO2_DONE20:
        array(value, 1);
        bytes(value.get(0), 16);
        return new To2Messages.Done20(raw, value);
      case TO2_DONE_ACK20:
        array(value, 1);
        bytes(value.get(0), 16);
        return new To2Messages.DoneAck20(raw, value);
      case ERROR:
        array(value, 5);
        uint(value.get(0), 65535);
        uint(value.get(1), 255);
        text(value.get(2));
        check(isNull(value.get(3)));
        uint(value.get(4), Long.MAX_VALUE);
        return new To2Messages.Error20(raw, value);
      default:
        throw new IOException("not a v200 TO2 type");
    }
  }

  /**
   * Encodes an outbound body and checks its v200 structure.
   * @param type v200 message type
   * @param value body value
   * @return encoded body
   * @throws IOException invalid outbound shape
   */
  public static byte[] encodePlaintext(MsgType type, CBORObject value) throws IOException {
    byte[] raw = value.EncodeToBytes();
    decodePlaintext(type, raw);
    return raw;
  }

  public static byte[] error(int code, int previousType) throws IOException {
    return encodePlaintext(MsgType.ERROR, CBORObject.NewArray().Add(code).Add(previousType)
        .Add("v200 request rejected").Add(CBORObject.Null).Add(0));
  }

  /**
   * Checks the scoped voucher-header fields without asserting cryptographic trust.
   * @param value header array
   * @throws IOException invalid header shape
   */
  public static void voucherHeader(CBORObject value) throws IOException {
    array(value, 6);
    check(integer(value.get(0)) == 200);
    bytes(value.get(1), 16);
    rendezvous(value.get(2));
    text(value.get(3));
    publicKey(value.get(4));
    hash(value.get(5), false);
  }

  /**
   * Checks entry framing and payload fields without verifying its signature.
   * @param value tagged voucher entry
   * @throws IOException invalid entry shape
   */
  public static void voucherEntry(CBORObject value) throws IOException {
    CBORObject payload = sign1(value);
    array(payload, 4);
    hash(payload.get(0), false);
    hash(payload.get(1), false);
    check(isNull(payload.get(2)));
    publicKey(payload.get(3));
  }

  private static CBORObject sign1(CBORObject value) throws IOException {
    check(value.HasOneTag(18));
    CBORObject body = value.Untag();
    array(body, 4);
    CBORObject headers = decodeObject(bytes(body.get(0), -1));
    map(headers);
    check(headers.size() == 1 && headers.ContainsKey(1));
    long algorithm = integer(headers.get(CBORObject.FromObject(1)));
    check(algorithm == -7 || algorithm == -35);
    map(body.get(1));
    check(body.get(1).size() == 0);
    bytes(body.get(3), algorithm == -7 ? 64 : 96);
    return decodeObject(bytes(body.get(2), -1));
  }

  private static void encrypted(CBORObject value) throws IOException {
    check(value.HasOneTag(16));
    CBORObject body = value.Untag();
    array(body, 3);
    CBORObject headers = decodeObject(bytes(body.get(0), -1));
    map(headers);
    check(headers.size() == 1 && headers.ContainsKey(1));
    long algorithm = integer(headers.get(CBORObject.FromObject(1)));
    check(algorithm == 1 || algorithm == 3);
    map(body.get(1));
    check(body.get(1).size() == 1 && body.get(1).ContainsKey(5));
    bytes(body.get(1).get(CBORObject.FromObject(5)), 12);
    check(bytes(body.get(2), -1).length >= 16);
  }

  private static void capabilities(CBORObject value) throws IOException {
    byte[] flags = bytes(value, -1);
    check(flags.length <= 1 && (flags.length == 0 || (flags[0] & 0x78) == 0));
  }

  private static void publicKey(CBORObject value) throws IOException {
    array(value, 3);
    long kind = integer(value.get(0));
    check((kind == 10 || kind == 11) && integer(value.get(1)) == 1);
    check(bytes(value.get(2), -1).length > 0);
  }

  private static void hash(CBORObject value, boolean mac) throws IOException {
    array(value, 2);
    long algorithm = integer(value.get(0));
    check(mac ? algorithm == 5 || algorithm == 6 : algorithm == -16 || algorithm == -43);
    bytes(value.get(1), algorithm == 5 || algorithm == -16 ? 32 : 48);
  }

  private static void rendezvous(CBORObject value) throws IOException {
    arrayList(value, true);
    for (CBORObject directive : value.getValues()) {
      arrayList(directive, true);
      for (CBORObject instruction : directive.getValues()) {
        array(instruction, 2);
        uint(instruction.get(0), 255);
        decodeObject(bytes(instruction.get(1), -1));
      }
    }
  }

  private static void serviceInfo(CBORObject value) throws IOException {
    arrayList(value, false);
    for (CBORObject item : value.getValues()) {
      array(item, 2);
      text(item.get(0));
      check(item.get(0).AsString().contains(":"));
      decodeObject(bytes(item.get(1), -1));
    }
  }

  private static void optionalSize(CBORObject value) throws IOException {
    if (!isNull(value)) {
      uint(value, 65535);
    }
  }

  private static void strings(CBORObject value, boolean nonempty) throws IOException {
    arrayList(value, nonempty);
    for (CBORObject item : value.getValues()) {
      text(item);
    }
  }

  private static void array(CBORObject value, int length) throws IOException {
    arrayList(value, false);
    check(value.size() == length);
  }

  private static void arrayList(CBORObject value, boolean nonempty) throws IOException {
    check(value != null && !value.isTagged() && value.getType() == CBORType.Array
        && (!nonempty || value.size() > 0));
  }

  private static void map(CBORObject value) throws IOException {
    check(value != null && !value.isTagged() && value.getType() == CBORType.Map);
  }

  private static long integer(CBORObject value) throws IOException {
    check(value != null && !value.isTagged() && value.getType() == CBORType.Integer
        && value.CanFitInInt64());
    return value.AsInt64();
  }

  private static void uint(CBORObject value, long maximum) throws IOException {
    long number = integer(value);
    check(number >= 0 && number <= maximum);
  }

  private static byte[] bytes(CBORObject value, int length) throws IOException {
    check(value != null && !value.isTagged() && value.getType() == CBORType.ByteString);
    byte[] data = value.GetByteString();
    check(length < 0 || data.length == length);
    return data;
  }

  private static void text(CBORObject value) throws IOException {
    check(value != null && !value.isTagged() && value.getType() == CBORType.TextString);
  }

  private static void bool(CBORObject value) throws IOException {
    check(value != null && !value.isTagged() && value.getType() == CBORType.Boolean);
  }

  private static void check(boolean condition) throws IOException {
    if (!condition) {
      throw new IOException("invalid v200 message shape");
    }
  }

  private static boolean isNull(CBORObject value) {
    return value != null && !value.isTagged() && value.isNull();
  }

  private static void checkDepth(CBORObject value, int depth) throws IOException {
    check(depth <= 32 && value.getTagCount() <= 1);
    if (value.getType() == CBORType.Array || value.getType() == CBORType.Map) {
      for (CBORObject child : value.getValues()) {
        checkDepth(child, depth + 1);
      }
      if (value.getType() == CBORType.Map) {
        for (CBORObject key : value.getKeys()) {
          checkDepth(key, depth + 1);
        }
      }
    }
  }
}