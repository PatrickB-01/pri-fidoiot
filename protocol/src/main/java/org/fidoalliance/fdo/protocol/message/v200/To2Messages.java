package org.fidoalliance.fdo.protocol.message.v200;

import com.upokecenter.cbor.CBORObject;
import org.fidoalliance.fdo.protocol.message.MsgType;

public final class To2Messages {

  private To2Messages() {
  }

  public static class Message {
    private final MsgType type;
    private final byte[] raw;
    private final CBORObject value;

    Message(MsgType type, byte[] raw, CBORObject value) {
      this.type = type;
      this.raw = raw.clone();
      this.value = value;
    }

    public MsgType getType() {
      return type;
    }

    public byte[] getRaw() {
      return raw.clone();
    }

    public CBORObject getValue() {
      return CBORObject.DecodeFromBytes(value.EncodeToBytes());
    }
  }

  public static final class HelloDeviceProbe extends Message {
    HelloDeviceProbe(byte[] raw, CBORObject value) {
      super(MsgType.TO2_HELLO_DEVICE_PROBE, raw, value);
    }
  }

  public static final class HelloDeviceAck20 extends Message {
    HelloDeviceAck20(byte[] raw, CBORObject value) {
      super(MsgType.TO2_HELLO_DEVICE_ACK20, raw, value);
    }
  }

  public static class SignedMessage extends Message {
    SignedMessage(MsgType type, byte[] raw, CBORObject value) {
      super(type, raw, value);
    }

    public byte[] getProtectedBytes() {
      return getValue().get(0).GetByteString();
    }

    public byte[] getPayloadBytes() {
      return getValue().get(2).GetByteString();
    }
  }

  public static final class ProveDevice20 extends SignedMessage {
    ProveDevice20(byte[] raw, CBORObject value) {
      super(MsgType.TO2_PROVE_DEVICE20, raw, value);
    }
  }

  public static final class ProveOvHeader20 extends SignedMessage {
    ProveOvHeader20(byte[] raw, CBORObject value) {
      super(MsgType.TO2_PROVE_OV_HDR20, raw, value);
    }
  }

  public static final class SetupDevice20 extends SignedMessage {
    SetupDevice20(byte[] raw, CBORObject value) {
      super(MsgType.TO2_SETUP_DEVICE20, raw, value);
    }
  }

  public static final class GetOvNextEntry20 extends Message {
    GetOvNextEntry20(byte[] raw, CBORObject value) {
      super(MsgType.TO2_GET_OV_NEXT_ENTRY20, raw, value);
    }
  }

  public static final class OvNextEntry20 extends Message {
    OvNextEntry20(byte[] raw, CBORObject value) {
      super(MsgType.TO2_OV_NEXT_ENTRY20, raw, value);
    }
  }

  public static class ProvisioningBody extends Message {
    ProvisioningBody(MsgType type, byte[] raw, CBORObject value) {
      super(type, raw, value);
    }
  }

  public static final class DeviceServiceInfoReady20 extends ProvisioningBody {
    DeviceServiceInfoReady20(byte[] raw, CBORObject value) {
      super(MsgType.TO2_DEVICE_SERVICE_INFO_RDY20, raw, value);
    }
  }

  public static final class DeviceServiceInfo20 extends ProvisioningBody {
    DeviceServiceInfo20(byte[] raw, CBORObject value) {
      super(MsgType.TO2_DEVICE_SVC_INFO20, raw, value);
    }
  }

  public static final class OwnerServiceInfo20 extends ProvisioningBody {
    OwnerServiceInfo20(byte[] raw, CBORObject value) {
      super(MsgType.TO2_OWNER_SVC_INFO20, raw, value);
    }
  }

  public static final class Done20 extends ProvisioningBody {
    Done20(byte[] raw, CBORObject value) {
      super(MsgType.TO2_DONE20, raw, value);
    }
  }

  public static final class DoneAck20 extends ProvisioningBody {
    DoneAck20(byte[] raw, CBORObject value) {
      super(MsgType.TO2_DONE_ACK20, raw, value);
    }
  }

  public static final class EncryptedBody extends Message {
    EncryptedBody(MsgType type, byte[] raw, CBORObject value) {
      super(type, raw, value);
    }
  }

  public static final class Error20 extends Message {
    Error20(byte[] raw, CBORObject value) {
      super(MsgType.ERROR, raw, value);
    }
  }
}