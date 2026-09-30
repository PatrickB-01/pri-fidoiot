package org.fidoalliance.fdo.protocol;

import com.upokecenter.cbor.CBORObject;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Optional;
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