package org.fidoalliance.fdo.protocol;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.fidoalliance.fdo.protocol.message.AnyType;
import org.fidoalliance.fdo.protocol.message.ErrorCode;
import org.fidoalliance.fdo.protocol.message.Hash;
import org.fidoalliance.fdo.protocol.message.HashType;
import org.fidoalliance.fdo.protocol.message.OwnerPublicKey;
import org.fidoalliance.fdo.protocol.message.PublicKeyEncoding;
import org.fidoalliance.fdo.protocol.message.PublicKeyType;
import org.fidoalliance.fdo.protocol.message.ProtocolVersion;
import org.fidoalliance.fdo.protocol.message.MsgType;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class SerializationTest {

  @Test
  public void version200IdentifiersPreserveLegacyDefaults() throws Exception {
    Assertions.assertEquals(ProtocolVersion.V101, ProtocolVersion.current());
    Assertions.assertEquals(ProtocolVersion.V200, ProtocolVersion.fromString("200"));
    Assertions.assertEquals(ProtocolVersion.V200, ProtocolVersion.fromNumber(200));
    for (int type = 80; type <= 91; type++) {
      DispatchMessage message = HttpUtils.getMessageFromUri("/fdo/200/msg/" + type);
      Assertions.assertEquals(ProtocolVersion.V200, message.getProtocolVersion());
      Assertions.assertEquals(type, message.getMsgType().toInteger());
    }
    Assertions.assertEquals(MsgType.TO2_HELLO_DEVICE,
        HttpUtils.getMessageFromUri("/fdo/101/msg/60").getMsgType());
    Assertions.assertEquals(ErrorCode.SWITCH_VERSION, ErrorCode.fromNumber(7));
    Assertions.assertEquals(ErrorCode.CHANGE_CAP_ERROR, ErrorCode.fromNumber(103));
  }

  @Test
  public void cborAndCryptoBaseline() throws Exception {
    Hash original = new Hash();
    original.setHashType(HashType.SHA256);
    original.setHashValue(new byte[] {1, 2, 3});
    Hash decoded = Mapper.INSTANCE.readValue(Mapper.INSTANCE.writeValue(original), Hash.class);
    Assertions.assertEquals(original.getHashType(), decoded.getHashType());
    Assertions.assertArrayEquals(original.getHashValue(), decoded.getHashValue());

    MessageDigest digest = MessageDigest.getInstance("SHA-256", new BouncyCastleFipsProvider());
    Assertions.assertEquals(
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        Hex.encodeHexString(digest.digest("abc".getBytes(StandardCharsets.US_ASCII))));
  }

  @Test
  public void Test() throws DecoderException, IOException {

    Hash hash = new Hash();
    hash.setHashType(HashType.SHA256);
    hash.setHashValue(new byte[] {1,2,3,4});

    byte[] data = Mapper.INSTANCE.writeValue(hash);


    OwnerPublicKey ownerKey = new OwnerPublicKey();
    ownerKey.setType(PublicKeyType.SECP256R1);
    ownerKey.setEnc(PublicKeyEncoding.X509);
    ownerKey.setBody(AnyType.fromObject(new byte[]{1, 2, 3}));

    data = Mapper.INSTANCE.writeValue(ownerKey);
    OwnerPublicKey ownerKey2 = Mapper.INSTANCE.readValue(data, OwnerPublicKey.class);
    data = ownerKey2.getBody().covertValue(byte[].class);

    /*GenericMap map = new GenericMap();
    map.put(-1, -7);
    map.put(-2, new byte[]{1, 2, 3});
    map.put(-3, new byte[]{1, 2, 3});


    CoseKeyBody coseKeyBody = new CoseKeyBody();

    coseKeyBody.getMap().putAll(map);

    ownerKey.setEnc(PublicKeyEncoding.COSEKEY);
    ownerKey.setBody(coseKeyBody);
    data = Mapper.INSTANCE.toBytes(ownerKey);
    str = Hex.encodeHexString(data);
    ownerKey2 = Mapper.INSTANCE.readObject(data, OwnerPublicKey.class);*/
    byte[] expectedData = new byte[]{1,2,3};
    assert (Arrays.equals(expectedData, data));
  }
}
