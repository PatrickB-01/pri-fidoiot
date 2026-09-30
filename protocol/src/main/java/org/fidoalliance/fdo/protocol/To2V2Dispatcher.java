package org.fidoalliance.fdo.protocol;

import com.upokecenter.cbor.CBORObject;
import java.io.IOException;
import java.util.Optional;
import org.fidoalliance.fdo.protocol.dispatch.MessageDispatcher;
import org.fidoalliance.fdo.protocol.message.ErrorCode;
import org.fidoalliance.fdo.protocol.message.MsgType;
import org.fidoalliance.fdo.protocol.message.ProtocolVersion;
import org.fidoalliance.fdo.protocol.message.v200.To2Codec;
import org.fidoalliance.fdo.protocol.message.v200.To2Messages;

public class To2V2Dispatcher implements MessageDispatcher {

  public static final String CONTRACT_CAPABILITY = "org.example.thesis.to2-contract-v1";

  @Override
  public Optional<DispatchMessage> dispatch(DispatchMessage request) throws IOException {
    if (request.getMsgType() == MsgType.ERROR) {
      return Optional.empty();
    }
    To2Messages.Message parsed = To2Codec.decodeWire(request.getMsgType(), request.getMessage());
    if (request.getMsgType() != MsgType.TO2_HELLO_DEVICE_PROBE) {
      return reject(request, ErrorCode.INVALID_JWT_TOKEN);
    }
    if (request.getAuthToken().isPresent()) {
      return reject(request, ErrorCode.INVALID_JWT_TOKEN);
    }
    CBORObject probe = parsed.getValue();
    byte[] flags = probe.get(0).GetByteString();
    if (flags.length == 0 || (flags[0] & 4) == 0) {
      return reject(request, ErrorCode.SWITCH_VERSION);
    }
    if ((flags[0] & 0x80) != 0) {
      return reject(request, ErrorCode.CHANGE_CAP_ERROR);
    }
    boolean acceptedProfile = probe.get(1).getValues().stream()
        .anyMatch(value -> CONTRACT_CAPABILITY.equals(value.AsString()));
    if (!acceptedProfile) {
      return reject(request, ErrorCode.CHANGE_CAP_ERROR);
    }
    return reject(request, ErrorCode.INTERNAL_SERVER_ERROR);
  }

  private Optional<DispatchMessage> reject(DispatchMessage request, ErrorCode code)
      throws IOException {
    DispatchMessage response = new DispatchMessage();
    response.setProtocolVersion(ProtocolVersion.V200);
    response.setMsgType(MsgType.ERROR);
    response.setMessage(To2Codec.error(code.toInteger(), request.getMsgType().toInteger()));
    return Optional.of(response);
  }
}