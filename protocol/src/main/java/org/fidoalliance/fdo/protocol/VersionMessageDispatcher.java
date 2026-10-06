package org.fidoalliance.fdo.protocol;

import java.io.IOException;
import java.util.Optional;
import org.fidoalliance.fdo.protocol.dispatch.MessageDispatcher;
import org.fidoalliance.fdo.protocol.message.ProtocolVersion;

public class VersionMessageDispatcher implements MessageDispatcher {

  private final MessageDispatcher legacy;
  private final MessageDispatcher version200;

  public VersionMessageDispatcher() {
    this(null, null);
  }

  public VersionMessageDispatcher(MessageDispatcher legacy, MessageDispatcher version200) {
    this.legacy = legacy;
    this.version200 = version200;
  }

  /**
   * Routes a rejected v200 transport request to its session cleanup boundary.
   * @param request rejected request metadata
   * @param code sanitized error code
   * @return phase-correct response
   * @throws IOException unavailable handler
   */
  public Optional<DispatchMessage> failure(DispatchMessage request, int code) throws IOException {
    MessageDispatcher selected = version200 == null
        ? Config.getWorker(To2V2Dispatcher.class) : version200;
    if (!(selected instanceof To2V2Dispatcher)) {
      throw new IOException("v200 failure handler unavailable");
    }
    return ((To2V2Dispatcher) selected).failure(request, code);
  }

  @Override
  public Optional<DispatchMessage> dispatch(DispatchMessage request) throws IOException {
    int type = request.getMsgType().toInteger();
    if (request.getProtocolVersion() == ProtocolVersion.V200) {
      if (type != 255 && (type < 80 || type > 91)) {
        throw new IOException("legacy type in v200 envelope");
      }
      MessageDispatcher selected = version200 == null
          ? Config.getWorker(To2V2Dispatcher.class) : version200;
      return selected.dispatch(request);
    }
    if (request.getProtocolVersion() == ProtocolVersion.V100
        || request.getProtocolVersion() == ProtocolVersion.V101) {
      if (type >= 80 && type <= 91) {
        throw new IOException("v200 type in legacy envelope");
      }
      MessageDispatcher selected = legacy == null
          ? Config.getWorker(StandardMessageDispatcher.class) : legacy;
      return selected.dispatch(request);
    }
    throw new IOException("unsupported protocol version");
  }
}