// Copyright 2022 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package org.fidoalliance.fdo.protocol;

import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.Optional;
import org.fidoalliance.fdo.protocol.dispatch.ExceptionConsumer;
import org.fidoalliance.fdo.protocol.dispatch.MessageDispatcher;
import org.fidoalliance.fdo.protocol.message.AnyType;
import org.fidoalliance.fdo.protocol.message.MsgType;
import org.fidoalliance.fdo.protocol.message.ProtocolVersion;
import org.fidoalliance.fdo.protocol.message.v200.To2Codec;

public class ProtocolServlet extends HttpServlet {


  private static final LoggerService logger = new LoggerService(ProtocolServlet.class);

  protected MessageDispatcher getDispatcher() {
    return new VersionMessageDispatcher();
  }

  protected void logMessage(DispatchMessage msg) {
    StringBuilder builder = new StringBuilder();
    builder.append("Type ");
    builder.append(msg.getMsgType().toInteger());
    builder.append(" ");
    try {
      Mapper.INSTANCE.writeDiagnostic(builder,
          Mapper.INSTANCE.readValue(msg.getMessage(), AnyType.class));
    } catch (Exception e) {
      builder.append("failed to covert to diagnostic form.");
    }

    logger.info(builder.toString());
  }

  @Override
  protected void doPost(HttpServletRequest req, HttpServletResponse resp) {

    String path = req.getRequestURI().substring(req.getContextPath().length());
    if (path.startsWith("/fdo/200/")) {
      doVersion200(req, resp, path);
      return;
    }

    DispatchMessage reqMsg = null;
    try {
      reqMsg = HttpUtils.getMessageFromUri(req.getRequestURI());

      Enumeration<String> values = req.getHeaders(HttpUtils.HTTP_AUTHORIZATION);
      while (values.hasMoreElements()) {
        reqMsg.setAuthToken(values.nextElement());
      }

      if (req.getContentLength() > BufferUtils.getMaxBufferSize()) {
        throw new MessageBodyException("message too large.");
      }

      reqMsg.setMessage(req.getInputStream().readNBytes(req.getContentLength()));

      if (reqMsg.getMessage() != null) {
        logMessage(reqMsg);
      } else {
        throw new NullPointerException("Received empty request message");
      }

      MessageDispatcher dispatcher = getDispatcher();
      Optional<DispatchMessage> result = dispatcher.dispatch(reqMsg);

      if (result.isPresent()) {
        DispatchMessage respMsg = result.get();
        if (respMsg.getMsgType() == MsgType.ERROR) {
          resp.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        }

        resp.setHeader(HttpUtils.HTTP_AUTHORIZATION, respMsg.getAuthToken().get());
        resp.setContentType(HttpUtils.HTTP_APPLICATION_CBOR);
        resp.setHeader(HttpUtils.HTTP_MESSAGE_TYPE,
            Integer.toString(respMsg.getMsgType().toInteger()));
        resp.setContentLength(respMsg.getMessage().length);
        resp.getOutputStream().write(respMsg.getMessage());

        logMessage(respMsg);
      }

    } catch (Throwable throwable) {

      try {
        Config.getWorker(ExceptionConsumer.class).accept(throwable);
      } catch (IOException e) {
        logger.error("failed log exception");
        // already in exception handler
      }

      resp.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
      resp.setHeader(HttpUtils.HTTP_MESSAGE_TYPE,
          Integer.toString(MsgType.ERROR.toInteger()));
      if (reqMsg != null) {

        try {
          DispatchMessage errorMsg = DispatchMessage.fromThrowable(throwable, reqMsg);

          resp.setContentLength(errorMsg.getMessage().length);
          resp.getOutputStream().write(errorMsg.getMessage());
          logMessage(errorMsg);



        } catch (Throwable throwable1) {
          logger.error("failed to write error response");
          // already in exception handler
        }


      }

    }
  }

  private void doVersion200(HttpServletRequest request, HttpServletResponse response,
                            String path) {
    int previousType = 0;
    boolean incomingError = path.equals("/fdo/200/msg/255");
    DispatchMessage message = null;
    try {
      if (path.matches("/fdo/200/msg/(0|[1-9][0-9]{0,2})")) {
        int routeType = Integer.parseInt(path.substring(path.lastIndexOf('/') + 1));
        if (routeType <= 255) {
          previousType = routeType;
        }
      }
      message = HttpUtils.getMessageFromUri(path);
      previousType = message.getMsgType().toInteger();
      List<String> tokens = Collections.list(request.getHeaders(HttpUtils.HTTP_AUTHORIZATION));
      if (tokens.size() > 1) {
        throw new IOException("duplicate authorization header");
      }
      if (!tokens.isEmpty()) {
        String token = tokens.get(0);
        if (token.isEmpty() || token.length() > 1024 || !token.chars()
            .allMatch(character -> character >= 33 && character <= 126)) {
          throw new IOException("invalid authorization header");
        }
        message.setAuthToken(token);
      }
      if (!path.matches("/fdo/200/msg/(80|82|84|86|88|90|255)")) {
        throw new IOException("invalid request route");
      }
      if (!HttpUtils.HTTP_APPLICATION_CBOR.equalsIgnoreCase(request.getContentType())) {
        throw new IOException("invalid content type");
      }
      List<String> types = Collections.list(request.getHeaders(HttpUtils.HTTP_MESSAGE_TYPE));
      if (types.size() > 1 || (!types.isEmpty()
          && !Integer.toString(previousType).equals(types.get(0)))) {
        throw new IOException("invalid message type header");
      }
      long declaredLength = request.getContentLengthLong();
      if (declaredLength > To2Codec.MAX_MESSAGE_BYTES) {
        throw new IOException("oversized body");
      }
      byte[] raw = request.getInputStream().readNBytes(To2Codec.MAX_MESSAGE_BYTES + 1);
      if (raw.length == 0 || raw.length > To2Codec.MAX_MESSAGE_BYTES
          || (declaredLength >= 0 && raw.length != declaredLength)) {
        throw new IOException("invalid body length");
      }
      message.setMessage(raw);
      Optional<DispatchMessage> result = getDispatcher().dispatch(message);
      if (result.isPresent()) {
        DispatchMessage reply = result.get();
        if (reply.getProtocolVersion() != ProtocolVersion.V200) {
          throw new IOException("wrong response version");
        }
        response.setStatus(reply.getMsgType() == MsgType.ERROR ? 500 : 200);
        response.setHeader(HttpUtils.HTTP_MESSAGE_TYPE,
            Integer.toString(reply.getMsgType().toInteger()));
        if (reply.getAuthToken().isPresent()) {
          response.setHeader(HttpUtils.HTTP_AUTHORIZATION, reply.getAuthToken().get());
        }
        writeVersion200(response, reply.getMessage());
      } else {
        response.setStatus(200);
        response.setContentLength(0);
      }
      logger.info("v200 type " + previousType + " bytes " + raw.length
          + " status " + response.getStatus());
    } catch (Exception exception) {
      Optional<DispatchMessage> failureReply = Optional.empty();
      try {
        MessageDispatcher dispatcher = getDispatcher();
        if (message != null && dispatcher instanceof VersionMessageDispatcher) {
          failureReply = ((VersionMessageDispatcher) dispatcher).failure(message, 100);
        }
      } catch (Exception unavailable) {
        logger.info("v200 session failure handler unavailable");
      }
      if (incomingError) {
        response.setStatus(200);
        response.setContentLength(0);
        return;
      }
      response.setStatus(500);
      response.setHeader(HttpUtils.HTTP_MESSAGE_TYPE, "255");
      try {
        if (failureReply.isPresent()) {
          DispatchMessage error = failureReply.get();
          if (error.getAuthToken().isPresent()) {
            response.setHeader(HttpUtils.HTTP_AUTHORIZATION, error.getAuthToken().get());
          }
          writeVersion200(response, error.getMessage());
        } else {
          writeVersion200(response, To2Codec.error(100, previousType));
        }
      } catch (IOException failure) {
        logger.error("v200 error response unavailable");
      }
      logger.info("v200 request rejected status 500");
    }
  }

  private void writeVersion200(HttpServletResponse response, byte[] bytes) throws IOException {
    response.setContentType(HttpUtils.HTTP_APPLICATION_CBOR);
    response.setHeader("Cache-Control", "no-store");
    response.setContentLength(bytes.length);
    response.getOutputStream().write(bytes);
  }
}
