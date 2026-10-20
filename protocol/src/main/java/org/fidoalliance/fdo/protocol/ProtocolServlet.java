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
    long started = System.nanoTime();
    int requestBytes = 0;
    int responseBytes = 0;
    int responseType = 0;
    Integer errorCode = null;
    String failureCategory = null;
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
      requestBytes = raw.length;
      if (raw.length == 0 || raw.length > To2Codec.MAX_MESSAGE_BYTES
          || (declaredLength >= 0 && raw.length != declaredLength)) {
        throw new IOException("invalid body length");
      }
      message.setMessage(raw);
      Optional<DispatchMessage> result = getDispatcher().dispatch(message);
      if (result.isPresent()) {
        DispatchMessage reply = result.get();
        responseType = reply.getMsgType().toInteger();
        errorCode = reply.getDiagnosticErrorCode();
        failureCategory = reply.getDiagnosticCategory();
        responseBytes = reply.getMessage().length;
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
      responseType = 255;
      errorCode = 100;
      response.setHeader(HttpUtils.HTTP_MESSAGE_TYPE, "255");
      try {
        if (failureReply.isPresent()) {
          DispatchMessage error = failureReply.get();
          errorCode = error.getDiagnosticErrorCode();
          failureCategory = error.getDiagnosticCategory();
          responseBytes = error.getMessage().length;
          if (error.getAuthToken().isPresent()) {
            response.setHeader(HttpUtils.HTTP_AUTHORIZATION, error.getAuthToken().get());
          }
          writeVersion200(response, error.getMessage());
        } else {
          byte[] error = To2Codec.error(100, previousType);
          responseBytes = error.length;
          writeVersion200(response, error);
        }
      } catch (IOException failure) {
        logger.error("v200 error response unavailable");
      }
    } finally {
      long ended = System.nanoTime();
      String trace = safeBenchmarkHeader(request, "X-Benchmark-Trace",
          "device-[0-9]{4}", "unattributed");
      String profile = safeBenchmarkHeader(request, "X-Benchmark-Profile",
          "p256|p384|hybrid", "unknown");
      String sequence = safeBenchmarkHeader(request, "X-Benchmark-Sequence",
          "[1-9][0-9]{0,5}", "0");
      logger.info("{\"schema\":\"thesis-to2-owner-event-v1\",\"role\":\"owner\","
          + "\"phase\":\"exchange\",\"protocol_version\":200,\"run_id\":\"" + trace
          + "\",\"profile\":\"" + profile + "\",\"sequence\":" + sequence
          + ",\"message_type\":" + previousType + ",\"response_type\":" + responseType
          + ",\"request_bytes\":" + requestBytes + ",\"response_bytes\":" + responseBytes
          + ",\"start_monotonic_ns\":" + started + ",\"end_monotonic_ns\":" + ended
          + ",\"duration_ns\":" + (ended - started) + ",\"status\":" + response.getStatus()
          + ",\"result\":\"" + (response.getStatus() == 200 ? "success" : "failure")
          + "\",\"error_code\":" + errorCode + ",\"failure_category\":"
          + (failureCategory == null ? "null" : "\"" + failureCategory + "\"") + "}");
    }
  }

  private String safeBenchmarkHeader(HttpServletRequest request, String name,
                                     String pattern, String fallback) {
    String value = request.getHeader(name);
    return value != null && value.length() <= 64 && value.matches(pattern) ? value : fallback;
  }

  private void writeVersion200(HttpServletResponse response, byte[] bytes) throws IOException {
    response.setContentType(HttpUtils.HTTP_APPLICATION_CBOR);
    response.setHeader("Cache-Control", "no-store");
    response.setContentLength(bytes.length);
    response.getOutputStream().write(bytes);
  }
}
