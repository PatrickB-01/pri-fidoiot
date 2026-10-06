package org.fidoalliance.fdo.protocol;

import com.upokecenter.cbor.CBORObject;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;

public class To2SimulationHealthServlet extends HttpServlet {

  @Override
  protected void doGet(HttpServletRequest request, HttpServletResponse response)
      throws IOException {
    response.setContentType("application/json");
    response.setCharacterEncoding("UTF-8");
    response.setHeader("Cache-Control", "no-store");
    boolean configured = Config.getWorker(To2V2Dispatcher.class).isConfigured();
    CBORObject health = CBORObject.NewMap();
    health.Add("status", "runtime-ready");
    health.Add("to2_implemented", configured);
    health.Add("est_implemented", false);
    response.getWriter().write(health.ToJSONString());
  }
}