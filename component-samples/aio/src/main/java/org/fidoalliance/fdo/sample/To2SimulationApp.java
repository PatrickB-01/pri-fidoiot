package org.fidoalliance.fdo.sample;

import org.fidoalliance.fdo.protocol.Config;
import org.fidoalliance.fdo.protocol.HttpServer;

public class To2SimulationApp {

  public static void main(String[] args) {
    Config.getWorker(HttpServer.class).run();
  }
}