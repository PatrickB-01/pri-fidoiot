package org.fidoalliance.fdo.sample;

import org.fidoalliance.fdo.protocol.Config;
import org.fidoalliance.fdo.protocol.HttpServer;
import org.fidoalliance.fdo.protocol.To2V2Dispatcher;

public class To2SimulationApp {

  public static void main(String[] args) {
    Config.getWorker(To2V2Dispatcher.class);
    Config.getWorker(HttpServer.class).run();
  }
}