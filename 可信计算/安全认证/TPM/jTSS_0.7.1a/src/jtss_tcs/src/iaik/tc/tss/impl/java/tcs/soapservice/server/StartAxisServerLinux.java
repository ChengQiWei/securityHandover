/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 */


package iaik.tc.tss.impl.java.tcs.soapservice.server;

import iaik.tc.tss.impl.java.tcs.TcTcsProperties;
import iaik.tc.utils.logging.Log;
import iaik.tc.utils.logging.LogLevels;

import java.io.IOException;
import java.net.ServerSocket;

import org.apache.axis.transport.http.SimpleAxisServer;
import org.apache.commons.daemon.Daemon;
import org.apache.commons.daemon.DaemonContext;

/*
 * This is the main entry for the start of the TCS. In this class we have implemented 
 * two different ways for this start: We can either start it with the main() function 
 * or we start it as Apache daemon. 
 * If you start it with the main() function you have to add the server-config.wsdd file
 * to the class path.
 */
public class StartAxisServerLinux implements Daemon{

  static protected SimpleAxisServer sas_;
  private int portNumber_;
  boolean debug_;

  public static void main(String argv[]) {
    StartAxisServerLinux sas = new StartAxisServerLinux();
    Log.setLogLevel(LogLevels.DEBUG);
    sas.main0(argv);
  }

  public void main0(String argv[]) {
    try {
      processConfigFile();
    } catch (Exception e) {
      setDefaultValues();
    }
    try {      
      setupServer();
      startServer();
    } catch (Exception e) {
      e.printStackTrace();
      System.exit(-1);
    }
  }
  /*
   * init(.), start(), stop(), and destroy() is the implementation of the Apache daemon Interface. 
   */
  public void init(final DaemonContext args) {
    
    //If the jtss_tcs.ini file does not exist we use the default values for the startup
    try {
      Log.setLogLevel(LogLevels.DEBUG);
      processConfigFile();
    } catch (Exception e) {
      setDefaultValues();
    }
    if(debug_) {
      Log.setLogLevel(LogLevels.DEBUG);
    }
    
    try {
      setupServer();
    } catch (Exception e) {    
      e.printStackTrace();
      System.exit(-1);
    }
  }

  public void start() {
    try {
      startServer();
    } catch (Exception e) {    
      System.exit(-1);
    }
  }
  
  public void stop() {
    Log.info("Try to stop the running AXIS server");
    try {
      sas_.stop();
    } catch (Exception e) { 
      e.printStackTrace();
    }
  }

  public void destroy() {
    System.exit(0);
  }


  /*
   * Parse and process the arguments in the config file. The getProperty() method
   * returns a NullPointer if the entry does not exist. 
   */
  void processConfigFile() throws Exception{
    try{
      String portString = new String();
      portString = TcTcsProperties.getInstance().getProperty("SOAP", "portnumber");
      portNumber_ = Integer.parseInt(portString);
    } catch (NullPointerException e) {}
      
    try{
      String debugString = new String();
      debugString = TcTcsProperties.getInstance().getProperty("SOAP", "debug");
      debug_ = debugString.equals("true") ? true : false;
    } catch (NullPointerException e) {}
  }

  
  /*
   * This is setup sequence for an Axis server. Initialize the server and set
   * the socket.
   */
  public void setupServer() throws Exception{
    Log.info("Initializing the AXIS server");
    sas_ = new SimpleAxisServer();
    try {
      ServerSocket ss = new ServerSocket(portNumber_);
      sas_.setServerSocket(ss);
      Log.info("AXIS server successfully initialized");
    } catch (IOException e) {
      Log.err("Could not intialize the server socket. Maybe the TCS is already running.");
      throw e;
    }
  }

  /*
   * Start the server. 
   */
  public void startServer() throws Exception{
    Log.info("Try to start the AXIS server");
    try {
      sas_.start();
      Log.info("AXIS server successfully started");
    } catch (Exception e) {
      Log.err("Could not intialize the server socket.");
      throw e;
    }
  }
  
  public void setDefaultValues() {
    portNumber_ = 30004;
    debug_ = true;
  }
}
