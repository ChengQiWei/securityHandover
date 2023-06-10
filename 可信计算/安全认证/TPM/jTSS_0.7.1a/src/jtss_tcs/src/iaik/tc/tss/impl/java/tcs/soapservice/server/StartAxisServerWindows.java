/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 */

package iaik.tc.tss.impl.java.tcs.soapservice.server;

import iaik.tc.tss.impl.java.tcs.TcTcsProperties;
import iaik.tc.utils.logging.Log;
import iaik.tc.utils.logging.LogLevels;

import java.io.IOException;
import java.net.ServerSocket;

import org.apache.axis.EngineConfiguration;
import org.apache.axis.EngineConfigurationFactory;
import org.apache.axis.transport.http.SimpleAxisServer;
import org.apache.axis.utils.cache.ClassCache;

public class StartAxisServerWindows implements Runnable {

  static protected SimpleAxisServer sas_;
  private int portNumber_;
  boolean debug_;
  private static boolean shutdown = false;

	public static void main(String[] args) {
		try {
				Thread startThread = new Thread(new StartAxisServerWindows());
				startThread.start();
				startThread.join();
		} catch ( Exception e ) {
			e.printStackTrace();
		}
	}

	public void run() {

		//If the jtss_tcs.ini file does not exist we use the default values for the startup
    try {
      processConfigFile();
    } catch (Exception e) {
      setDefaultValues();
    }
    if(debug_) {
      Log.setLogLevel(LogLevels.DEBUG);
    }

    try {      
      setupServer();

      //If we start this Class as service in Windows Vista, the Axis library is not able to load 
      //TSSCoreServiceBindingImpl from the thread's classloader. (see the method getServiceClass() in 
      //org.apache.axis.providers.java.JavaProvider.class). Therefore, we register the needed class in 
      //the class cache of the Axis server such that the the Axis library can find it.
      
      ClassCache cc = sas_.getAxisServer().getClassCache();
      Class cl = Class.forName("iaik.tc.tss.impl.java.tcs.soapservice.TSSCoreServiceBindingImpl");
      cc.registerClass("iaik.tc.tss.impl.java.tcs.soapservice.TSSCoreServiceBindingImpl", cl);
      
      startServer();
    } catch (Exception e) {
      System.exit(-1);
    }

		while (!shutdown) {
			try {
				Thread.sleep(10000);
			} catch (InterruptedException ignore) {}
		}
	}
	
	private static void signalShutdown() {
		shutdown = true;
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
}
