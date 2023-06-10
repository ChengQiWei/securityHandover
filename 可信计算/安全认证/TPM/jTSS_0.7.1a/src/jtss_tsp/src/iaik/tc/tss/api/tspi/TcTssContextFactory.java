/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 */

package iaik.tc.tss.api.tspi;

import java.lang.reflect.Constructor;

import iaik.tc.tss.api.exceptions.common.TcTssException;
import iaik.tc.tss.impl.java.tsp.internal.TcTspProperties;
import iaik.tc.utils.logging.Log;

/**
 * This factory provides the Context object. It automatically selects the correct binding, based on the 
 * configuration in the jtss_tsp.ini file.
 */
public class TcTssContextFactory extends TcTssAbstractFactory {

  static String TSP_INI_SEC_BINDING="BindingFactory";
  static String TSP_INI_KEY_BINDING_FACTORY_TYPE="type";

  /* (non-Javadoc)0
   * @see iaik.tc.tss.api.tspi.TcTssAbstractFactory#newContextObject()
   */
  @Override
  public TcIContext newContextObject() throws TcTssException, IllegalArgumentException {

    // instantiate the binding to the TCS

    String factClassName = new String();
    TcTssAbstractFactory factInstance=null;

    try {
      Class cls = null;
      try {
        factClassName = "iaik.tc.tss.impl.jni.tsp.TcTssJniFactory";
        cls = Class.forName(factClassName);
        Constructor constr = cls.getConstructor();
        factInstance = (TcTssAbstractFactory)constr.newInstance();
        TcIContext con = factInstance.newContextObject();
        con.connect();
        con.closeContext();
      //  Log.info("TrouSerS or IFX TSS found. Using JNI bindings...");

      } catch (Exception e1) {
   //     Log.info("TrouSerS or IFX Stack and/or jTSS Wrapper not found. Trying IAIK jTSS.");

        try {
          factClassName = TcTspProperties.getInstance().getProperty(TSP_INI_SEC_BINDING,
              TSP_INI_KEY_BINDING_FACTORY_TYPE);
          cls = Class.forName(factClassName);
        } catch (ClassNotFoundException e) {
          String err = "Neither TrouSerS nor IAIK jTSS are usable.";
          Log.err(err);
          throw new Exception(err);
        }
      }

      Constructor constr = cls.getConstructor();

      factInstance = (TcTssAbstractFactory) constr.newInstance(); 

    } catch (Exception e){
       Log.err("Error! No TSP-TCS binding could be initalized. Both jTSS Wrapper and jTSS were tried. Check the TSP configuration file.");
      throw new RuntimeException(e);
    }

    return factInstance.newContextObject();
  }
}
