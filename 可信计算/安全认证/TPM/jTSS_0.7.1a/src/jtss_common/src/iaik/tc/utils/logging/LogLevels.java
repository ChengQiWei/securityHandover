/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 */


package iaik.tc.utils.logging;


/**
 * This class holds constants that represent the individual log levels. 
 */
public class LogLevels {

	private LogLevels()
	{
	}
	
  public static final short DEBUG = 50;
  public static final short INFO  = 60;
  public static final short WARN  = 70;
  public static final short ERR   = 80;
  public static final short OFF   = 1000;
  
  protected static final String STRING_DEBUG  = "DEBUG";
  protected static final String STRING_INFO   = "INFO";
  protected static final String STRING_WARN   = "WARN";
  protected static final String STRING_ERR    = "ERROR";
  protected static final String STRING_OFF    = "OFF";
  

  /**
   * This method returns a String representation of the given log level. 
   */
  public static String levelToString(short level) {
    switch (level) {
    case LogLevels.OFF:
      return STRING_OFF;
    case LogLevels.ERR:
      return STRING_ERR;
    case LogLevels.WARN:
      return STRING_WARN;
    case LogLevels.INFO:
      return STRING_INFO;
    case LogLevels.DEBUG:
      return STRING_DEBUG;
    default:
      throw new IllegalArgumentException("Unknown log level " + level);
    }
  }
}
