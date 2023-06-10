/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 */

package iaik.tc.utils.logging;


import iaik.tc.utils.logging.java12.LogCallerInfoJava12;
import iaik.tc.utils.logging.java14.LogCallerInfoJava14;

import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.GregorianCalendar;
import java.util.HashMap;
import java.util.StringTokenizer;
import java.util.Vector;

/**
 * This class provides logging functionality for the whole project. By default, this class has one
 * console writer. New writers can be added and removed at runtime. It is also possible to read the
 * configuration for logging from a string-value (which can be defined in a configuration-file).
 */
public class Log {

	/**
	 * This field holds the current log level.
	 */
	protected static short commonThreshold_ = LogLevels.WARN;

	/**
	 * Flag which defines whether to print stack traces of exceptions or not.
	 */
	private static final boolean printExceptions_ = true;

	/**
	 * List of all registered output handlers.
	 */
	private static Vector outputHandlers_ = new Vector();

	/**
	 * Date format for logging output.
	 */
	protected static SimpleDateFormat dateFormat_ = new SimpleDateFormat("HH:mm:ss:SSS");

	
	/**
	 * This field determines if Java 1.4 features are used for logging.
	 */
	protected static boolean useJava14Logging_ = true;
	
	
	/**
	 * This field holds the names of classes with specific log levels. 
	 */
	protected static HashMap classNames_ = new HashMap();
	
	
	/**
	 * If this option is set to true, Java source file names and line numbers are 
	 * printed in a way that can be parsed by Eclipse. This allows to directly jump
	 * to the according parts in the source code.
	 */
	protected static boolean appendEclipseMarkers_ = false;
	
	/**
	 * Initialization. 
	 */
	static {
		// by default, log messages are written to the console
		outputHandlers_.add(new LogConsoleOutputHandler());
		
		// check if we can use Java 1.4 features for logging
		try {
			new LogCallerInfoJava14();
//			System.out.println("Can use Java 1.4 features for logging.");
		} catch (NoSuchMethodError e) {
			useJava14Logging_ = false;
			System.out.println("Note: Java 1.4 features not available. Falling back to legacy logging implementation.");
		}
	}


	/**
	 * Read the configuration of the Logging-class from the given string. The string contains a list
	 * of writers separated by semicolons. Possible writers are:
	 * 
	 * <pre>
	 *                  	stdout:
	 *                  		write logging-output to the console
	 *                  	file:
	 *                  		write logging-output to a file. The filename is given after a colon. 
	 *                  		Example:  file:/tmp/log.txt
	 *                  	none:
	 *                  		null-writer. does not printout logging output
	 * </pre>
	 * 
	 * The method not only reads the provided configuration but also sets up the output streams accordingly. 
	 *  
	 * @param config
	 */
	public synchronized static void readConfig(final String config)
	{
		outputHandlers_.clear();
		StringTokenizer st = new StringTokenizer(config, ";");
		while (st.hasMoreTokens()) {
			String nextWriter = st.nextToken();
			if (nextWriter.equals("stdout")) {
				addOutStream(new LogConsoleOutputHandler());
			} else if (nextWriter.startsWith("file:")) {
				addOutStream(new LogFileOutputHandler(nextWriter.substring(5)));
			} else if (nextWriter.equals("none")) {
				// add nothing
			} else {
				System.err.println("unknown writer: " + nextWriter);
			}
		}
	}


	/**
	 * This method allows users to modify the current log level.
	 */
	public synchronized static void setLogLevel(short level)
	{
		commonThreshold_ = level;
	}
  
  
	/**
	 * This method allows users to query the current log level.
	 * 
	 * @return current log level
	 */
	public synchronized static short getLogLevel() {
		return commonThreshold_;
	}

	
	/**
	 * This method allows users to modify the current log level for a specific class.
	 */
	public synchronized static void setLogLevel(Class classinfo, short level)
	{
		classNames_.put(classinfo.getName(), new Short(level));
	}


	/**
	 * This method allows users to specify if markers for Eclipse should be appended
	 * to log messages. These markers are parsed by Eclipse and allow users to simply
	 * jump to the line in the source where the log messages was generated.
	 */
	public synchronized static void appendEclipseMarkers(boolean append)
	{
		appendEclipseMarkers_ = append;
	}

	
	/**
	 * This method is used to reset all class-specific logging configurations.
	 */
	public synchronized static void flushLogLevelSpecific()
	{
		classNames_.clear();
	}


	/**
	 * This method is used to delete the logging setting for a specific class.
	 */
	public synchronized static void flushLogLevelSpecific(Class classinfo)
	{
		if (classNames_.containsKey(classinfo.getName())) {
			classNames_.remove(classinfo.getName());
		}
	}

	
	
	/**
	 * Add an output handler to the list of writers
	 * 
	 * @param handler new output handler for writing logging output
	 */
	public synchronized static void addOutStream(final LogGenericOutputHandler handler)
	{
		outputHandlers_.add(handler);
	}


	/**
	 * Strips off the package of a fully qualified class name
	 * 
	 * @param className fully qualified class name
	 * @return returns the class name without the package qualifier
	 */
	protected static String stripPackage(final String className)
	{
		if (className == null) System.out.println("className is NULL");
		return className.substring(className.lastIndexOf(".") + 1);
	}


	/**
	 * This method writes the log-message to all registered writers along with additional information 
	 * like the current system-time, the calling method, the name of the calling class and the line 
	 * number.
	 * 
	 * @param level the log level (as defined in the LogLevels class)
	 * @param msg the log-message itself
	 */
	public synchronized static void logMsg(final short level, final String msg)
	{
		// Note: The condition handled by this if clause is also covered by the if clause below.
		// The purpose of this if clause is to avoid the effrot involved in getting the caller
		// info if the logging threshold is higher than the level of the msg (which is very likely
		// during normal operation).
		if (level < commonThreshold_ && classNames_.isEmpty()) {
			return;
		}
		
		LogCallerInfo lci = null;
		if (useJava14Logging_) {
			lci = new LogCallerInfoJava14();
		} else {
			lci = new LogCallerInfoJava12();
		}

		if (classNames_.containsKey(lci.getClassName())) {
			// class has a specific log level
			if (level < ((Short)classNames_.get(lci.getClassName())).shortValue()) {
				return;
			}
		} else {
			// class does not have a specific log level
			if (level < commonThreshold_) {
				return;
			}
		}
		
		Calendar cal = new GregorianCalendar();

		StringBuffer logLine = new StringBuffer();
		logLine.append(dateFormat_.format(cal.getTime()));
		logLine.append(" [");
		logLine.append(LogLevels.levelToString(level));
		logLine.append("] ");
		logLine.append(stripPackage(lci.getClassName()));
		logLine.append("::");
		logLine.append(lci.getMethodName());
		logLine.append(" (");
		logLine.append(lci.getLineNumber());
		logLine.append("):\t");
		logLine.append(msg);;
		
		if (appendEclipseMarkers_) {
			logLine.append(System.getProperty("line.separator"));
			logLine.append("             ");
			logLine.append(new String("(" + lci.getClassName() + ".java:" + lci.getLineNumber()+")"));
		}
		
		for (int i = 0; i < outputHandlers_.size(); i++) {
			((LogGenericOutputHandler) outputHandlers_.elementAt(i)).printLine(logLine.toString());
		}
	}


	/**
	 * Log an error-message.
	 * 
	 * @param msg message to log
	 */
	public static void err(final String msg)
	{
		logMsg(LogLevels.ERR, msg);
	}


	/**
	 * Log an error-message. This usually happens when dealing with an unintended exception
	 * 
	 * @param e reference to the exception to log
	 */
	public synchronized static void err(final Exception e)
	{
		if (printExceptions_ && e != null) {
			e.printStackTrace();
		} else {
			logMsg(LogLevels.ERR, e.getMessage());
		}
	}


	/**
	 * Log an error-message. This usually happens when dealing with an unintended exception
	 * 
	 * @param e reference to the exception to log
	 * @param msg message to log
	 */
	public synchronized static void err(final String msg, final Exception e)
	{
		logMsg(LogLevels.ERR, msg);
		logMsg(LogLevels.ERR, e.getMessage());
		if (printExceptions_ && e != null) {
			e.printStackTrace();
		}
	}


	/**
	 * Log a warning message.
	 * 
	 * @param msg message to log
	 */
	public static void warn(final String msg)
	{
		logMsg(LogLevels.WARN, msg);
	}


	/**
	 * Log an informative message
	 * 
	 * @param msg message to log
	 */
	public static void info(final String msg)
	{
		logMsg(LogLevels.INFO, msg);
	}


	/**
	 * Log a debug message
	 * 
	 * @param msg message to log
	 */
	public static void debug(final String msg)
	{
		logMsg(LogLevels.DEBUG, msg);
	}
}
