/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 */



package iaik.tc.utils.logging.java12;

import java.io.OutputStream;
import java.io.PrintWriter;
import java.io.Writer;
import java.util.StringTokenizer;


/**
 * This class implements a custom PrintWriter that extracts the class name,
 * method name and line number of the caller from the stack trace.
 */
public class LogPrintWriter extends PrintWriter {

	/**
	 * Holds the number of lines already processed.
	 */
	protected short lineCnt_ = 0;
	
	/**
	 * Holds the caller's class name.
	 */
	protected String className_ = "UnknownClass";

	/**
	 * Holds the caller's method name.
	 */
	protected String methodName_ = "UnknownMethod";

	/**
	 * Holds the caller's line number.
	 */
	protected int lineNumber_ = -1;
	
	
	/**
	 * This field holds the index of the caller on the stack.
	 */
	protected short callerStackElement_;
	
	
	/**
	 * Constructor. 
	 */
	public LogPrintWriter(Writer out)
	{
		super(out);
	}


	/**
	 * Constructor. 
	 */
	public LogPrintWriter(OutputStream out)
	{
		super(out);
	}


	/**
	 * Constructor. 
	 */
	public LogPrintWriter(Writer out, boolean autoFlush)
	{
		super(out, autoFlush);
	}


	/**
	 * Constructor. 
	 */
	public LogPrintWriter(OutputStream out, boolean autoFlush)
	{
		super(out, autoFlush);
	}

	
	/**
	 * This method parses the input and decodes the class name, method name and
	 * the line number of the caller.
	 * If for some reason the String to decode does not match the expected format,
	 * the method is not going to try to decode the data. 
	 */
	protected void decodeString(String s)
	{
		if (lineCnt_ == callerStackElement_) { 
			StringTokenizer st = new StringTokenizer(s, "(:)");
			
			if (!st.hasMoreElements()) {
				return;
			}
			methodName_ = st.nextToken();
			methodName_ = methodName_.substring(methodName_.lastIndexOf(".") + 1);

			if (!st.hasMoreElements()) {
				return;
			}
			className_ = st.nextToken();
			className_ = className_.substring(0, className_.lastIndexOf("."));
			
			if (!st.hasMoreElements()) {
				return;
			}
			String line = st.nextToken();
			lineNumber_ = Integer.parseInt(line);
		}
		lineCnt_++;
	}
	
	
	// java 1.2
	/**
	 * Overwrites the default implementation and sends the data to the decode method.
	 */
	public void println(String s)
	{
		decodeString(s);
	}

	// java 1.3
	/**
	 * Overwrites the default implementation and sends the data to the decode method.
	 */
	public void println(char[] s)
	{
		decodeString(new String(s));
	}

	/**
	 * Overwrites the default implementation and sends the data to the decode method.
	 */
	public void print(String s)
	{
		decodeString(s);
	}


	/************************************************************************************************
	 * Returns contents of the className field.
	 */
	public String getClassName()
	{
		return className_;
	}


	/************************************************************************************************
	 * Returns contents of the lineNumber field.
	 */
	public int getLineNumber()
	{
		return lineNumber_;
	}


	/************************************************************************************************
	 * Returns contents of the methodName field.
	 */
	public String getMethodName()
	{
		return methodName_;
	}


	/************************************************************************************************
	 * Sets the index of the caller stack element. 
	 */
	public void setCallerStackElement(short callerStackElement)
	{
		callerStackElement_ = callerStackElement;
	}
	
}
