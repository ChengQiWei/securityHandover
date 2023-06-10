/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 */


package iaik.tc.utils.logging;


/**
 * This class is used to obtain the name of the calling class, the name of the calling method
 * as well as the line number the call comes from. 
 */
public abstract class LogCallerInfo {

	/**
	 * Name of the calling method;
	 */
	protected String methodName_ = "UnknownMethod";
	
	
	/**
	 * Name of the class containing the calling method.
	 */
	protected String className_ = "UnkonwnClass";
	

	/**
	 * Line number the call originates from.
	 */
	protected int lineNumber_ = 0;
	
	
	/**
	 * This constant holds the index of the caller on the stack.
	 */
	protected final short CALLER_STACK_ELEMENT = 5;

	
	/************************************************************************************************
	 * Constructor
	 */
	public LogCallerInfo()
	{
		getCallerInfo();
	}

	protected abstract void getCallerInfo();
	
	
	/************************************************************************************************
	 * Returns contents of the className field.
	 */
	public String getClassName()
	{
		return className_;
	}
	/************************************************************************************************
	 * Sets the className field.
	 */
	public void setClassName(String className)
	{
		className_ = className;
	}
	/************************************************************************************************
	 * Returns contents of the lineNumber field.
	 */
	public int getLineNumber()
	{
		return lineNumber_;
	}
	/************************************************************************************************
	 * Sets the lineNumber field.
	 */
	public void setLineNumber(int lineNumber)
	{
		lineNumber_ = lineNumber;
	}
	/************************************************************************************************
	 * Returns contents of the methodName field.
	 */
	public String getMethodName()
	{
		return methodName_;
	}
	/************************************************************************************************
	 * Sets the methodName field.
	 */
	public void setMethodName(String methodName)
	{
		methodName_ = methodName;
	}
}
