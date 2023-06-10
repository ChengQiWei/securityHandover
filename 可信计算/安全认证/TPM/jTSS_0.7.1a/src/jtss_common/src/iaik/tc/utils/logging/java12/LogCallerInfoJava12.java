/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 */



package iaik.tc.utils.logging.java12;

import iaik.tc.utils.logging.LogCallerInfo;

/**
 * This class implements the CallerInfo for Java environments older than version 1.4.
 * The class library of those Java environments does not support the Exception.getStackTrace
 * method. Therefore, the call stack is obtained differently: The calltrace is written to a
 * custom PrintWriter implementation which parses the data and extracts the class name, the
 * method name and the line number of the call.
 */
public class LogCallerInfoJava12 extends LogCallerInfo {

	protected void getCallerInfo()
	{
		LogPrintWriter lpw = new LogPrintWriter(System.out);
		lpw.setCallerStackElement(CALLER_STACK_ELEMENT);
		new Exception().printStackTrace(lpw);
		
		className_ = lpw.getClassName();
		methodName_ = lpw.getMethodName();
		lineNumber_ = lpw.getLineNumber();
	}
}
