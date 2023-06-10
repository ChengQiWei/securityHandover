/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 */


package iaik.tc.utils.logging.java14;

import iaik.tc.utils.logging.LogCallerInfo;

/**
 * This class implements the CallerInfo for Java environments version 1.4 and above.
 * Via the getStackTrace method, the class name, method name and line number of the caller
 * can easily be obtained.
 */
public class LogCallerInfoJava14 extends LogCallerInfo {

	protected void getCallerInfo()
	{
		StackTraceElement[] stack = new Exception().getStackTrace();

		if (stack.length <= CALLER_STACK_ELEMENT) {
			return;
		}
		
		className_ = stack[CALLER_STACK_ELEMENT].getClassName();
		methodName_ = stack[CALLER_STACK_ELEMENT].getMethodName();
		lineNumber_ = stack[CALLER_STACK_ELEMENT].getLineNumber();
	}
}
