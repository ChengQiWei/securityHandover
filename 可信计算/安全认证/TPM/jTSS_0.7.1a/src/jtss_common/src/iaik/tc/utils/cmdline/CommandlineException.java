/*
 * Copyright (C) 2009 IAIK, Graz University of Technology
 */

package iaik.tc.utils.cmdline;

import java.io.PrintWriter;
import java.io.StringWriter;

public class CommandlineException extends Exception {

	private static final long serialVersionUID = 1L;

	private int return_ = -1;

	public CommandlineException() {
		super("unknown error");
	}

	public CommandlineException(String message, Throwable e) {
		super(message, e);
	}

	public CommandlineException(Throwable e) {
		super(e);
	}

	public CommandlineException(String message) {
		super(message);
	}

	public CommandlineException(String message, int desiredReturnValue) {
		super(message);

		return_ = desiredReturnValue;
	}

	public int getReturnValue() {
		return return_;
	}

	public String getStackTraceString() {
		StringWriter wrt = new StringWriter();
		PrintWriter out = new PrintWriter(wrt);
		this.printStackTrace(out);
		return wrt.toString();
	}
}
