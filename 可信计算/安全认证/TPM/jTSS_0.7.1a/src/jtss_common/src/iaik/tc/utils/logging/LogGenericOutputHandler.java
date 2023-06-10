/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 */


package iaik.tc.utils.logging;


/**
 * This interface defines the required methods for an outputstream used for logging
 */
public interface LogGenericOutputHandler {

	/**
	 * print out the given line
	 * 
	 * @param line line to print
	 */
	public void printLine(final String line);
}
