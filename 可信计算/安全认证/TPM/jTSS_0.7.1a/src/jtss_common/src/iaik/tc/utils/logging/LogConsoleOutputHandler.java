/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 */


package iaik.tc.utils.logging;


/**
 * This class implements a simple LogIOutputStream which prints all output to stderr
 */
public class LogConsoleOutputHandler implements LogGenericOutputHandler {

	/**
	 * Prints out the given line to stderr
	 * 
	 */
	public void printLine(final String line)
	{
		System.out.println(line);
	}

}
