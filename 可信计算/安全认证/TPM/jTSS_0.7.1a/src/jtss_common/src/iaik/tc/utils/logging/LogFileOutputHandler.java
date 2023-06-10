/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 */


package iaik.tc.utils.logging;


import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;

/**
 * This class implements an IOutputStream which writes to a file.
 */
public class LogFileOutputHandler implements LogGenericOutputHandler {

	/**
	 * FileOutputStream for writing the output
	 */
	java.io.FileOutputStream ostream_ = null;


	/**
	 * Default constructor
	 * 
	 * @param fileName name of the file used for logging
	 */
	public LogFileOutputHandler(final String fileName)
	{
		try {
			ostream_ = new FileOutputStream(new File(fileName));
		} catch (IOException e) {
			System.err.println("error opening logfile");
		}
	}


	/**
	 * writes the content to the file. if the file could not be created or opened for writing, this
	 * method does nothing
	 */
	public void printLine(final String line)
	{
		if (ostream_ != null) {
			StringBuffer output = new StringBuffer(line);
			output.append(System.getProperty("line.separator"));
			try {
				ostream_.write(output.toString().getBytes());
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
	}
}
