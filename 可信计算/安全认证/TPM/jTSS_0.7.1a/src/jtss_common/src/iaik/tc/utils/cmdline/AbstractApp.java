/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 */

package iaik.tc.utils.cmdline;


/**
 * This class represents the minimal functionality an application must implement if it wants to make
 * use of the command line library.
 */
public abstract class AbstractApp {

	/**
	 * This field holds the parameters provided by the user and accepted by the application.
	 */
	protected ParamParser params_ = null;


	/**
	 * This method returns a ParamParser instance of the application.
	 */
	public abstract ParamParser getParamParser();


	/**
	 * This is the main method of the application. It is called after all parameters have been parsed
	 * (and no errors have occurred).
	 */
	public abstract void execute() throws CommandlineException;

}
