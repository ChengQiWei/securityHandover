/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 */

package iaik.tc.utils.cmdline;


public class SubCommand {

	/**
	 * This field holds the key (i.e. the sub-command string)
	 */
	protected String key_ = null;

	/**
	 * This field holds the description of the sub-command.
	 */
	protected String description_ = null;

	/**
	 * This field holds the class of the application that is represented by the sub-command.
	 */
	protected Class appClass_ = null;

	/**
	 * This field holds an instance of the application that is represented by the sub-command.
	 */
	protected AbstractApp app_ = null;


	/*************************************************************************************************
	 * Constructor.
	 */
	public SubCommand(String key, String description, Class appClass)
	{
		key_ = key;
		description_ = description;
		appClass_ = appClass;
	}


	/*************************************************************************************************
	 * This method returns the description of the sub-command.
	 */
	public String getDescription()
	{
		return description_;
	}


	/*************************************************************************************************
	 * This method returns a parameter parser instance that is able to handle the parameters accepted
	 * by this sub-command.
	 */
	public ParamParser getParamParser()
	{
		createAppInstance();
		return app_.getParamParser();
	}


	/*************************************************************************************************
	 * This method is used to start the application represented by this sub-command.
	 */
	public void run(ParamParser paramParser) throws CommandlineException
	{
		createAppInstance();
		app_.params_ = paramParser;
		app_.execute();
	}


	/*************************************************************************************************
	 * This method returns the key of this sub-command.
	 */
	public String getKey()
	{
		return key_;
	}


	/*************************************************************************************************
	 * This method creates a new instance of the application represented by this sub-command. A new
	 * instance is only created if no instance exists yet.
	 */
	protected void createAppInstance()
	{
		if (app_ != null) {
			return;
		}

		try {
			Object appInstance = appClass_.newInstance();
			if (!(appInstance instanceof AbstractApp)) {
				throw new IllegalArgumentException("The application class " + appClass_.getName()
						+ " is not an instance of AbstractApp.");
			}
			app_ = (AbstractApp) (appInstance);
		} catch (InstantiationException e) {
			throw new RuntimeException(e.getMessage());
		} catch (IllegalAccessException e) {
			throw new RuntimeException(e.getMessage());
		}
	}
}
