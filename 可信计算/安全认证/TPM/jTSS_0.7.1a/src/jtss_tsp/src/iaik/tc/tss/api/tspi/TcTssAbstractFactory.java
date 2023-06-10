/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.api.tspi;

import iaik.tc.tss.api.exceptions.common.TcTssException;



/**
 * This class defines the minimal set of methods that has to be implemented by inheriting TSS
 * factory classes. This main factory is used to create a new context object of a specific backend
 * implementation. All further TSS objects are then created using the create methods of the context
 * object.
 */
public abstract class TcTssAbstractFactory {

	/**
	 * Hidden default constructor.
	 */
	protected TcTssAbstractFactory()
	{
	}


	/*************************************************************************************************
	 * This method returns a new instance of the context class of the specific implementation.
	 */
	public abstract TcIContext newContextObject() throws TcTssException;

}
