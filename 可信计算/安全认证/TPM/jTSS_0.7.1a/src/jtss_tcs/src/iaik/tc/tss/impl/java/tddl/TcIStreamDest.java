/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.impl.java.tddl;

import iaik.tc.tss.api.exceptions.tcs.TcTddlException;
import iaik.tc.tss.api.structs.common.TcBlobData;


/**
 * Stream Destination class. Used for TDDL and transport sessions. 
 *
 */
public interface TcIStreamDest {

	public abstract TcBlobData transmitData(TcBlobData command) throws TcTddlException;
	
}
