/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.api.exceptions.tsp;


import iaik.tc.tss.api.constants.tsp.TcTssErrors;
import iaik.tc.tss.api.exceptions.common.TcTssException;

/**
 * This exception is thrown if an error at TSP level occurred.
 */
public class TcTspException extends TcTssException {

	private static final long serialVersionUID = 1L;


	public TcTspException(final long errCode)
	{
		super(errCode | TcTssErrors.TSS_LAYER_TSP);
	}


	public TcTspException(final long errCode, String message)
	{
		super(errCode | TcTssErrors.TSS_LAYER_TSP, message);
	}

	
	protected String getErrMsg()
	{
		return TcTssErrors.getErrMsg(errCode_);
	}

}
