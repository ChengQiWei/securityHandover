/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.api.exceptions.tcs;


import iaik.tc.tss.api.constants.tcs.TcTcsErrors;
import iaik.tc.tss.api.exceptions.common.TcTssException;

/**
 * This exception is thrown if an error at TCS level occurred.
 */
public class TcTcsException extends TcTssException {

	private static final long serialVersionUID = 1L;


	public TcTcsException(final long errCode)
	{
		super(errCode | TcTcsErrors.TSS_LAYER_TCS);
	}


	public TcTcsException(final long errCode, String message)
	{
		super(errCode | TcTcsErrors.TSS_LAYER_TCS, message);
	}


	protected String getErrMsg()
	{
		return TcTcsErrors.getErrMsg(errCode_);
	}
}
