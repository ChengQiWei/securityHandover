/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.api.exceptions.tcs;

import iaik.tc.tss.api.constants.tcs.TcTcsErrors;
import iaik.tc.tss.api.constants.tcs.TcTddlErrors;
import iaik.tc.tss.api.exceptions.common.TcTssException;


/**
 * This exception is thrown if an error at TDDL level occurred.
 */
public class TcTddlException extends TcTssException {

	private static final long serialVersionUID = 1L;


	public TcTddlException(final long errCode)
	{
		super(errCode | TcTcsErrors.TSS_LAYER_TDDL);
	}


	public TcTddlException(final long errCode, String message)
	{
		super(errCode | TcTcsErrors.TSS_LAYER_TDDL, message);
	}


	public TcTddlException(String message)
	{
		super(TcTcsErrors.TCS_E_FAIL | TcTcsErrors.TSS_LAYER_TDDL, message);
	}
	
	protected String getErrMsg()
	{
		return TcTddlErrors.getErrMsg(errCode_);
	}
}
