/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.api.exceptions.tcs;


import iaik.tc.tss.api.constants.tcs.TcTcsErrors;
import iaik.tc.tss.api.constants.tpm.TcTpmErrors;
import iaik.tc.tss.api.exceptions.common.TcTssException;

/**
 * This exception is thrown if an error at TPM level occurred.
 */
public class TcTpmException extends TcTssException {

	private static final long serialVersionUID = 1L;


	public TcTpmException(final long errCode)
	{
		super(errCode | TcTcsErrors.TSS_LAYER_TPM);
	}


	public TcTpmException(final long errCode, String message)
	{
		super(errCode | TcTcsErrors.TSS_LAYER_TPM, message);
	}


	protected String getErrMsg()
	{
		return TcTpmErrors.getErrMsg(errCode_);
	}
}
