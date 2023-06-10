/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.api.exceptions.tcs;


import iaik.tc.tss.api.exceptions.common.TcTssException;
import iaik.tc.tss.api.structs.tsp.TcTssKmKeyinfo;

/**
 * This exception is thrown by the persistent storage if a key could not be loaded (by UUID) because
 * a required parent key is currently not loaded. Information about the parent key in question can be
 * obtained via the {@link TcTssKmLoadFailed#getKmKeyInfo()} method.
 */
public class TcTssKmLoadFailed extends TcTssException {


	private static final long serialVersionUID = 1L;
	TcTssKmKeyinfo kmKeyinfo_ = null;


	public TcTssKmLoadFailed(long errCode, TcTssKmKeyinfo kmKeyInfo)
	{
		super(errCode);
		kmKeyinfo_ = kmKeyInfo;
	}


	public TcTssKmKeyinfo getKmKeyInfo()
	{
		return kmKeyinfo_;
	}
	
	
	@Override
	protected String getErrMsg()
	{
		return "Loading of key failed because a parent key requires authorization.";
	}
}
