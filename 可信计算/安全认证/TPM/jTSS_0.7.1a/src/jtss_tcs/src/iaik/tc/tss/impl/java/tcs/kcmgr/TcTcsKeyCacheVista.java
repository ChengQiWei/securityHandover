/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.impl.java.tcs.kcmgr;


import iaik.tc.tss.api.exceptions.tcs.TcTcsException;
import iaik.tc.tss.api.exceptions.tcs.TcTddlException;
import iaik.tc.tss.api.exceptions.tcs.TcTpmException;
import iaik.tc.tss.api.structs.tpm.TcITpmKey;
import iaik.tc.tss.impl.java.tcs.authmgr.TcTcsAuthCacheVista;

/**
 * On Windows Vista, the TBS is designed to manage TPM resources.
 *
 * For more information refer to {@link TcTcsAuthCacheVista}. 
 */
public class TcTcsKeyCacheVista extends TcTcsKeyCache {

	/*
	 * (non-Javadoc)
	 * @see iaik.tss.impl.java.tcs.kcmgr.TcTcsKeyCache#ensureCanLoadKey(iaik.tss.api.structs.tpm.TcITpmKey, long)
	 */
	protected void ensureCanLoadKey(TcITpmKey wrappedKeyBlob, long parentHandle) throws TcTddlException, TcTpmException, TcTcsException
	{
	}
	
	protected boolean tcsKeyIsLoadedInTpm(long khTcs) throws TcTddlException, TcTpmException
	{
		return true;
	}
	
	/*
	 * (non-Javadoc)
	 * @see iaik.tss.impl.java.tcs.kcmgr.TcTcsKeyCache#swapOutFirstKeyNotParent(long)
	 */
	public boolean swapOutKeyNotParent(long khTpmParent) throws TcTddlException, TcTpmException
	{
		return true;
	}


	/*
	 * (non-Javadoc)
	 * @see iaik.tss.impl.java.tcs.kcmgr.TcTcsKeyCache#swapInFromCache(long)
	 */
	protected long swapInFromCache(long khTcs) throws TcTddlException, TcTpmException, TcTcsException
	{
		long tpmKeyHandle = TcTcsKeyHandleMgr.getInstance().getTpmKhForTcsKh(khTcs);
		return tpmKeyHandle;
	}

}
