/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.impl.java.tcs.kcmgr;

import iaik.tc.tss.api.constants.tcs.TcTcsErrors;
import iaik.tc.tss.api.exceptions.tcs.TcTcsException;
import iaik.tc.tss.api.exceptions.tcs.TcTddlException;
import iaik.tc.tss.api.exceptions.tcs.TcTpmException;
import iaik.tc.tss.impl.java.tcs.pbg.TcTpmCmdDeprKey;
import iaik.tc.tss.impl.java.tddl.TcTddl;
import iaik.tc.utils.logging.Log;

public class TcTcsKeyCacheTpm11NoSwap extends TcTcsKeyCache {

	/************************************************************************************************
	 * This method is queried by the key cache manager to determine if a key is cached or not.
	 * Since some 1.1b TPMs do not support key caching, keys are evicted (based on an LRU list).
	 * The key cache manager first checks if a key is already loaded in the TPM and then checks
	 * if it was swapped out. To allow to return a meaningful error message we tell the KCM that
	 * the key was swaped out. As a consequence the KCM tries to swap the key in (using
	 * swapInFromCache) where a meaningful exception is thrown.
	 */
	protected boolean tcsKeyIsCached(long khToCheck)
	{
		return true;
	}

	
	/*
	 * (non-Javadoc)
	 * @see iaik.tss.impl.java.tcs.kcmgr.TcTcsKeyCache#swapInFromCache(long)
	 */
	protected long swapInFromCache(long khTcs) throws TcTddlException,
			TcTpmException, TcTcsException {
		throw new TcTcsException(TcTcsErrors.TCS_E_KEY_CONTEXT_RELOAD,
				"Key could not be reloaded. The key was evicted because there were no " +
				"free key slots and this TPM does not support key swaping.");
	}

	
	/*
	 * (non-Javadoc)
	 * @see iaik.tss.impl.java.tcs.kcmgr.TcTcsKeyCache#swapOutFirstKeyNotParent(long)
	 */
	public boolean swapOutKeyNotParent(long khTpmParent)
			throws TcTddlException, TcTpmException, TcTcsException {

		long khTpmToEvict = -1;

		// get LRU TPM key handle
		khTpmToEvict = TcTcsKeyHandleMgr.getInstance().getTpmKhLruNotParent(khTpmParent);
		TcTddl dest = TcTddl.getInstance();
		TcTpmCmdDeprKey.TpmEvictKey(dest, khTpmToEvict);

		
		try {
			long khTcsToEvict = TcTcsKeyHandleMgr.getInstance().getTcsKhForTpmKh(khTpmToEvict);
			TcTcsKeyHandleMgr.getInstance().removeKeyHandleMappingByTcsKh(khTcsToEvict);
			Log.debug("evicted key witn TPM KH " + khTpmToEvict +  "/TCS KH " + khTcsToEvict + " (swaping not supported)");
		} catch (TcTcsException e) {
			// There is no TCS key handle for the swapped out TPM key handle (i.e. this is
			// a key we have no knowledge about).
			// This can happen if other software loaded keys in to the TPM before the TCS was started.
			Log.debug("Non TCS-managed key removed key from TPM.");
		}
		
		return true;
	}
}
