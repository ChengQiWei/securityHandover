/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.impl.java.tcs.kcmgr;


import iaik.tc.tss.api.constants.tcs.TcTcsConstants;
import iaik.tc.tss.api.constants.tcs.TcTcsErrors;
import iaik.tc.tss.api.constants.tpm.TcTpmConstants;
import iaik.tc.tss.api.constants.tpm.TcTpmErrors;
import iaik.tc.tss.api.exceptions.tcs.TcTcsException;
import iaik.tc.tss.api.exceptions.tcs.TcTddlException;
import iaik.tc.tss.api.exceptions.tcs.TcTpmException;
import iaik.tc.tss.api.structs.common.TcBasicTypeDecoder;
import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.tss.api.structs.tpm.TcTpmContextBlob;
import iaik.tc.tss.impl.java.tcs.pbg.TcTpmCmdCapability;
import iaik.tc.tss.impl.java.tcs.pbg.TcTpmCmdEviction;
import iaik.tc.tss.impl.java.tcs.pbg.TcTpmCmdSessMgmt;
import iaik.tc.tss.impl.java.tddl.TcTddl;
import iaik.tc.utils.logging.Log;

public class TcTcsKeyCacheTpm12 extends TcTcsKeyCache {

	/**
	 * This method frees TPM space by swapping out the first key that does not match the provided
	 * parent key handle. This allows the caller to specify a key that has to remain inside the TPM.
	 * 
	 * @param khTpmParent The TPM key handle of the parent that should remain in the TPM.
	 * 
	 * @return Returns true if space could be freed (by swapping out keys), false otherwise.
	 * 
	 * @throws TcTpmException This exception is thrown if accessing the TPM fails.
	 */
	public boolean swapOutKeyNotParent(long khTpmParent) throws TcTddlException, TcTpmException, TcTcsException
	{
		boolean swapOutSuccessfull = false;
		TcTcsCachedKey cachedKey = null;

		// swap out key
		long khTpmToSave = TcTcsKeyHandleMgr.getInstance().getTpmKhLruNotParent(khTpmParent);
		if (khTpmToSave > -1) {
			// TPM 1.2 style
			Log.debug("swapping out key using 1.2 style");
			TcBlobData label = TcBlobData.newStringASCII("0000000000000000");
			TcTddl dest = TcTddl.getInstance();
			Object[] tpmOutData = TcTpmCmdSessMgmt.TpmSaveContext(dest, khTpmToSave, TcTpmConstants.TPM_RT_KEY,
					label);
			// Log.debug(TcTcsSessManager.getInstance().savedSessionsToString());
			cachedKey = new TcTcsCachedKey(TcTcsCachedKey.CT_SAVE_CONTEXT, tpmOutData[1]);
			// Note: Keys are left in place by TpmSaveContext. Therefore an explicit eviction (flush) is
			// required.
			TcTpmCmdEviction.TpmFlushSpecific(dest, khTpmToSave, TcTpmConstants.TPM_RT_KEY);
			swapOutSuccessfull = true;
		}

		// cache the key
		if (swapOutSuccessfull && cachedKey != null) {
			try {
				long khTcsToSave = TcTcsKeyHandleMgr.getInstance().getTcsKhForTpmKh(khTpmToSave);
				TcTcsKeyHandleMgr.getInstance().removeKeyHandleMappingByTcsKh(khTcsToSave);
				synchronized (cachedKeys_) {
					cachedKeys_.put(new Long(khTcsToSave), cachedKey);
					Log.debug("Number of elements in key cache: " + cachedKeys_.size());
				}
			} catch (TcTcsException e) {
				// There is no TCS key handle for the swapped out TPM key handle (i.e. this is
				// a key we have no knowledge about).
				// This can happen if other software loaded keys in to the TPM before the TCS was started.
				Log.debug("Non TCS-managed key removed key from TPM.");
			}
		}

		return swapOutSuccessfull;
	}


	/**
	 * This method swaps in (loads) the specified key from the cache into the TPM. If there is no
	 * space available in the TPM, the first key currently loaded in the TPM is swapped out using the
	 * corresponding swap out method.
	 * 
	 * @param khTcs The TCS key handle of the key to be swapped in.
	 * 
	 * @return The new TPM key handle assigned to the swapped-in key.
	 * 
	 * @throws TcTcsException This exception is throw if the TCS key handle could not be found in the
	 *           key cache or the key cache entry is invalid.
	 * @throws TcTpmException This exception is thrown if accessing the TPM fails.
	 */
	protected long swapInFromCache(long khTcs) throws TcTddlException, TcTpmException, TcTcsException
	{
		Long khTpm = new Long(TcTcsConstants.NULL_HOBJECT);

		TcTcsCachedKey cachedKey = null;
		synchronized (cachedKeys_) {
			cachedKey = (TcTcsCachedKey) cachedKeys_.remove(new Long(khTcs));
		}
		if (cachedKey == null) {
			throw new TcTcsException(TcTpmErrors.TPM_E_INVALID_KEYHANDLE,
					"TCS key handle not found in cache.");
		}

		TcTddl dest = TcTddl.getInstance();

		// make sure that there is a free key slot for the swapped-in key
		TcBlobData subCap = TcBlobData.newUINT32(TcTpmConstants.TPM_CAP_PROP_KEYS);
		Object[] tpmOutData = TcTpmCmdCapability.TpmGetCapability(dest,
				TcTpmConstants.TPM_CAP_PROPERTY, subCap);
		long numFreeKeySlots = (new TcBasicTypeDecoder((TcBlobData) tpmOutData[1])).decodeUINT32();
		if (numFreeKeySlots < 1) {
			swapOutKeyNotParent(-1); // we do not care about the parent key here
		}

		// TPM 1.2 style
		if (cachedKey.getKeyType() == TcTcsCachedKey.CT_SAVE_CONTEXT) {
			TcTpmContextBlob cBlob = (TcTpmContextBlob) cachedKey.getKeyBlob();
			tpmOutData = TcTpmCmdSessMgmt.TpmLoadContext(dest, 0L, false, cBlob.getEncoded()
					.getLengthAsLong(), cBlob);
			khTpm = (Long) tpmOutData[1];
			TcTcsKeyHandleMgr.getInstance().addKeyHandleMapping(khTpm.longValue(), khTcs);
		} else {
			// unable to load key into TPM - re-add the key to the cache
			synchronized (cachedKeys_) {
				cachedKeys_.put(new Long(khTcs), cachedKey);
			}
			throw new TcTcsException(TcTcsErrors.TCS_E_INTERNAL_ERROR,
					"Unable to load key from cache (key blob type mismatch).");
		}

		return khTpm.longValue();
	}

}
