/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.impl.java.tcs.kcmgr;

import iaik.tc.tss.api.constants.tcs.TcTcsErrors;
import iaik.tc.tss.api.constants.tpm.TcTpmConstants;
import iaik.tc.tss.api.constants.tpm.TcTpmOrdinals;
import iaik.tc.tss.api.exceptions.tcs.TcTcsException;
import iaik.tc.tss.api.exceptions.tcs.TcTddlException;
import iaik.tc.tss.api.exceptions.tcs.TcTpmException;
import iaik.tc.tss.api.structs.common.TcBasicTypeDecoder;
import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.tss.api.structs.tpm.TcITpmKey;
import iaik.tc.tss.api.structs.tpm.TcTpmKeyHandleList;
import iaik.tc.tss.impl.java.tcs.TcTcsCommon;
import iaik.tc.tss.impl.java.tcs.pbg.TcTpmCmdCapability;
import iaik.tc.tss.impl.java.tddl.TcTddl;
import iaik.tc.tss.impl.java.tddl.TcTddlSocket;
import iaik.tc.utils.misc.OsDetection;

import java.util.HashMap;

public abstract class TcTcsKeyCache {

	/**
	 * This class is implemented as a singleton. This field holds then only
	 * instance of the class.
	 */
	protected static TcTcsKeyCache instance_ = null;

	/**
	 * mapping: TCS key handle -> cached key blob
	 */
	protected HashMap cachedKeys_ = new HashMap();

	/**
	 * Making constructor unavailable (Singleton).
	 */
	protected TcTcsKeyCache() {
	}

	/**
	 * This class can only be instantiated once (Singleton).
	 */
	public static synchronized TcTcsKeyCache getInstance()
			throws TcTddlException, TcTpmException, TcTcsException {
		
	
		
		if (instance_ == null) {
			if (    		   OsDetection
									.operatingSystemIs(OsDetection.OS_WINDOWS_VISTA)
							|| OsDetection
									.operatingSystemIs(OsDetection.OS_WINDOWS_SEVEN)
							|| OsDetection
									.operatingSystemIs(OsDetection.OS_WINDOWS_EIGHT)
							|| OsDetection
									.operatingSystemIs(OsDetection.OS_WINDOWS_EIGHT_ONE)
							|| OsDetection
									.operatingSystemIs(OsDetection.OS_WINDOWS_MMVIII)
							|| OsDetection
									.operatingSystemIs(OsDetection.OS_WINDOWS_MMVIIIR2)
							|| OsDetection
									.operatingSystemIs(OsDetection.OS_WINDOWS_UNKNOWN)
				) {
				instance_ = new TcTcsKeyCacheVista();

			} else {
				if (TcTcsCommon
						.isOrdinalSupported(TcTpmOrdinals.TPM_ORD_LoadContext)) {
					instance_ = new TcTcsKeyCacheTpm12();
				} else if (TcTcsCommon
						.isOrdinalSupported(TcTpmOrdinals.TPM_ORD_LoadKeyContext)) {
					instance_ = new TcTcsKeyCacheTpm11();
				} else {
					instance_ = new TcTcsKeyCacheTpm11NoSwap();
				}
			}
			
			//Workaround for IBM SW TPM
			TcTddl tddl = TcTddl.getInstance();
			if (tddl instanceof TcTddlSocket)
				instance_ = new TcTcsKeyCacheTpm12();
				
			
		}
		return instance_;
	}

	/**
	 * This method returns true if the key with the given handle is in the key
	 * cache.
	 */
	protected boolean tcsKeyIsCached(long khToCheck) {
		synchronized (cachedKeys_) {
			if (cachedKeys_.containsKey(new Long(khToCheck))) {
				return true;
			} else {
				return false;
			}
		}
	}

	/**
	 * This method removes the cached key blob corresponding to the given TCS
	 * key handle from the cache.
	 */
	protected void removeTcsKeyFromCache(long tcsKeyHandle)
			throws TcTcsException {
		synchronized (cachedKeys_) {
			if (!tcsKeyIsCached(tcsKeyHandle)) {
				throw new TcTcsException(TcTcsErrors.TCS_E_INVALID_KEYHANDLE,
						"The given TCS key handle was not found in the key cache.");
			}
			cachedKeys_.remove(new Long(tcsKeyHandle));
		}
	}

	/**
	 * This method frees TPM space by swapping out the first key that does not
	 * match the provided parent key handle. This allows the caller to specify a
	 * key that has to remain inside the TPM.
	 * 
	 * @param khTpmParent
	 *            The TPM key handle of the parent that should remain in the
	 *            TPM.
	 * 
	 * @return Returns true if space could be freed (by swapping out keys),
	 *         false otherwise.
	 * 
	 * @throws TcTpmException
	 *             This exception is thrown if accessing the TPM fails.
	 */
	public abstract boolean swapOutKeyNotParent(long khTpmParent)
			throws TcTddlException, TcTpmException, TcTcsException;

	/**
	 * This method swaps in (loads) the specified key from the cache into the
	 * TPM. If there is no space available in the TPM, the first key currently
	 * loaded in the TPM is swapped out using the corresponding swap out method.
	 * 
	 * @param khTcs
	 *            The TCS key handle of the key to be swapped in.
	 * 
	 * @return The new TPM key handle assigned to the swapped-in key.
	 * 
	 * @throws TcTcsException
	 *             This exception is throw if the TCS key handle could not be
	 *             found in the key cache or the key cache entry is invalid.
	 * @throws TcTpmException
	 *             This exception is thrown if accessing the TPM fails.
	 */
	protected abstract long swapInFromCache(long khTcs) throws TcTddlException,
			TcTpmException, TcTcsException;

	/**
	 * This method takes a TCS key handle and tries to ensure that the
	 * corresponding key is loaded in the TPM. On success, the TPM key handle is
	 * returned. The method performs the following steps:<br>
	 * <ul>
	 * <li>check if key is already loaded in TPM; if yes: return TPM key handle
	 * <li>check if key is in cache; if yes: load from cache into TPM
	 * <li>if key is not cached: throw a TcTcsException
	 * </ul>
	 * On success, the TPM key handle corresponding to the given TCS key handle
	 * is returned.
	 * 
	 * @param khTcs
	 *            The TCS key handle of the key that should be loaded in the
	 *            TPM.
	 * 
	 * @return The TPM key handle corresponding to the given TCS key handle.
	 * 
	 * @throws TcTcsException
	 *             This exception is thrown if the provided key handle is
	 *             unknown of the key is not loaded in the TPM, and also could
	 *             not be loaded from the key cache.
	 * @throws TcTpmException
	 */
	public long ensureKeyIsLoadedInTpm(long khTcs) throws TcTddlException,
			TcTpmException, TcTcsException {
		// certain key handles are not touched
		// TSS spec 1.2 A.23 says on page 527:
		// "For the entity type of SRK the associated application key handle
		// (TCS_KEY_HANDLE) MUST be 0x40000000."
		// The other KH special values are not mentioned there but it is assumed
		// that they should be treated in the same way.

		if (khTcs == TcTpmConstants.TPM_KH_SRK
				|| khTcs == TcTpmConstants.TPM_KH_OWNER
				|| khTcs == TcTpmConstants.TPM_KH_REVOKE
				|| khTcs == TcTpmConstants.TPM_KH_TRANSPORT
				|| khTcs == TcTpmConstants.TPM_KH_OPERATOR
				|| khTcs == TcTpmConstants.TPM_KH_ADMIN
				|| khTcs == TcTpmConstants.TPM_KH_EK) {
			return khTcs;
		}

		// step 1: check if key is loaded in TPM
		if (tcsKeyIsLoadedInTpm(khTcs)) {
			long tpmKeyHandle = TcTcsKeyHandleMgr.getInstance()
					.getTpmKhForTcsKh(khTcs);
			// update key usage timestamp (LRU list)
			TcTcsKeyHandleMgr.getInstance().updateTpmKhUsage(tpmKeyHandle);
			return tpmKeyHandle;
		}

		// key is not in TPM; maybe it is cached
		if (tcsKeyIsCached(khTcs)) {
			long tpmKeyHandle = swapInFromCache(khTcs);
			// update key usage timestamp (LRU list)
			TcTcsKeyHandleMgr.getInstance().updateTpmKhUsage(tpmKeyHandle);
			return tpmKeyHandle;
		}

		// key not loaded in TPM and not cached
		throw new TcTcsException(TcTcsErrors.TCS_E_INVALID_KEYHANDLE,
				"Key not loaded or cached. Unknown TCS key handle: " + khTcs);
	}

	/**
	 * This method tries to ensure that there is enough space available inside
	 * the TPM to load the given key. If there is not enough space, the method
	 * tries to free up space by swapping out keys from the TPM. When swapping,
	 * out keys, touching the parent key of the key is avoided because the
	 * parent is required for unwrapping the key.
	 * 
	 * @param wrappedKeyBlob
	 *            The key to be loaded.
	 * @param parentHandle
	 *            The TPM key handle of the key's parent.
	 * 
	 * @throws TcTpmException
	 *             If not enough space could be freed or accessing the TPM
	 *             failed, this exception is thrown.
	 */
	protected void ensureCanLoadKey(TcITpmKey wrappedKeyBlob, long parentHandle)
			throws TcTddlException, TcTpmException, TcTcsException {
		while (!canLoadKey(wrappedKeyBlob)) {
			boolean swapOutSuccessfull = swapOutKeyNotParent(parentHandle);
			if (!swapOutSuccessfull) {
				throw new TcTpmException(TcTcsErrors.TCS_E_FAIL,
						"Not enough space to load key (and unable to free space by swapping out keys).");
			}
		}
	}

	/**
	 * This method checks if the TPM has enough space left to load the given
	 * key.
	 * 
	 * @param key
	 *            The key to be checked.
	 * 
	 * @return Returns true if the TPM has enough free space to load the given
	 *         key, false otherwise.
	 * 
	 * @throws TcTpmException
	 *             This exception is thrown if accessing the TPM fails.
	 */
	protected boolean canLoadKey(TcITpmKey key) throws TcTddlException,
			TcTpmException {
		TcTddl dest = TcTddl.getInstance();
		TcBlobData subCap = (key.getAlgorithmParms()).getEncoded();
		Object[] tpmOutData = TcTpmCmdCapability.TpmGetCapability(dest,
				TcTpmConstants.TPM_CAP_CHECK_LOADED, subCap);

		// Note: CHECK_LOADED sounds a bit misleading. However the TPM spec
		// says:
		// A Boolean value. TRUE indicates that the TPM has enough memory
		// available
		// to load a key of the type specified by the TPM_KEY_PARMS structure.
		// FALSE
		// indicates that the TPM does not have enough memory.

		TcBlobData canLoadKey = (TcBlobData) tpmOutData[1];
		boolean retVal = new TcBasicTypeDecoder(canLoadKey).decodeBoolean();

		// Log.debug("Enough space to load key into TPM: " + retVal);

		return retVal;
	}

	/**
	 * This method checks if the key with the given TPM key handle is loaded in
	 * the TPM.
	 * 
	 * @param khTpm
	 *            The TPM key handle to be checked.
	 * 
	 * @return Returns true if the key is loaded, false otherwise.
	 * 
	 * @throws TcTpmException
	 *             This exception is thrown if accessing the TPM fails.
	 */
	protected boolean tpmKeyIsLoadedInTpm(long khTpm) throws TcTddlException,
			TcTpmException {
		TcTddl dest = TcTddl.getInstance();
		Object[] tpmOutData = TcTpmCmdCapability.TpmGetCapability(dest,
				TcTpmConstants.TPM_CAP_KEY_HANDLE, null);
		TcTpmKeyHandleList khList = new TcTpmKeyHandleList(
				(TcBlobData) tpmOutData[1]);

		boolean keyIsLoaded = false;

		for (int i = 0; i < khList.getHandle().length; i++) {
			if (khList.getHandle()[i] == khTpm) {
				keyIsLoaded = true;
				break;
			}
		}

		return keyIsLoaded;
	}

	/**
	 * This method checks if the key with the given TCS key handle is loaded in
	 * the TPM.
	 * 
	 * @param khTcs
	 *            The TCS key handle to be checked.
	 * 
	 * @return Returns true if the key is loaded, false otherwise.
	 * 
	 * @throws TcTpmException
	 *             This exception is thrown if accessing the TPM fails.
	 */
	protected boolean tcsKeyIsLoadedInTpm(long khTcs) throws TcTddlException,
			TcTpmException {
		try {
			long khTpm = TcTcsKeyHandleMgr.getInstance()
					.getTpmKhForTcsKh(khTcs);
			boolean keyIsLoaded = tpmKeyIsLoadedInTpm(khTpm);
			if (!keyIsLoaded) {
				// Log.debug("Found an invalid TCS to TPM key handle mapping (khTcs: "
				// + khTcs + ", khTpm: + "
				// + khTpm + ")");
				TcTcsKeyHandleMgr.getInstance().removeKeyHandleMappingByTcsKh(
						khTcs);
			}
			return keyIsLoaded;

		} catch (TcTcsException e) {
			// TCS key handle is not know
			return false;
		}
	}
}
