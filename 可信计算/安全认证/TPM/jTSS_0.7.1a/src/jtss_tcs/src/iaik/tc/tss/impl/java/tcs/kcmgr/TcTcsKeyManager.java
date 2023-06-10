/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.impl.java.tcs.kcmgr;


import iaik.tc.tss.api.constants.tcs.TcTcsConstants;
import iaik.tc.tss.api.constants.tcs.TcTcsErrors;
import iaik.tc.tss.api.constants.tpm.TcTpmConstants;
import iaik.tc.tss.api.constants.tpm.TcTpmErrors;
import iaik.tc.tss.api.constants.tpm.TcTpmOrdinals;
import iaik.tc.tss.api.exceptions.common.TcTssException;
import iaik.tc.tss.api.exceptions.tcs.TcTcsException;
import iaik.tc.tss.api.exceptions.tcs.TcTddlException;
import iaik.tc.tss.api.exceptions.tcs.TcTpmException;
import iaik.tc.tss.api.structs.tcs.TcTcsAuth;
import iaik.tc.tss.api.structs.tpm.TcITpmKey;
import iaik.tc.tss.api.structs.tpm.TcITpmKeyNew;
import iaik.tc.tss.api.structs.tpm.TcTpmEncauth;
import iaik.tc.tss.api.structs.tpm.TcTpmKey;
import iaik.tc.tss.api.structs.tpm.TcTpmKeyParms;
import iaik.tc.tss.api.structs.tpm.TcTpmNonce;
import iaik.tc.tss.impl.java.tcs.TcTcsCommon;
import iaik.tc.tss.impl.java.tcs.ctxmgr.TcTcsContext;
import iaik.tc.tss.impl.java.tcs.ctxmgr.TcTcsContextMgr;
import iaik.tc.tss.impl.java.tcs.pbg.TcTpmCmdDeprChangeAuth;
import iaik.tc.tss.impl.java.tcs.pbg.TcTpmCmdDeprKey;
import iaik.tc.tss.impl.java.tcs.pbg.TcTpmCmdDeprMisc;
import iaik.tc.tss.impl.java.tcs.pbg.TcTpmCmdEkHandling;
import iaik.tc.tss.impl.java.tcs.pbg.TcTpmCmdEviction;
import iaik.tc.tss.impl.java.tcs.pbg.TcTpmCmdStorage;
import iaik.tc.tss.impl.java.tddl.TcTddl;
import iaik.tc.utils.logging.Log;

public class TcTcsKeyManager {

	static {
		try {
			keyCache_ = TcTcsKeyCache.getInstance();
			khMgr_ = TcTcsKeyHandleMgr.getInstance();
		} catch (TcTssException e) {
			Log.err(e);
		}
	}
	
	
	/**
	 * Key cache manager.
	 */
	protected static TcTcsKeyCache keyCache_;

	/**
	 * Key handle manager.
	 */
	protected static TcTcsKeyHandleMgr khMgr_;
	

	/************************************************************************************************
	 * This method is used to load a TPM 1.1 key (TcTpmKey) into the TPM. As this method is passed on
	 * TPM_LoadKey, it is to be used on v1.1 TPMs.
	 */
	public static Object[] LoadKeyByBlob(long hContext, long tcsParentHandle,
			TcTpmKey wrappedKeyBlob, TcTcsAuth inAuth1) throws TcTddlException, TcTpmException, TcTcsException
	{
		long tpmParentHandle = keyCache_.ensureKeyIsLoadedInTpm(tcsParentHandle);

		keyCache_.ensureCanLoadKey(wrappedKeyBlob, tpmParentHandle);

		TcTddl dest = TcTddl.getInstance();
		Object[] tpmOutData = TcTpmCmdDeprMisc.TpmLoadKey(dest, tpmParentHandle, wrappedKeyBlob,
				inAuth1);

		Long resultCode = (Long) tpmOutData[0];
		TcTcsAuth outAuth1 = (TcTcsAuth) tpmOutData[1];
		Long tpmKH = (Long) tpmOutData[2];

		// create new TCS (application) key handle
		Long newTcsKH = new Long(khMgr_.getNextFreeTcsKeyHandle());
		khMgr_.addKeyHandleMapping(tpmKH.longValue(), newTcsKH.longValue());

		// associate the tcsKeyHandle with the context
		TcTcsContext context = TcTcsContextMgr.getContextForHandle(hContext);
		context.addTcsKeyHandle(newTcsKH);

		return new Object[] { resultCode, outAuth1, newTcsKH, tpmKH };
	}


	/************************************************************************************************
	 * This method is used to load a TPM 1.2 key (TcTpmKey12) or TPM 1.1 key into the TPM. As this
	 * method is passed on TPM_LoadKey2, it is to be used on v1.2 TPMs.
	 */
	public static Object[] LoadKey2ByBlob(long hContext, long tcsParentHandle,
			TcITpmKey wrappedKeyBlob, TcTcsAuth inAuth1) throws TcTddlException, TcTpmException, TcTcsException
	{
		long tpmParentHandle = keyCache_.ensureKeyIsLoadedInTpm(tcsParentHandle);
		
		keyCache_.ensureCanLoadKey(wrappedKeyBlob, tpmParentHandle);

		TcTddl dest = TcTddl.getInstance();
		Object[] tpmOutData = TcTpmCmdStorage.TpmLoadKey2(dest, tpmParentHandle, wrappedKeyBlob,
				inAuth1);

		Long resultCode = (Long) tpmOutData[0];
		TcTcsAuth outAuth1 = (TcTcsAuth) tpmOutData[1];
		Long tpmKH = (Long) tpmOutData[2];

		// create new TCS (application) key handle
		Long newTcsKH = new Long(khMgr_.getNextFreeTcsKeyHandle());
		khMgr_.addKeyHandleMapping(tpmKH.longValue(), newTcsKH.longValue());

		// associate the tcsKeyHandle with the context
		TcTcsContext context = TcTcsContextMgr.getContextForHandle(hContext);
		context.addTcsKeyHandle(newTcsKH);

		return new Object[] { resultCode, outAuth1, newTcsKH };
	}


	/************************************************************************************************
	 * 
	 */
	public static Object[] EvictKey(long hContext, long tcsKeyHandle)
		throws TcTddlException, TcTpmException, TcTcsException
	{
		Long resultCode = new Long(TcTcsErrors.TCS_SUCCESS);

		// check if key is loaded in TPM
		if (keyCache_.tcsKeyIsLoadedInTpm(tcsKeyHandle)) {
			// unload key from TPM

			// remove TCS -> TPM key handle mapping
			long tpmKeyHandle = keyCache_.ensureKeyIsLoadedInTpm(tcsKeyHandle);
			khMgr_.removeKeyHandleMappingByTcsKh(tcsKeyHandle);
			
			TcTddl dest = TcTddl.getInstance();
			if (TcTcsCommon.isOrdinalSupported(TcTpmOrdinals.TPM_ORD_FlushSpecific)) {
				// TPM 1.2 style
				TcTpmCmdEviction.TpmFlushSpecific(dest, tpmKeyHandle, TcTpmConstants.TPM_RT_KEY);
			} else if (TcTcsCommon.isOrdinalSupported(TcTpmOrdinals.TPM_ORD_EvictKey)) {
				// TPM 1.1 style
				TcTpmCmdDeprKey.TpmEvictKey(dest, tpmKeyHandle);
			} else {
				String msg = "Neither TPM_ORD_FlushSpecific nor TPM_ORD_EvictKey are supported by this TPM. Please report!";
				Log.warn(msg);
				throw new TcTcsException(TcTpmErrors.TPM_E_FAIL, msg);
			}
		}

		// invalidate key handle
		khMgr_.freeKeyHandle(tcsKeyHandle);
		
		// remove key from cache (if cached)
		if (keyCache_.tcsKeyIsCached(tcsKeyHandle)) {
			keyCache_.removeTcsKeyFromCache(tcsKeyHandle);
		}

		// remove association with context
		// Note: if hContext == NULL_OBJECT, that means that the context is currently closing down
		//       (and is therefore no longer found by the context manager)
		if (hContext != TcTcsConstants.NULL_HOBJECT) {
			TcTcsContext context = TcTcsContextMgr.getContextForHandle(hContext);
			context.removeTcsKeyHandle(new Long(tcsKeyHandle));
		}

		return new Object[] { resultCode };
	}


	/************************************************************************************************
	 * This method is part of the KeyManager for one reason: The outgoing TPM key handle (ephHandle)
	 * has to be translated into a TCS key handle.
	 */
	public static Object[] ChangeAuthAsymStart(long hContext, long tcsKeyHandle,
			TcTpmNonce antiReplay, TcTpmKeyParms tempKey, TcTcsAuth inAuth1)
		throws TcTddlException, TcTpmException, TcTcsException
	{
		long tpmKeyHandle = keyCache_.ensureKeyIsLoadedInTpm(tcsKeyHandle);

		TcTddl dest = TcTddl.getInstance();
		Object[] retVal = TcTpmCmdDeprChangeAuth.TpmChangeAuthAsymStart(dest, tpmKeyHandle, antiReplay,
				tempKey, inAuth1);

		// translate outgoing TPM key handle to TCS key handle
		Long ephTpmHandle = (Long) retVal[5];
		long ephTcsHandle = khMgr_.getNextFreeTcsKeyHandle();
		khMgr_.addKeyHandleMapping(ephTpmHandle.longValue(), ephTcsHandle);
		retVal[5] = new Long(ephTcsHandle);

		return retVal;
	}

	
	/************************************************************************************************
	 * Reading the public SRK or EK (TPM owner).  
	 */
	public static Object[] OwnerReadInternalPub(long hContext, long tcsKeyHandle,
			TcTcsAuth inAuth1) throws TcTddlException, TcTpmException, TcTcsException
	{
		long tpmKeyHandle = keyCache_.ensureKeyIsLoadedInTpm(tcsKeyHandle);

		TcTddl dest = TcTddl.getInstance();
		Object[] retVal = TcTpmCmdEkHandling.TpmOwnerReadInternalPub(dest, tpmKeyHandle, inAuth1);

		return retVal;
	}


	/************************************************************************************************
	 * Reading public portion of a key. 
	 */
	public static synchronized Object[] GetPubKey(long hContext, long tcsKeyHandle,
			TcTcsAuth inAuth1) throws TcTddlException, TcTpmException, TcTcsException
	{
		long tpmKeyHandle = keyCache_.ensureKeyIsLoadedInTpm(tcsKeyHandle);

		TcTddl dest = TcTddl.getInstance();
		Object[] retVal = TcTpmCmdStorage.TpmGetPubKey(dest, tpmKeyHandle, inAuth1);

		return retVal;
	}


	/************************************************************************************************
	 * This method allows creating a new key, which is wrapped by the already loaded wrapping key. 
	 */
	public static synchronized Object[] TcsipCreateWrapKey(long hContext, long tcsParentKeyHandle,
			TcTpmEncauth dataUsageAuth, TcTpmEncauth dataMigrationAuth, TcITpmKeyNew keyInfo,
			TcTcsAuth inAuth1) throws TcTddlException, TcTpmException, TcTcsException
	{
		long tpmParentKeyHandle = keyCache_.ensureKeyIsLoadedInTpm(tcsParentKeyHandle);

		TcTddl dest = TcTddl.getInstance();
		Object[] retVal = TcTpmCmdStorage.TpmCreateWrapKey(dest, tpmParentKeyHandle, dataUsageAuth,
				dataMigrationAuth, keyInfo, inAuth1);

		return retVal;
	}

}

