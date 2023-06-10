/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.impl.java.tcs.authmgr;


import iaik.tc.tss.api.constants.tcs.TcTcsErrors;
import iaik.tc.tss.api.constants.tpm.TcTpmConstants;
import iaik.tc.tss.api.constants.tpm.TcTpmErrors;
import iaik.tc.tss.api.exceptions.tcs.TcTcsException;
import iaik.tc.tss.api.exceptions.tcs.TcTddlException;
import iaik.tc.tss.api.exceptions.tcs.TcTpmException;
import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.tss.api.structs.tcs.TcTcsAuth;
import iaik.tc.tss.api.structs.tpm.TcTpmContextBlob;
import iaik.tc.tss.api.structs.tpm.TcTpmKeyHandleList;
import iaik.tc.tss.api.structs.tpm.TcTpmNonce;
import iaik.tc.tss.impl.java.tcs.pbg.TcTpmCmdCapability;
import iaik.tc.tss.impl.java.tcs.pbg.TcTpmCmdEviction;
import iaik.tc.tss.impl.java.tcs.pbg.TcTpmCmdSessMgmt;
import iaik.tc.tss.impl.java.tcs.sessmgr.TcTcsSessManager;
import iaik.tc.tss.impl.java.tddl.TcTddl;
import iaik.tc.utils.logging.Log;
import iaik.tc.utils.misc.CheckPrecondition;

import java.util.Vector;

public class TcTcsAuthCacheTpm12 extends TcTcsAuthCache {

	/*
	 * (non-Javadoc)
	 * 
	 * @see iaik.tss.impl.java.tcs.authmgr.TcTcsAuthCache#evictAllAuthSessions()
	 */
	public void evictAllAuthSessions() throws TcTddlException, TcTpmException
	{
		TcTddl dest = TcTddl.getInstance();
		TcBlobData subCap = TcBlobData.newUINT32(TcTpmConstants.TPM_RT_AUTH);
		Object[] tpmOutData = TcTpmCmdCapability.TpmGetCapability(dest, TcTpmConstants.TPM_CAP_HANDLE,
				subCap);

		TcTpmKeyHandleList savedSessions = new TcTpmKeyHandleList((TcBlobData) tpmOutData[1]);
		for (int i = 0; i < savedSessions.getHandle().length; i++) {
			TcTpmCmdEviction.TpmFlushSpecific(dest, savedSessions.getHandle()[i],
					TcTpmConstants.TPM_RT_AUTH);
		}
	}


	/*
	 * (non-Javadoc)
	 * 
	 * @see iaik.tss.impl.java.tcs.authmgr.TcTcsAuthCache#swapOutAuth(long[])
	 */
	public void swapOutAuth(long[] keepHandles) throws TcTddlException, TcTpmException, TcTcsException
	{
		TcTddl dest = TcTddl.getInstance();
		TcTcsSessManager sessMgr = TcTcsSessManager.getInstance();

		// step 1: There are is no free auth session slot. We have to swap out an auth session from the
		// TPM. To do so, we have to make sure that there is a saved context slot. In a first steps
		// we try to evict the oldest session of the same resource type. If that fails, we try to evict
		// the oldest overall session.

		if (sessMgr.getNumFreeSavedSessSlots() <= 0) {
			TcTcsSessManager.getInstance().evictOldestSavedSess(TcTpmConstants.TPM_RT_AUTH, keepHandles);
		}
		if (sessMgr.getNumFreeSavedSessSlots() <= 0) {
			TcTcsSessManager.getInstance().evictOldestSavedSess(keepHandles);
		}
		if (sessMgr.getNumFreeSavedSessSlots() <= 0) {
			throw new TcTcsException(TcTcsErrors.TCS_E_OUTOFMEMORY,
					"Unable to free space in the saved context list");
		}

		// step 2: Now there is a free "saved context" slot such that we can swap out a session.
		// Get the list of loaded auth sessions and swap one out.

		TcBlobData subCap = TcBlobData.newUINT32(TcTpmConstants.TPM_RT_AUTH);
		Object[] tpmOutData = TcTpmCmdCapability.TpmGetCapability(dest, TcTpmConstants.TPM_CAP_HANDLE,
				subCap);
		TcTpmKeyHandleList authHandles = new TcTpmKeyHandleList((TcBlobData) tpmOutData[1]);

		TcBlobData label = TcBlobData.newStringASCII("0000000000000000");

		for (int i = 0; i < authHandles.getLoaded(); i++) {
			long handleToSwapOut = authHandles.getHandle()[i];
			boolean swapOutOk = true;
			for (int j = 0; j < keepHandles.length; j++) {
				if (handleToSwapOut == keepHandles[j]) {
					swapOutOk = false;
					break; // j-loop
				}
			}
			if (swapOutOk) {
				tpmOutData = TcTpmCmdSessMgmt.TpmSaveContext(dest, handleToSwapOut,
						TcTpmConstants.TPM_RT_AUTH, label);
				TcTpmContextBlob blob = (TcTpmContextBlob) tpmOutData[1];
				sessMgr.addSavedSession(blob);
				break; // i-loop
			}
		}
	}


	/*
	 * (non-Javadoc)
	 * 
	 * @see iaik.tss.impl.java.tcs.authmgr.TcTcsAuthCache#ensureAuthsAreLoadedInTpm(iaik.tss.api.structs.tcs.TcTpmAuth[])
	 */
	public void ensureAuthsAreLoadedInTpm(TcTcsAuth[] auths)
		throws TcTddlException, TcTpmException, TcTcsException
	{
		CheckPrecondition.notNull(auths, "auths");

		TcTcsSessManager sessMgr = TcTcsSessManager.getInstance();

		// step 1: check if auth is already loaded in TPM

		TcTddl dest = TcTddl.getInstance();
		TcBlobData subCap = TcBlobData.newUINT32(TcTpmConstants.TPM_RT_AUTH);
		Object[] tpmOutData = TcTpmCmdCapability.TpmGetCapability(dest, TcTpmConstants.TPM_CAP_HANDLE,
				subCap);
		TcTpmKeyHandleList authHandles = new TcTpmKeyHandleList((TcBlobData) tpmOutData[1]);
		
		Vector authsNotLoaded = new Vector();
		long[] allHandles = new long[auths.length];
		for (int i = 0; i < auths.length; i++) {
			boolean authLoaded = false;
			for (int j = 0; j < authHandles.getLoaded(); j++) {
				if (auths[i].getAuthHandle() == authHandles.getHandle()[j]) {
					authLoaded = true;
					break;
				}
			}
			if (!authLoaded) {
				authsNotLoaded.add(new Integer(i));
			}
		}
		if (authsNotLoaded.isEmpty()) {
			return;
		}

		// step 2: not all auth sessions are loaded: check if they are cached

		for (int i = 0; i < authsNotLoaded.size(); i++) {
			int authIdx = ((Integer) authsNotLoaded.elementAt(i)).intValue();
			if (!sessMgr.handleIsInCache(TcTpmConstants.TPM_RT_AUTH, auths[authIdx].getAuthHandle())) {
				throw new TcTcsException(TcTcsErrors.TCS_E_INVALID_AUTHSESSION,
						"The provided auth session is not loaded in the TPM and is not cached. "
								+ "It might have been evicted (from TPM and/or cache) due to space limitations.");
			}
		}

		// step 3: all missing auth sessions are cached - load the session (free up space if there is no space
		// in the TPM to load the session)
		for (int i = 0; i < authsNotLoaded.size(); i++) {
			int authIdx = ((Integer) authsNotLoaded.elementAt(i)).intValue();
			boolean sessionLoaded = false;
			do {
				try {
					long newAuthHandle = sessMgr.loadSession(TcTpmConstants.TPM_RT_AUTH, auths[authIdx]
							.getAuthHandle());
					auths[authIdx].setAuthHandle(newAuthHandle);
					sessionLoaded = true;
				} catch (TcTpmException e) {
					if (e.getErrCode() == TcTpmErrors.TPM_E_RESOURCES) {
						swapOutAuth(allHandles);
					} else {
						throw e;
					}
				}
			} while (!sessionLoaded);
		}

		Log.debug(sessMgr.savedSessionsToString());
		Log.debug(cachedAuthSessionsToString());
	}

	
	// TODO: implementation of the following three methods might be required on STM TPMs

	/*
	 * (non-Javadoc)
	 * 
	 * @see iaik.tss.impl.java.tcs.authmgr.TcTcsAuthCache#addActiveAuthSession(iaik.tss.api.structs.tcs.TcTpmAuth)
	 */
	public void addActiveAuthSession(long authHandle, TcTpmNonce nonceEven)
	{
		// Note: 1.2 TPMs have a capability that allows us to retrieve the list of currently active
		// sessions directly from the TPM. Therefore, this method is not used on 1.2 TPMs.
	}


	/*
	 * (non-Javadoc)
	 * 
	 * @see iaik.tss.impl.java.tcs.authmgr.TcTcsAuthCache#removeActiveAuthSession(iaik.tss.api.structs.tcs.TcTpmAuth)
	 */
	public void removeActiveAuthSession(TcTcsAuth auth)
	{
		// Note: 1.2 TPMs have a capability that allows us to retrieve the list of currently active
		// sessions directly from the TPM. Therefore, this method is not used on 1.2 TPMs.
	}


	/*
	 * (non-Javadoc)
	 * @see iaik.tss.impl.java.tcs.authmgr.TcTcsAuthCache#trackAuthSession(iaik.tss.api.structs.tcs.TcTpmAuth, iaik.tss.api.structs.tcs.TcTpmAuth)
	 */
	public void trackActiveAuthSession(TcTcsAuth inAuth, TcTcsAuth outAuth)
	{
		// Note: 1.2 TPMs have a capability that allows us to retrieve the list of currently active
		// sessions directly from the TPM. Therefore, this method is not used on 1.2 TPMs.
	}

	

	/*
	 * (non-Javadoc)
	 * 
	 * @see iaik.tss.impl.java.tcs.authmgr.TcTcsAuthCache#loadedAuthSessionsToString()
	 */
	public String cachedAuthSessionsToString() throws TcTddlException, TcTpmException
	{
		TcTddl dest = TcTddl.getInstance();
		TcBlobData subCap = TcBlobData.newUINT32(TcTpmConstants.TPM_RT_AUTH);
		Object[] tpmOutData = TcTpmCmdCapability.TpmGetCapability(dest, TcTpmConstants.TPM_CAP_HANDLE,
				subCap);
		TcTpmKeyHandleList savedSessions = new TcTpmKeyHandleList((TcBlobData) tpmOutData[1]);

		String retVal = "loaded auth sessions: ";
		for (int i = 0; i < savedSessions.getLoaded(); i++) {
			retVal += savedSessions.getHandle()[i] + " ";
		}
		
		return retVal;
	}

}
