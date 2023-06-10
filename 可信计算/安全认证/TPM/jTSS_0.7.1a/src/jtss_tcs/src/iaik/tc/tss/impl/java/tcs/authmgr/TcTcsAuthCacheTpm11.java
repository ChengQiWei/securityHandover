/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.impl.java.tcs.authmgr;


import iaik.tc.tss.api.constants.tcs.TcTcsErrors;
import iaik.tc.tss.api.constants.tpm.TcTpmErrors;
import iaik.tc.tss.api.exceptions.tcs.TcTcsException;
import iaik.tc.tss.api.exceptions.tcs.TcTddlException;
import iaik.tc.tss.api.exceptions.tcs.TcTpmException;
import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.tss.api.structs.tcs.TcTcsAuth;
import iaik.tc.tss.impl.java.tcs.pbg.TcTpmCmdDeprContext;
import iaik.tc.tss.impl.java.tddl.TcTddl;
import iaik.tc.utils.logging.Log;
import iaik.tc.utils.misc.CheckPrecondition;
import iaik.tc.utils.misc.Utils;

import java.util.HashMap;
import java.util.Iterator;
import java.util.Vector;

public class TcTcsAuthCacheTpm11 extends TcTcsAuthCache {

	protected HashMap savedAuthSessions_ = new HashMap();


	/*
	 * (non-Javadoc)
	 * 
	 * @see iaik.tss.impl.java.tcs.authmgr.TcTcsAuthCache#evictAllAuthSessions()
	 */
	public void evictAllAuthSessions() throws TcTddlException, TcTpmException
	{
	}


	/*
	 * (non-Javadoc)
	 * 
	 * @see iaik.tss.impl.java.tcs.authmgr.TcTcsAuthCache#swapOutAuth(long[])
	 */
	public void swapOutAuth(long[] keepHandles)
		throws TcTddlException, TcTpmException, TcTcsException
	{
		TcTddl dest = TcTddl.getInstance();

		synchronized (savedAuthSessions_) {
			Object[] session = removeFirstActiveAuthSession(keepHandles);
			if (session == null) {
				throw new TcTcsException(TcTcsErrors.TCS_E_INTERNAL_ERROR,
						"Unable to swap out auth session: No no suitable session found.");
			}
			TcBlobData authId = (TcBlobData) session[0];
			Long authHandle = (Long) session[1];
			Log.debug("going to remove auth session handle: " + authHandle);
			Object[] tpmOutData = TcTpmCmdDeprContext.TpmSaveAuthContext(dest, authHandle.longValue());
			TcBlobData sessionBlob = (TcBlobData) tpmOutData[1];
			savedAuthSessions_.put(authId, sessionBlob);
		}
	}


	/*************************************************************************************************
	 * This method returns true if the given auth session is cached, false otherwise.
	 */
	protected boolean isAuthInCache(TcTcsAuth auth)
	{
		synchronized (savedAuthSessions_) {
			return savedAuthSessions_.containsKey(deriveUniqueAuthId(auth));
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

		synchronized (savedAuthSessions_) {

			// step 1a: - find those auth sessions that are not currently loaded
			// step 1b: - check if those auth sessions are cached

			long[] keepHandles = new long[auths.length]; // the handles that must not be swapped out
			Vector authsNotLoaded = new Vector();
			for (int i = 0; i < auths.length; i++) {
				if (!isActiveAuthSession(auths[i])) {
					if (!isAuthInCache(auths[i])) {
						throw new TcTcsException(TcTcsErrors.TCS_E_INVALID_AUTHSESSION,
								"Unable to find auth session in cache.");
					} else {
						authsNotLoaded.add(new Integer(i));
					}
				}
				keepHandles[i] = auths[i].getAuthHandle();
			}

			// step 2: if all auth sessions are loaded there is nothing further to do

			if (authsNotLoaded.isEmpty()) {
				return;
			}

			// step 3a: remove saved auth sessions from the sessions cache
			// step 3b: load saved auth sessions into the TPM (and swap out loaded sessions if required)

			for (int i = 0; i < authsNotLoaded.size(); i++) {
				int authIdx = ((Integer) authsNotLoaded.elementAt(i)).intValue();
				TcTcsAuth auth = auths[authIdx];
				TcBlobData sessionBlob = (TcBlobData) savedAuthSessions_.remove(deriveUniqueAuthId(auth));

				boolean sessionLoaded = false;
				do {
					try {
						TcTddl dest = TcTddl.getInstance();
						Object[] tpmOutData = TcTpmCmdDeprContext.TpmLoadAuthContext(dest, sessionBlob
								.getLengthAsLong(), sessionBlob);
						long newAuthHandle = ((Long) tpmOutData[1]).longValue();
						auth.setAuthHandle(newAuthHandle);
						Log.debug("re-adding auth session");
						addActiveAuthSession(newAuthHandle, auth.getNonceEven());
						sessionLoaded = true;
					} catch (TcTpmException e) {
						if (e.getErrCode() == TcTpmErrors.TPM_E_SIZE
								|| e.getErrCode() == TcTpmErrors.TPM_E_NOSPACE) {
							swapOutAuth(keepHandles);
						} else {
							throw e;
						}
					}
				} while (!sessionLoaded);
			}

		}
	}


	/*
	 * (non-Javadoc)
	 * 
	 * @see iaik.tss.impl.java.tcs.authmgr.TcTcsAuthCache#loadedAuthSessionsToString()
	 */
	public String cachedAuthSessionsToString()
	{
		StringBuffer saved = new StringBuffer("saved auth session handles: ");
		synchronized (savedAuthSessions_) {
			Iterator it = savedAuthSessions_.keySet().iterator();
			while (it.hasNext()) {
				TcBlobData authId = (TcBlobData) it.next();
				saved.append(authId.toHexString() + " " + Utils.getNL());
			}
		}

		return saved.toString();
	}

}
