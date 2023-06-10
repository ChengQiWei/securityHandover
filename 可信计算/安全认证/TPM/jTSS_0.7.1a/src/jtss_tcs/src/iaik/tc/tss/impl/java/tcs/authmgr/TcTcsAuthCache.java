/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.impl.java.tcs.authmgr;


import iaik.tc.tss.api.constants.tpm.TcTpmOrdinals;
import iaik.tc.tss.api.exceptions.tcs.TcTcsException;
import iaik.tc.tss.api.exceptions.tcs.TcTddlException;
import iaik.tc.tss.api.exceptions.tcs.TcTpmException;
import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.tss.api.structs.tcs.TcTcsAuth;
import iaik.tc.tss.api.structs.tpm.TcTpmNonce;
import iaik.tc.tss.impl.java.tcs.TcTcsCommon;
import iaik.tc.tss.impl.java.tddl.TcTddl;
import iaik.tc.tss.impl.java.tddl.TcTddlSocket;
import iaik.tc.utils.logging.Log;
import iaik.tc.utils.misc.OsDetection;
import iaik.tc.utils.misc.Utils;

import java.util.LinkedList;


public abstract class TcTcsAuthCache {

	private LinkedList authSessionHandles_ = new LinkedList();

	private LinkedList authSessionIds_ = new LinkedList();

	/**
	 * This class is implemented as a singleton. This field holds the only instance of the class.
	 */
	protected static TcTcsAuthCache instance_ = null;


	/*************************************************************************************************
	 * Making constructor unavailable (Singleton).
	 */
	protected TcTcsAuthCache()
	{
	}


	/*************************************************************************************************
	 * This class can only be instantiated once (Singleton).
	 */
	public static synchronized TcTcsAuthCache getInstance()
		throws TcTddlException, TcTpmException, TcTcsException
	{
		boolean onSWTPM= TcTddl.getInstance() instanceof TcTddlSocket; 
		
		if (instance_ == null) {
			if (!onSWTPM && 
					(		   OsDetection
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
					)
			) {
				instance_ = new TcTcsAuthCacheVista();
			} else {
				if (TcTcsCommon.isOrdinalSupported(TcTpmOrdinals.TPM_ORD_LoadContext)) {
					instance_ = new TcTcsAuthCacheTpm12();
				} else if (TcTcsCommon.isOrdinalSupported(TcTpmOrdinals.TPM_ORD_LoadAuthContext)) {
					instance_ = new TcTcsAuthCacheTpm11();
				} else {
					instance_ = new TcTcsAuthCacheTpm11NoSwap();
				}
			}
		}

					
		return instance_;
	}


	/*************************************************************************************************
	 * This method evicts all auth sessions from the TPM. The TSS is supposed to have full control of
	 * the TPM. No other entity than the TSS is responsible for managing sessions. Consequently, the
	 * TSS flushes all existing auth sessions before taking control of the saved context slots.
	 * 
	 * Note: This method is specific to 1.2 TPMs.
	 * 
	 * <p> Note: This functionality is also implemented in {@link TcTddl}. Changes
	 * here should be applied in TcTddl too.
	 * 
	 * @throws TcTddlException
	 * @throws TcTpmException
	 */
	public abstract void evictAllAuthSessions() throws TcTddlException, TcTpmException;


	/*************************************************************************************************
	 * This method swaps out an auth sessions from the TPM.
	 * 
	 * @param keepHandles When swapping out an auth session, this method avoids to swap out the
	 *          sessions with the handles specified by notHandles. If it does not matter which session
	 *          to swap out, simply pass an empty array.
	 * 
	 * @throws TcTddlException
	 * @throws TcTpmException
	 * @throws TcTcsException
	 */
	public abstract void swapOutAuth(long[] keepHandles)
		throws TcTddlException, TcTpmException, TcTcsException;


	/*************************************************************************************************
	 * This method is called by TCSI methods that use auth sessions. By calling this method, it is
	 * ensured that the required auth sessions are loaded in the TPM. In cases the auth sessions were
	 * swapped out, they are re-loaded into the TPM. Should re-loading be required, the TPM might
	 * assign a new auth handles to the sessions. In such a case, the authHandles of the auth
	 * parameter are modified accordingly.
	 * 
	 * @param auths The auth sessions that have to be present in the TPM.
	 * 
	 * @throws TcTddlException
	 * @throws TcTpmException
	 * @throws TcTcsException
	 */
	public abstract void ensureAuthsAreLoadedInTpm(TcTcsAuth[] auths)
		throws TcTddlException, TcTpmException, TcTcsException;


	/*************************************************************************************************
	 * This method is intended for debugging. It returns a string of auth handles currently loaded in
	 * the TPM.
	 */
	public abstract String cachedAuthSessionsToString() throws TcTddlException, TcTpmException;


	/*************************************************************************************************
	 * This method is used internally to derive unique ID for the given auth session. This unique ID
	 * is used to identify the auth session when swapped out and subsequently reloaded into the TPM.
	 * Note: This is required since the auth session ID assigned by the TPM is not unique (e.g. IFX
	 * 1.1b TPMs or STM 1.2 TPMs; IFX 1.2 TPMs assign a unique ID to auth sessions).
	 * 
	 * @param auth Auth session the unique ID should be generated for.
	 * 
	 * @return The new unique ID.
	 */
	protected TcBlobData deriveUniqueAuthId(TcTcsAuth auth)
	{
		// we hash nonce even again and use this value as unique id
		return auth.getNonceEven().getNonce().sha1();
	}


	/*************************************************************************************************
	 * This method is called if a new auth session was established.
	 * 
	 * @param authHandle The new auth session.
	 * @param nonceEven The even nonce generated by the TPM.
	 */
	public void addActiveAuthSession(long authHandle, TcTpmNonce nonceEven)
	{
		// Note: We can not rely on authHandle to uniquely identify an auth session. Some TPMs do not
		// use unique handles for new auth sessions (they reuse handles as soon as they become available
		// again). Therefore we derive a unique ID from the TcTpmAuth informations (more precisely the
		// nonce even generated by the TPM). If an auth session is continued (i.e. used for more than
		// one command), the nonce even and thereby our unique session id changes. With the
		// trackAuthSession method below we are able to track sessions that are used for more than one
		// command.

		synchronized (authSessionHandles_) {
			synchronized (authSessionIds_) {
				authSessionHandles_.add(new Long(authHandle));
				TcTcsAuth auth = new TcTcsAuth();
				auth.setNonceEven(nonceEven);
				authSessionIds_.add(deriveUniqueAuthId(auth));
				// Log.debug("added auth session: " + authHandle + " "
				// + deriveUniqueAuthId(auth).toHexString());
			}
		}
	}


	/*************************************************************************************************
	 * This method is called if an auth session is no longer active (terminated intentionally or
	 * because of an error). The auth session is removed from the list of activeAuth sessions.
	 * 
	 * @param auth The auth session to be removed.
	 */
	public void removeActiveAuthSession(TcTcsAuth auth)
	{
		synchronized (authSessionHandles_) {
			synchronized (authSessionIds_) {
				int index = authSessionIds_.indexOf(deriveUniqueAuthId(auth));
				if (index != -1) {
					authSessionIds_.remove(index);
					authSessionHandles_.remove(index);
				} else {
					Log.warn("Could not find auth session to remove (" + index + ", "
							+ deriveUniqueAuthId(auth).toHexString() + ")");
				}
			}
		}
	}


	/*************************************************************************************************
	 * This method is called if an auth is used to authorize more than one TPM command. In such a
	 * case, the TPM generates a new nonceEven and consequently the unique identifier we use for auth
	 * sessions changes as well. Therefore, this method updates the identifier of the auth session in
	 * the list of active auth sessions.
	 */
	public void trackActiveAuthSession(TcTcsAuth inAuth, TcTcsAuth outAuth)
	{
		TcBlobData oldId = deriveUniqueAuthId(inAuth);
		TcBlobData newId = deriveUniqueAuthId(outAuth);
		Long newHandle = new Long(outAuth.getAuthHandle());

		synchronized (authSessionHandles_) {
			synchronized (authSessionIds_) {
				int index = authSessionIds_.indexOf(oldId);
				if (index != -1) {
					authSessionIds_.set(index, newId);
					authSessionHandles_.set(index, newHandle);
				} else {
					Log.warn("Updating active auth sessions failed. Old ID not found: " + oldId.toHexString()

					+ ".");
				}
			}
		}
	}


	/*************************************************************************************************
	 * This method removes the first (oldest) active auth session from the list of active sessions.
	 * The removed entry is returned.
	 * 
	 * @param keepHandles This array contains handles that must not be removed.
	 * 
	 * @return If no suitable auth session could be found, null is returned. Otherwise, an Object[]
	 *         {(TcBlobData) authSessionId, (Long) authSessionHandle) } is returned.
	 */
	protected Object[] removeFirstActiveAuthSession(long[] keepHandles)
	{
		synchronized (authSessionHandles_) {
			synchronized (authSessionIds_) {
				if (authSessionHandles_.isEmpty()) {
					return null;
				}

				Object authId = null;
				Object authHnd = null;

				for (int i = 0; i < authSessionHandles_.size(); i++) {
					long currentHandle = ((Long) authSessionHandles_.get(i)).longValue();
					boolean matchFound = false;
					for (int j = 0; j < keepHandles.length; j++) {
						if (keepHandles[j] == currentHandle) {
							matchFound = true;
							break; // j loop
						}
					}
					if (!matchFound) {
						authId = authSessionIds_.remove(i);
						authHnd = authSessionHandles_.remove(i);
						break;
					}
				}

				if (authId == null || authHnd == null) {
					return null;
				} else {
					return new Object[] { authId, authHnd };
				}
			}
		}
	}


	/*************************************************************************************************
	 * This method returns true if the given auth session could be found in the list of active
	 * sessions, false otherwise.
	 */
	protected boolean isActiveAuthSession(TcTcsAuth auth)
	{
		synchronized (authSessionHandles_) {
			synchronized (authSessionIds_) {
				TcBlobData authId = deriveUniqueAuthId(auth);
				if (authSessionIds_.contains(authId)) {
					return true;
				} else {
					return false;
				}
			}
		}
	}


	/*************************************************************************************************
	 * This method returns a string representation of the active auth sessions (containing session ids
	 * and session handles).
	 */
	protected String activeAuthSessionsToString()
	{
		StringBuffer sb = new StringBuffer("active auth sessions: ");
		sb.append(Utils.getNL());

		synchronized (authSessionHandles_) {
			synchronized (authSessionIds_) {
				for (int i = 0; i < authSessionIds_.size(); i++) {
					sb.append("handle: ");
					sb.append( authSessionHandles_.get(i));
					sb.append(" id: ");
					sb.append(((TcBlobData) authSessionIds_.get(i)).toHexString());
					sb.append(Utils.getNL());
				}
			}
		}

		return sb.toString();
	}

}
