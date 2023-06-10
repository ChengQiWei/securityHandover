/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.impl.java.tcs.authmgr;

import iaik.tc.tss.api.constants.tcs.TcTcsErrors;
import iaik.tc.tss.api.exceptions.tcs.TcTcsException;
import iaik.tc.tss.api.exceptions.tcs.TcTddlException;
import iaik.tc.tss.api.exceptions.tcs.TcTpmException;
import iaik.tc.tss.api.structs.tcs.TcTcsAuth;
import iaik.tc.tss.impl.java.tcs.pbg.TcTpmCmdDeprKey;
import iaik.tc.tss.impl.java.tddl.TcTddl;

public class TcTcsAuthCacheTpm11NoSwap extends TcTcsAuthCache {

	/*
	 * (non-Javadoc)
	 * 
	 * @see iaik.tss.impl.java.tcs.authmgr.TcTcsAuthCache#cachedAuthSessionsToString()
	 */
	public String cachedAuthSessionsToString() throws TcTddlException, TcTpmException
	{
		return "Auth session caching is not supported by this TPM.";
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see iaik.tss.impl.java.tcs.authmgr.TcTcsAuthCache#ensureAuthsAreLoadedInTpm(iaik.tss.api.structs.tcs.TcTcsAuth[])
	 */
	public void ensureAuthsAreLoadedInTpm(TcTcsAuth[] auths)
		throws TcTddlException, TcTpmException, TcTcsException
	{
		// Noting to do since TPM supports not auth session caching.
	}

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

		Object[] session = removeFirstActiveAuthSession(keepHandles);
		if (session == null) {
			throw new TcTcsException(TcTcsErrors.TCS_E_INTERNAL_ERROR,
					"Unable to swap out auth session: No suitable session found.");
		}

		Long authHandle = (Long)session[1];
		TcTpmCmdDeprKey.TpmTerminateHandle(dest, authHandle.longValue());
	}

}
