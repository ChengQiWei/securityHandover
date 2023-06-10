/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.impl.java.tcs.authmgr;


import iaik.tc.tss.api.constants.tpm.TcTpmConstants;
import iaik.tc.tss.api.exceptions.tcs.TcTcsException;
import iaik.tc.tss.api.exceptions.tcs.TcTddlException;
import iaik.tc.tss.api.exceptions.tcs.TcTpmException;
import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.tss.api.structs.tcs.TcTcsAuth;
import iaik.tc.tss.api.structs.tpm.TcTpmKeyHandleList;
import iaik.tc.tss.api.structs.tpm.TcTpmNonce;
import iaik.tc.tss.impl.java.tcs.pbg.TcTpmCmdCapability;
import iaik.tc.tss.impl.java.tddl.TcTddl;

/**
 * This class implements the auth session handling for Windows Vista. Contrary to the TSS design
 * of the TCG, on Vista the TSS is not the software component that has exclusive access to the
 * TPM. On Vista TPM access is managed by the TPM Base Services (TBS). The TBS can block specified
 * TPM commands and also offers resource virtualization. By virtualization, TBS means that TPM
 * key slots and session handles returned by the TPM are not directly passed to applications
 * that use the TBS. For every TPM resource, the TBS creates an own, virtualized, handle it
 * returns to the calling application. Internally, the TBS keeps a mapping from TPM resource
 * handles to TBS resource handles. When commands are sent to the TPM, the TBS modifies the
 * command stream such that it replaces TBS handles with real TPM handles. By that, the TBS
 * greatly increases the resources offered by the TPM.
 * In essence, the TBS takes over duties from the TSS (e.g. caching auth sessions using
 * Save/LoadContext). As a consequence, the TSS can not really do resource management (since
 * it does not get hold of the actual TPM resources) but has to/can rely on the TBS to do
 * its job.     
 */
public class TcTcsAuthCacheVista extends TcTcsAuthCache {

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
	public void swapOutAuth(long[] keepHandles) throws TcTddlException, TcTpmException, TcTcsException
	{
	}


	/*
	 * (non-Javadoc)
	 * 
	 * @see iaik.tss.impl.java.tcs.authmgr.TcTcsAuthCache#ensureAuthsAreLoadedInTpm(iaik.tss.api.structs.tcs.TcTpmAuth[])
	 */
	public void ensureAuthsAreLoadedInTpm(TcTcsAuth[] auths)
		throws TcTddlException, TcTpmException, TcTcsException
	{
	}

	
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
