/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.impl.java.tcs.sessmgr;


import iaik.tc.tss.api.constants.tcs.TcTcsErrors;
import iaik.tc.tss.api.constants.tpm.TcTpmConstants;
import iaik.tc.tss.api.exceptions.tcs.TcTcsException;
import iaik.tc.tss.api.exceptions.tcs.TcTddlException;
import iaik.tc.tss.api.exceptions.tcs.TcTpmException;
import iaik.tc.tss.api.structs.common.TcBasicTypeDecoder;
import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.tss.api.structs.tpm.TcTpmContextBlob;
import iaik.tc.tss.api.structs.tpm.TcTpmKeyHandleList;
import iaik.tc.tss.impl.java.tcs.pbg.TcTpmCmdCapability;
import iaik.tc.tss.impl.java.tcs.pbg.TcTpmCmdEviction;
import iaik.tc.tss.impl.java.tcs.pbg.TcTpmCmdSessMgmt;
import iaik.tc.tss.impl.java.tddl.TcTddl;
import iaik.tc.utils.logging.Log;
import iaik.tc.utils.misc.Utils;

import java.util.LinkedList;

/**
 * The functionality provided by this class is only usable by TPMs conforming to the version 1.2 of
 * the TPM specification!
 * 
 * This class implements the management of saved TPM sessions as specified in the 1.2 TPM
 * specification. Sessions can be exported from the TPM via the TPM_SaveContext command and
 * re-loaded into the TPM using the TPM_LoadContext command. The number of sessions that can be
 * saved is limited by the size of contextList[]. This is a list kept inside the TPM that holds
 * contextCound values. All sessions exported from the TPM are assigned such a contextCount value
 * which is not allowed to wrap.
 * 
 * Note: The following resource types are handled in contextList: TPM_RT_AUTH, TPM_RT_TRANS,
 * TPM_RT_DAA_TPM. Keys (TPM_RT_KEY) are NOT handled in this list. That means that the size
 * limitation of contextList does NOT apply to keys exported (via SaveContext) from the TPM.
 */
public class TcTcsSessManager {

	/**
	 * This list is used to keep track of the sessions that have been saved. It holds instances of
	 * TcTpmContextBlob.
	 */
	protected LinkedList savedSessions_ = new LinkedList();

	/**
	 * This class is implemented as a singleton. This field holds then only instance of the class.
	 */
	protected static TcTcsSessManager instance_ = null;


	/**
	 * This class can only be instantiated once (Singleton).
	 */
	public static synchronized TcTcsSessManager getInstance()
	{
		if (instance_ == null) {
			instance_ = new TcTcsSessManager();
		}
		return instance_;
	}


	/*************************************************************************************************
	 * This method evicts all saved context sessions from the TPM. The TSS is supposed to have full
	 * control of the TPM. No other entity than the TSS is responsible for managing sessions.
	 * Consequently, the TSS flushes all old saved context sessions before taking control of the saved
	 * context slots.
	 * 
	 * @throws TcTddlException
	 * @throws TcTpmException
	 */
	public void evictAllSavedSessions() throws TcTddlException, TcTpmException
	{
		evictAllSavedSessions(TcTddl.getInstance());
	}

	/*************************************************************************************************
	 * This method evicts all saved context sessions from the TPM. The TSS is supposed to have full
	 * control of the TPM. No other entity than the TSS is responsible for managing sessions.
	 * Consequently, the TSS flushes all old saved context sessions before taking control of the saved
	 * context slots.
	 * 
	 * @throws TcTddlException
	 * @throws TcTpmException
	 */
	public void evictAllSavedSessions(TcTddl tddl) throws TcTddlException,
			TcTpmException {
		TcBlobData subCap = TcBlobData.newUINT32(TcTpmConstants.TPM_RT_CONTEXT);
		Object[] tpmOutData = TcTpmCmdCapability.TpmGetCapability(tddl,	TcTpmConstants.TPM_CAP_HANDLE,
				subCap);

		TcTpmKeyHandleList savedSessions = new TcTpmKeyHandleList((TcBlobData) tpmOutData[1]);
		for (int i = 0; i < savedSessions.getHandle().length; i++) {
			TcTpmCmdEviction.TpmFlushSpecific(tddl, savedSessions.getHandle()[i],
					TcTpmConstants.TPM_RT_CONTEXT);
		}
	}


	/*************************************************************************************************
	 * This method adds a session to the list of saved sessions. This method is called whenever a
	 * session had to be swapped out of the TPM due to space limitations.
	 * @param blob The saved context blob that was exported from the TPM.
	 */
	public void addSavedSession(TcTpmContextBlob blob)
	{
		synchronized (savedSessions_) {
			savedSessions_.addLast(blob);
		}
	}


	/*************************************************************************************************
	 * This method returns the number of free (available) slots for saved contexts inside the TPM. The
	 * TPM keeps track of saved context sessions in an internal list called contextList which is is
	 * finite.
	 * 
	 * @return The number of free slots for saved sessions.
	 * 
	 * @throws TcTddlException
	 * @throws TcTpmException
	 */
	public long getNumFreeSavedSessSlots() throws TcTddlException, TcTpmException
	{
		TcTddl dest = TcTddl.getInstance();
		TcBlobData subCap = TcBlobData.newUINT32(TcTpmConstants.TPM_CAP_PROP_CONTEXT);
		Object[] tpmOutData = TcTpmCmdCapability.TpmGetCapability(dest,
				TcTpmConstants.TPM_CAP_PROPERTY, subCap);
		long numFreeSavedContextSlots = new TcBasicTypeDecoder((TcBlobData) tpmOutData[1])
				.decodeUINT32();

		return numFreeSavedContextSlots;
	}


	/*************************************************************************************************
	 * According to the TPM 1.2 spec, a TPM can only hold a limited amount of saved sessions (this is
	 * limited by the size of contextList inside the TPM). If the list of saved context sessions can
	 * not hold any further sessions (i.e. numFreeContextSlots return 0) no more sessions can be
	 * swapped out of the TPM. In such a case, this method allows to evict the oldest saved session to
	 * free up space in the list of saved sessions. This method deletes a sessions bases on a given
	 * resource type. The session is removed from the internal list as well as from the TPM.
	 * 
	 * @param resType The resource type of the session to be removed.
	 * @param notHandles With this parameter, the caller can specify a handle that MUST not be removed
	 *          even if it is the oldest handle of the given resource type. If passing -1 (invalid
	 *          handle) as notHandle, this parameter has no effect.
	 * 
	 * @return If a handle matching the given resource type that does not match notHande could be
	 *         found and successfully remove, true is returned. If no such handle could be found,
	 *         false is returned.
	 * 
	 * @throws TcTddlException
	 * @throws TcTpmException
	 */
	public boolean evictOldestSavedSess(long resType, long[] notHandles)
		throws TcTddlException, TcTpmException
	{
		TcTpmContextBlob blob = null;
		synchronized (savedSessions_) {
			for (int i = 0; i < savedSessions_.size(); i++) {
				TcTpmContextBlob tmp = (TcTpmContextBlob) savedSessions_.get(i);
				if (tmp.getResourceType() == resType) {
					boolean swapOutOk = true;
					for (int j = 0; j < notHandles.length; j++) {
						if (tmp.getResourceType() == notHandles[j]) {
							swapOutOk = false;
							break; // j-loop
						}
					}
					if (swapOutOk) {
						blob = tmp;
						savedSessions_.remove(i);
						break; // i-loop
					}
				}
			}
		}

		if (blob == null) {
			return false;
		}

		Log.debug("evicting saved session (contextCount: " + blob.getContextCount() + ", RT: "
				+ blob.getResourceType() + ", handle: " + blob.getHandle() + ")");

		TcTddl dest = TcTddl.getInstance();
		TcTpmCmdEviction.TpmFlushSpecific(dest, blob.getContextCount(), TcTpmConstants.TPM_RT_CONTEXT);

		return true;
	}


	/*************************************************************************************************
	 * According to the TPM 1.2 spec, a TPM can only hold a limited amount of saved sessions (this is
	 * limited by the size of contextList inside the TPM). If the list of saved context sessions can
	 * not hold any further sessions (i.e. numFreeContextSlots return 0) no more sessions can be
	 * swapped out of the TPM. In such a case, this method allows to evict the oldest saved session to
	 * free up space in the list of saved sessions. The session is removed from the internal list as
	 * well as from the TPM.
	 * 
	 * @param notHandles With this parameter, the caller can specify handles that MUST not be removed
	 *          even if they are the oldest handles of the given resource type. If passing an empty
	 *          array as notHandles, this parameter has no effect.
	 * 
	 * @return If a handle that does not match notHande could be found and successfully remove, true
	 *         is returned. If no such handle could be found, false is returned.
	 * 
	 * @throws TcTddlException
	 * @throws TcTpmException
	 */
	public boolean evictOldestSavedSess(long[] notHandles) throws TcTddlException, TcTpmException
	{
		TcTpmContextBlob blob = null;
		synchronized (savedSessions_) {
			for (int i = 0; i < savedSessions_.size(); i++) {
				TcTpmContextBlob tmp = (TcTpmContextBlob) savedSessions_.get(i);

				boolean swapOutOk = true;
				for (int j = 0; j < notHandles.length; j++) {
					if (tmp.getResourceType() == notHandles[j]) {
						swapOutOk = false;
						break; // j-loop
					}
				}
				if (swapOutOk) {
					blob = tmp;
					savedSessions_.remove(i);
					break; // i-loop
				}
			}
		}

		if (blob == null) {
			return false;
		}

		Log.debug("evicting saved session (contextCount: " + blob.getContextCount() + ", RT: "
				+ blob.getResourceType() + ", handle: " + blob.getHandle() + ")");

		TcTddl dest = TcTddl.getInstance();
		TcTpmCmdEviction.TpmFlushSpecific(dest, blob.getContextCount(), TcTpmConstants.TPM_RT_CONTEXT);

		return true;
	}


	/*************************************************************************************************
	 * This method loads a saved session into the TPM. It is assumed that there is enough space to
	 * load the session. This method will not attempt to free space inside the TPM if the session can
	 * not be loaded. If not enough space is available, this is indicated by a TcTpmException.
	 * 
	 * @param resType The resource type of the session to be loaded.
	 * @param handle The handle of the session to be reloaded.
	 * 
	 * @return When reloading sessions, the TPM may assign a new handle to the reloaded session. The
	 *         session handle assigned by the TPM is returned by this method.
	 * 
	 * @throws TcTddlException
	 * @throws TcTpmException
	 * @throws TcTcsException This exception is thrown if the given resource type/handle combination
	 *           could not be found in the cache.
	 */
	public long loadSession(long resType, long handle)
		throws TcTddlException, TcTpmException, TcTcsException
	{
		synchronized (savedSessions_) {
			for (int i = 0; i < savedSessions_.size(); i++) {
				TcTpmContextBlob blob = (TcTpmContextBlob) savedSessions_.get(i);
				if (blob.getResourceType() == resType && blob.getHandle() == handle) {
					TcTddl dest = TcTddl.getInstance();
					Object[] tpmOutData = TcTpmCmdSessMgmt.TpmLoadContext(dest, blob.getHandle(), true, blob
							.getEncoded().getLengthAsLong(), blob);
					if (handle != ((Long) tpmOutData[1]).longValue()) {
						Log.debug("Got new handle for re-loaded sessions (old: " + handle + ", new: "
								+ (Long) tpmOutData[1] + ")");
					}
					savedSessions_.remove(i);
					return ((Long) tpmOutData[1]).longValue();
				}
			}
		}

		throw new TcTcsException(TcTcsErrors.TCS_E_BAD_PARAMETER,
				"Given resource type/handle combination not found in cache.");
	}


	/*************************************************************************************************
	 * This method checks if an entity with the given resource type and handle is in the cache.
	 */
	public boolean handleIsInCache(long resType, long handle)
	{
		boolean retVal = false;

		synchronized (savedSessions_) {
			for (int i = 0; i < savedSessions_.size(); i++) {
				if (((TcTpmContextBlob) savedSessions_.get(i)).getResourceType() == resType
						&& ((TcTpmContextBlob) savedSessions_.get(i)).getHandle() == handle) {
					retVal = true;
					break;
				}
			}
		}

		return retVal;
	}


	/*************************************************************************************************
	 * This method is designed for debug purposes. It returns a String holding the saved sessions as
	 * reported by the TPM and as stored in the session cache.
	 */
	public String savedSessionsToString() throws TcTddlException, TcTpmException
	{
		TcTddl dest = TcTddl.getInstance();
		TcBlobData subCap = TcBlobData.newUINT32(TcTpmConstants.TPM_RT_CONTEXT);
		Object[] tpmOutData = TcTpmCmdCapability.TpmGetCapability(dest, TcTpmConstants.TPM_CAP_HANDLE,
				subCap);
		TcBlobData capBlob = (TcBlobData) tpmOutData[1];

		String retVal = "";
		TcTpmKeyHandleList savedSessions = new TcTpmKeyHandleList(capBlob);

		String sessHandles = "saved session handles (Cache): ";
		synchronized (savedSessions_) {
			for (int i = 0; i < savedSessions_.size(); i++) {
				sessHandles += ((TcTpmContextBlob) savedSessions_.get(i)).getHandle() + " (RT: "
						+ ((TcTpmContextBlob) savedSessions_.get(i)).getResourceType() + ", CNT: "
						+ ((TcTpmContextBlob) savedSessions_.get(i)).getContextCount() + ")  ";
			}
		}

		retVal = "saved sessions (TPM): " + savedSessions.toString() + Utils.getNL() + sessHandles;

		return retVal;
	}
}
