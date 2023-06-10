/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.impl.java.tcs.tcsi;

import iaik.tc.tss.api.constants.tcs.TcTcsErrors;
import iaik.tc.tss.api.constants.tpm.TcTpmConstants;
import iaik.tc.tss.api.exceptions.common.TcTssException;
import iaik.tc.tss.api.exceptions.tcs.TcTcsException;
import iaik.tc.tss.api.exceptions.tcs.TcTddlException;
import iaik.tc.tss.api.exceptions.tcs.TcTpmException;
import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.tss.api.structs.tcs.TcTcsAuth;
import iaik.tc.tss.api.structs.tcs.TcTcsLoadkeyInfo;
import iaik.tc.tss.api.structs.tpm.TcITpmKey;
import iaik.tc.tss.api.structs.tpm.TcITpmKeyNew;
import iaik.tc.tss.api.structs.tpm.TcITpmPcrInfo;
import iaik.tc.tss.api.structs.tpm.TcITpmStoredData;
import iaik.tc.tss.api.structs.tpm.TcTpmCmkAuth;
import iaik.tc.tss.api.structs.tpm.TcTpmDelegateOwnerBlob;
import iaik.tc.tss.api.structs.tpm.TcTpmDelegatePublic;
import iaik.tc.tss.api.structs.tpm.TcTpmDigest;
import iaik.tc.tss.api.structs.tpm.TcTpmEncauth;
import iaik.tc.tss.api.structs.tpm.TcTpmKey;
import iaik.tc.tss.api.structs.tpm.TcTpmKey12;
import iaik.tc.tss.api.structs.tpm.TcTpmKeyParms;
import iaik.tc.tss.api.structs.tpm.TcTpmMigrationkeyAuth;
import iaik.tc.tss.api.structs.tpm.TcTpmMsaComposite;
import iaik.tc.tss.api.structs.tpm.TcTpmNonce;
import iaik.tc.tss.api.structs.tpm.TcTpmNvDataPublic;
import iaik.tc.tss.api.structs.tpm.TcTpmPcrInfoLong;
import iaik.tc.tss.api.structs.tpm.TcTpmPcrSelection;
import iaik.tc.tss.api.structs.tpm.TcTpmPubkey;
import iaik.tc.tss.api.structs.tpm.TcTpmSecret;
import iaik.tc.tss.api.structs.tpm.TcTpmStorePubkey;
import iaik.tc.tss.api.structs.tpm.TcTpmTransportPublic;
import iaik.tc.tss.api.structs.tsp.TcTssKmKeyinfo;
import iaik.tc.tss.api.structs.tsp.TcTssPcrEvent;
import iaik.tc.tss.api.structs.tsp.TcTssUuid;
import iaik.tc.tss.impl.java.tcs.TcTcsProperties;
import iaik.tc.tss.impl.java.tcs.authmgr.TcTcsAuthCache;
import iaik.tc.tss.impl.java.tcs.authmgr.TcTcsAuthManager;
import iaik.tc.tss.impl.java.tcs.credmgr.TcTcsCredMgr;
import iaik.tc.tss.impl.java.tcs.ctxmgr.TcTcsContextMgr;
import iaik.tc.tss.impl.java.tcs.eventmgr.TcITcsEventMgr;
import iaik.tc.tss.impl.java.tcs.kcmgr.TcTcsKeyCache;
import iaik.tc.tss.impl.java.tcs.kcmgr.TcTcsKeyManager;
import iaik.tc.tss.impl.java.tcs.pbg.TcTpmCmdAdminOptIn;
import iaik.tc.tss.impl.java.tcs.pbg.TcTpmCmdAdminOwnership;
import iaik.tc.tss.impl.java.tcs.pbg.TcTpmCmdAdminTesting;
import iaik.tc.tss.impl.java.tcs.pbg.TcTpmCmdAudit;
import iaik.tc.tss.impl.java.tcs.pbg.TcTpmCmdCapability;
import iaik.tc.tss.impl.java.tcs.pbg.TcTpmCmdChangeAuth;
import iaik.tc.tss.impl.java.tcs.pbg.TcTpmCmdCrypto;
import iaik.tc.tss.impl.java.tcs.pbg.TcTpmCmdDaa;
import iaik.tc.tss.impl.java.tcs.pbg.TcTpmCmdDelegation;
import iaik.tc.tss.impl.java.tcs.pbg.TcTpmCmdDeprChangeAuth;
import iaik.tc.tss.impl.java.tcs.pbg.TcTpmCmdDeprDir;
import iaik.tc.tss.impl.java.tcs.pbg.TcTpmCmdDeprKey;
import iaik.tc.tss.impl.java.tcs.pbg.TcTpmCmdDeprMisc;
import iaik.tc.tss.impl.java.tcs.pbg.TcTpmCmdEkHandling;
import iaik.tc.tss.impl.java.tcs.pbg.TcTpmCmdIdentity;
import iaik.tc.tss.impl.java.tcs.pbg.TcTpmCmdIntegrity;
import iaik.tc.tss.impl.java.tcs.pbg.TcTpmCmdMaintenance;
import iaik.tc.tss.impl.java.tcs.pbg.TcTpmCmdManagement;
import iaik.tc.tss.impl.java.tcs.pbg.TcTpmCmdMigration;
import iaik.tc.tss.impl.java.tcs.pbg.TcTpmCmdMonotonicCnt;
import iaik.tc.tss.impl.java.tcs.pbg.TcTpmCmdNvStorage;
import iaik.tc.tss.impl.java.tcs.pbg.TcTpmCmdStorage;
import iaik.tc.tss.impl.java.tcs.pbg.TcTpmCmdTiming;
import iaik.tc.tss.impl.java.tcs.pbg.TcTpmCmdTransport;
import iaik.tc.tss.impl.java.tcs.pbg.TcTpmCmdVendorSpecific;
import iaik.tc.tss.impl.java.tddl.TcTddl;
import iaik.tc.tss.impl.ps.TcITssPersistentStorage;
import iaik.tc.utils.logging.Log;
import iaik.tc.utils.misc.CheckPrecondition;
import iaik.tc.utils.properties.Properties;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;

/**
 * This class provides a set of functions making up the TCS interface (TCSI).
 * This interface is the one to be exposed to the TSP. This can be done in
 * several ways ranging from RPC (RMI) to SOAP. For testing, a local procedure
 * call interface might be of interest as well. Note that access to the TPM must
 * be properly synchronized. According to the TCG specification, the TCS is the
 * component for the TSS that is responsible for this synchronization. Since all
 * calls from TSPs (no matter if they were received via SOAP, RMI, ...) have to
 * pass the TCSI implemented in this class, it is the logical point for
 * implementing synchronization. Methods (or data) that are beyond (or more
 * precisely below) the TCSI do not require explicit synchronization since it
 * can safely be assumed that only one thread at a time can be beyond this
 * point.
 *
 */
public class TcTcsi {

	private static TcTcsKeyCache initKeyCache() {
		// instantiate key cache
		TcTcsKeyCache keyCache = null;
		try {
			keyCache = TcTcsKeyCache.getInstance();
		} catch (TcTssException e) {
			Log.warn("Can not instantiate key cache");
			Log.debug(e.toString());
		}
		return keyCache;
	}

	private static TcITssPersistentStorage initSystemPS() {
		// instantiate persistent storage
		TcITssPersistentStorage ps = null;
		String psClassName = "";
		try {
			psClassName = TcTcsProperties.getInstance().getProperty(
					TcTcsProperties.TCS_INI_SEC_PS,
					TcTcsProperties.TCS_INI_KEY_PS_TYPE);
			Class cls = Class.forName(psClassName);
			Class[] constParams = new Class[] { Properties.class };
			Constructor constr = cls.getConstructor(constParams);
			ps = (TcITssPersistentStorage) constr
					.newInstance(new Object[] { TcTcsProperties.getInstance() });

		} catch (TcTcsException e) {
			Log.info("Unable to open TCS configuration file for system persistent "
					+ "storage information. Disabling system persistent storage.");
			Log.debug(e.toString());
		} catch (InvocationTargetException e) {
			Log.info("Unable to instantiate system persistent storage.");
			Throwable cause = e.getCause();
			if (cause instanceof TcTssException) {
				Log.debug(cause.toString());
			} else {
				Log.debug(cause.toString() + ": " + cause.getMessage());
			}
		} catch (Exception e) {
			Log.info("Unable to instantiate system persistent storage ("
					+ psClassName + "). Disabling system persistent storage.");
			Log.debug(e.toString() + ": " + e.getMessage());
		}

		return ps;
	}

	private static TcITcsEventMgr initEventManager() {
		// instantiate Event Log
		TcITcsEventMgr evtMgr = null;
		String elClassName = "";
		try {

			elClassName = TcTcsProperties.getInstance().getProperty(
					TcTcsProperties.TCS_INI_SEC_EVENTMGR,
					TcTcsProperties.TCS_INI_KEY_EVENTMGR_TYPE);

			evtMgr = (TcITcsEventMgr) Class.forName(elClassName)
					.getMethod("getInstance", new Class[0])
					.invoke(null, (Object[]) null);

		} catch (TcTcsException e) {
			Log.info("Unable to open TCS configuration file for TCS event log "
					+ "information.");
			Log.debug(e.toString());
		} catch (InvocationTargetException e) {
			Log.info("Unable to instantiate TCS event log.");
			Throwable cause = e.getCause();
			if (cause instanceof TcTssException) {
				Log.debug(cause.toString());
			} else {
				Log.debug(cause.toString() + ": " + cause.getMessage());
			}
		} catch (Exception e) {
			Log.info("Unable to instantiate TCS event log (" + elClassName
					+ "). Check the TCS configuration file.");
			Log.debug(e.toString() + ": " + e.getMessage());
		}

		return evtMgr;
	}

	private static TcTcsKeyCache getKeyCache() {
		if (keyCache_ == null) {
			keyCache_ = initKeyCache();
		}

		return keyCache_;
	}

	private static TcITssPersistentStorage getPsSystem() {
		if (psSystem_ == null) {
			psSystem_ = initSystemPS();
		}

		return psSystem_;
	}

	private static TcITcsEventMgr getEventManager() {
		if (eventManager_ == null) {
			eventManager_ = initEventManager();
		}

		return eventManager_;
	}

	/**
	 * Key cache manager.
	 */
	protected static TcTcsKeyCache keyCache_ = null;

	/**
	 * Persistent System Storage.
	 */
	protected static TcITssPersistentStorage psSystem_ = null;

	/**
	 *
	 */
	protected static TcITcsEventMgr eventManager_ = null;

	// - - - - - Context Methods - - - - -

	public static synchronized Object[] TcsiOpenContext() {
		return TcTcsContextMgr.TcsiOpenContext();
	}

	public static synchronized long TcsiCloseContext(long hContext)
			throws TcTcsException, TcTpmException, TcTddlException {
		return TcTcsContextMgr.TcsiCloseContext(hContext);
	}

	public static synchronized long TcsiFreeMemory(long hContext, long pMemory)
			throws TcTcsException {
		return TcTcsContextMgr.TcsiFreeMemory(hContext, pMemory);
	}

	public static synchronized TcBlobData TcsiGetCapability(long hContext,
			long capArea, TcBlobData subCap) throws TcTcsException {
		return TcTcsContextMgr.TcsiGetCapability(hContext, capArea, subCap);
	}

	// - - - - - Event Manager Methods - - - - -

	/***************************************************************************
	 * This method adds a new event to the end of the array associated with the
	 * named PCR. This command adds supporting information for the named
	 * {@link TcTssPcrEvent} event to the end of the event log. The TCS MUST
	 * maintain an array of event-supporting data with events identified by the
	 * register to which they belong and the order in which the events occurred.
	 * The log need not be in a TCG-shielded location, and the Tcsi_LogPcrEvent
	 * action need not be a TCG-protected capability.
	 *
	 * @param hContext
	 *            Handle to established context.
	 * @param pcrEvent
	 *            Details of the event being logged.
	 *
	 * @return The number of the event just logged is returned in this variable.
	 *         The TCS number events for each PCR monotonically from 0.
	 *
	 * @throws {@link TcTcsException}
	 */
	public static synchronized long TcsiLogPcrEvent(long hContext,
			TcTssPcrEvent pcrEvent) throws TcTcsException {
		TcTcsContextMgr.checkContextHandle(hContext);

		if (getEventManager() == null) {
			throw new TcTcsException(TcTcsErrors.TCS_E_INTERNAL_ERROR,
					"PCR event description lost - EventManager not properly configured in TCS .ini file");
		} else {
			return getEventManager().logPcrEvent(pcrEvent);
		}
	}

	/***************************************************************************
	 * This method is used to retrieve events logged with
	 * {@link TcTcsi#TcsiLogPcrEvent(long, TcTssPcrEvent)}. This method needs
	 * not to be a protected capability and the log events retrieved need not to
	 * be in a shielded location.
	 *
	 * The command retrieves events previously logged using
	 * {@link TcTcsi#TcsiLogPcrEvent(long, TcTssPcrEvent)}. The format of the
	 * data returned is identical to that previously logged. This operation
	 * retrieves log entries by PCR index and event number. On TCS
	 * initialization the event log for each PCR is empty. Then, for each PCR,
	 * the first event logged is numbered 0; the next is numbered 1, and so on.
	 * Attempts to receive log items beyond the end of the log return an error.
	 *
	 * @param hContext
	 *            Handle to the established context.
	 * @param pcrIndex
	 *            The index of the PCR.
	 * @param number
	 *            The number events required. Events are numbered from 0 to the
	 *            number of events logged on the named PCR.
	 *
	 * @return TcTssPcrEvent holding the retrieved event.
	 *
	 * @throws {@link TcTcsException}
	 */
	public static synchronized TcTssPcrEvent TcsiGetPcrEvent(long hContext,
			long pcrIndex, long number) throws TcTcsException {
		TcTcsContextMgr.checkContextHandle(hContext);

		if (getEventManager() == null) {
			throw new TcTcsException(TcTcsErrors.TCS_E_INTERNAL_ERROR,
					"EventManager not properly configured in TCS .ini file");
		} else {
			return getEventManager().getPcrEvent(pcrIndex, number);
		}
	}

	/***************************************************************************
	 * This method returns the number of events logged with
	 * {@link TcTcsi#TcsiLogPcrEvent(long, TcTssPcrEvent)}.
	 *
	 * @param hContext
	 *            Handle to the established context.
	 * @param pcrIndex
	 *            The index of the PCR.
	 *
	 * @return The number of elements found matching the given criteria.
	 *
	 * @throws {@link TcTcsException}
	 */
	public static synchronized long TcsiGetPcrEventCount(long hContext,
			long pcrIndex) throws TcTcsException {
		TcTcsContextMgr.checkContextHandle(hContext);

		if (getEventManager() == null) {
			throw new TcTcsException(TcTcsErrors.TCS_E_INTERNAL_ERROR,
					"EventManager not properly configured in TCS .ini file");
		} else {
			return getEventManager().getPcrEventCount(pcrIndex);
		}
	}

	/***************************************************************************
	 * This method returns an event log bound to a single PCR. The event log is
	 * returned as an ordered sequence of {@link TcTssPcrEvent} structures. The
	 * caller can limit the size of the returned array using eventCount. The
	 * caller can also specify the number of the first event on the returned
	 * event log using firstEvent. This allow the caller to retrieve the event
	 * log step by step, or to retrieve a partial event log when required. The
	 * array elements are of variable size, and the {@link TcTssPcrEvent}
	 * structure defines the size of the current event and the register with
	 * which it is associated.
	 *
	 * @param hContext
	 *            Handle to the established context.
	 * @param pcrIndex
	 *            The index of the PCR.
	 * @param firstEvent
	 *            The number of the first event in the returned array.
	 * @param eventCount
	 *            The max number of events to returned. Set to -1 to return all
	 *            events for the PCR.
	 *
	 * @return The event array as defined by the parameters.
	 *
	 * @throws {@link TcTcsException}
	 */
	public static synchronized TcTssPcrEvent[] TcsiGetPcrEventsByPcr(
			long hContext, long pcrIndex, long firstEvent, long eventCount)
			throws TcTcsException {
		TcTcsContextMgr.checkContextHandle(hContext);

		if (getEventManager() == null) {
			throw new TcTcsException(TcTcsErrors.TCS_E_INTERNAL_ERROR,
					"EventManager not properly configured in TCS .ini file");
		} else {
			return getEventManager().getPcrEventsByPcr(pcrIndex, firstEvent, eventCount);
		}
	}

	/***************************************************************************
	 * This method returns the event log of all events since the TPM was
	 * initialized. The event log is returned as an ordered sequence of
	 * {@link TcTssPcrEvent} structures in the following order: all events bound
	 * to PCR 0 (in the order they have arrived), all events bound to PCR 1 (in
	 * the order they have arrived), etc. If the event log is empty, an empty
	 * array is returned.
	 *
	 * @param hContext
	 *            Handle to the established context.
	 *
	 * @return Array holding all the events collected up to this point.
	 *
	 * @throws {@link TcTcsException}
	 */
	public static synchronized TcTssPcrEvent[] TcsiGetPcrEventLog(long hContext)
			throws TcTcsException {
		TcTcsContextMgr.checkContextHandle(hContext);

		if (getEventManager() == null) {
			throw new TcTcsException(TcTcsErrors.TCS_E_INTERNAL_ERROR,
					"EventManager not properly configured in TCS .ini file");
		} else {
			return getEventManager().getPcrEventLog();
		}
	}

	// - - - - - Persistent Storage Methods - - - - -

	/***************************************************************************
	 * Tcsi_RegisterKey allows registering a key in the TCS Persistent Storage
	 * (PS). Only system specific keys (keys definitely bound to a certain
	 * system) should be registered in TCS PS. A key can be registered in TCS PS
	 * by providing: a) A UUID for that key, b) A UUID for its wrapping parent
	 * key and c) The key blob itself. If the same UUID is used to register a
	 * key on different systems this key can be addressed on different systems
	 * by the same UUID. This may be done for a basic roaming key, which will
	 * wrap all user storage keys in the appropriate key hierarchy.
	 *
	 * @param hContext
	 *            Handle to established context.
	 * @param wrappingKeyUuid
	 *            UUID of the already registered wrapping parent key.
	 * @param keyUuid
	 *            Id of the key to be registered.
	 * @param key
	 *            The key blob to be stored in the persistent storage.
	 * @param vendorData
	 *            Vendor specific data (currently ignored).
	 *
	 * @throws {@link TcTcsException}
	 */
	public static synchronized void TcsiRegisterKey(long hContext,
			TcTssUuid wrappingKeyUuid, TcTssUuid keyUuid, TcBlobData key,
			TcBlobData vendorData) throws TcTssException {
		TcTcsContextMgr.checkContextHandle(hContext);
		if (getPsSystem() != null) {
			getPsSystem().registerKey(wrappingKeyUuid, keyUuid, key);
		} else {
			throw new TcTcsException(TcTcsErrors.TCS_E_FAIL,
					"System persistent storage not properly initialized.");
		}
	}

	/***************************************************************************
	 * A key once registered in the TCS PS can be unregistered from the PS, if
	 * that key is not required any longer.
	 *
	 * @param hContext
	 *            Handle to established context.
	 * @param keyUuid
	 *            UUID by which the key is registered.
	 *
	 * @throws {@link TcTcsException}
	 */
	public static synchronized void TcsiUnregisterKey(long hContext,
			TcTssUuid keyUuid) throws TcTssException {
		TcTcsContextMgr.checkContextHandle(hContext);
		if (getPsSystem() != null) {
			getPsSystem().unregisterKey(keyUuid);
		} else {
			throw new TcTcsException(TcTcsErrors.TCS_E_FAIL,
					"System persistent storage not properly initialized.");
		}
	}

	/***************************************************************************
	 * Tcsip_KeyControlOwner controls attributes of a loaded key. This command
	 * requires owner authorization.
	 *
	 * @param hContext
	 *            Handle to established context.
	 * @param tcsKeyHandle
	 *            Application key handle.
	 * @param attribName
	 *            Attribute name.
	 * @param attribValue
	 *            Attribute value.
	 * @param ownerAuth
	 *            Owner authorization session data.
	 * @param uuidData
	 *            The UUID the key was registered as a TPM resident key.
	 *
	 * @throws {@link TcTcsException}
	 */
	public static synchronized void TcsipKeyControlOwner(long hContext,
			long tcsKeyHandle, long attribName, long attribValue,
			TcTcsAuth ownerAuth, TcTssUuid uuidData) throws TcTcsException {
		throw new TcTcsException(TcTcsErrors.TCS_E_NOTIMPL);
	}

	/***************************************************************************
	 * This method allows obtaining an array of {@link TcTssKmKeyinfo}
	 * structures. This information reflects the registered key hierarchy. The
	 * caller will receive information of the whole key hierarchy. The keys
	 * stored in the persistent storage are totally independent from either the
	 * context provided in the function call or the context, which was provided
	 * while processing the key registration.
	 *
	 * @param hContext
	 *            Handle to established context.
	 * @param keyUuid
	 *            UUID of key the key hierarchy should be returned of. If NULL,
	 *            the whole key hierarchy will be returned.
	 *
	 * @return Array of {@link TcTssKmKeyinfo} structures
	 *
	 * @throws {@link TcTcsException}
	 */
	public static synchronized TcTssKmKeyinfo[] TcsiEnumRegisteredKeys(
			long hContext, TcTssUuid keyUuid) throws TcTssException {
		TcTcsContextMgr.checkContextHandle(hContext);
		// note: keyUuid can be null

		if (getPsSystem() != null) {
			return getPsSystem().enumRegisteredKeys(keyUuid);
		} else {
			throw new TcTcsException(TcTcsErrors.TCS_E_FAIL,
					"System persistent storage not properly initialized.");
		}
	}

	/***************************************************************************
	 * This method allows obtaining a {@link TcTssKmKeyinfo} structure
	 * containing information about the registered key.
	 *
	 * @param hContext
	 *            Handle to established context.
	 * @param keyUuid
	 *            UUID of the key information is required.
	 *
	 * @return {@link TcTssKmKeyinfo} structure
	 *
	 * @throws {@link TcTssException}
	 */
	public static synchronized TcTssKmKeyinfo TcsiGetRegisteredKey(
			long hContext, TcTssUuid keyUuid) throws TcTssException {
		TcTcsContextMgr.checkContextHandle(hContext);
		CheckPrecondition.notNull(keyUuid, "keyUuid");
		if (getPsSystem() != null) {
			return getPsSystem().getRegisteredKey(keyUuid);
		} else {
			throw new TcTcsException(TcTcsErrors.TCS_E_FAIL,
					"System persistent storage not properly initialized.");
		}
	}

	/***************************************************************************
	 * This method returns the key blob (either {@link TcTpmKey} or
	 * {@link TcTpmKey12}) of the key with the given UUID.
	 *
	 * @param hContext
	 *            Handle to established context.
	 * @param keyUuid
	 *            UUID of the key to be returned.
	 *
	 * @return {@link TcBlobData} (either {@link TcTpmKey} or {@link TcTpmKey12})
	 *
	 * @throws {@link TcTssException}
	 */
	public static synchronized TcBlobData TcsiGetRegisteredKeyBlob(
			long hContext, TcTssUuid keyUuid) throws TcTssException {
		TcTcsContextMgr.checkContextHandle(hContext);
		CheckPrecondition.notNull(keyUuid, "keyUuid");
		if (getPsSystem() != null) {
			return getPsSystem().getRegisteredKeyBlob(keyUuid);
		} else {
			throw new TcTcsException(TcTcsErrors.TCS_E_FAIL,
					"System persistent storage not properly initialized.");
		}
	}

	/***************************************************************************
	 * This method returns the key blob specified by the publicInfo parameter.
	 * Note that the publicInfo parameter is the public part of a key (an
	 * instance of {@link TcTpmStorePubkey}.
	 *
	 * @param hContext
	 *            Handle to established context.
	 * @param algId
	 *            Algorithm ID for public key.
	 * @param publicInfo
	 *            Public key.
	 *
	 * @return {@link TcBlobData} (either {@link TcTpmKey} or {@link TcTpmKey12})
	 *
	 * @throws {@link TcTssException}
	 */
	public static synchronized TcBlobData TcsiGetRegisteredKeyByPublicInfo(
			long hContext, long algId, TcBlobData publicInfo)
			throws TcTssException {
		TcTcsContextMgr.checkContextHandle(hContext);
		if (getPsSystem() != null) {
			return getPsSystem().getRegisteredKeyByPublicInfo(algId, publicInfo);
		} else {
			throw new TcTcsException(TcTcsErrors.TCS_E_FAIL,
					"System persistent storage not properly initialized.");
		}
	}

	/***************************************************************************
	 *
	 * @param hContext
	 * @param keyUuid
	 *            The UUID of the key to be loaded.
	 * @param loadKeyInfo
	 *            Information required to load a key if authorization is
	 *            required.
	 *
	 * @return The TCS key handle of the loaded key.
	 *
	 * @throws TcTssException
	 */
	public static synchronized long TcsipLoadKeyByUuid(long hContext,
			TcTssUuid keyUuid, TcTcsLoadkeyInfo loadKeyInfo)
			throws TcTssException {
		throw new TcTcsException(TcTcsErrors.TCS_E_NOTIMPL);
	}

	// - - - - - Key Manager Methods - - - - -

	public static synchronized Object[] TcsipLoadKeyByBlob(long hContext,
			long hUnwrappingKey, TcTpmKey wrappedKeyBlob, TcTcsAuth inAuth)
			throws TcTddlException, TcTpmException, TcTcsException {
		TcTcsContextMgr.checkContextHandle(hContext);
		CheckPrecondition.notNull(wrappedKeyBlob, "wrappedKeyBlob");
		CheckPrecondition.notNull(inAuth, "inAuth"); // TODO (loadkey):
														// inAuth can be null
														// (i.e. no
		// authorization)

		Object[] retVal = TcTcsKeyManager.LoadKeyByBlob(hContext,
				hUnwrappingKey, wrappedKeyBlob, inAuth);

		// legal return codes: TCS_E_SUCCESS, TCS_E_FAIL

		return retVal;
	}

	public static synchronized Object[] TcsipLoadKey2ByBlob(long hContext,
			long tcsUnwrappingKey, TcITpmKey wrappedKeyBlob, TcTcsAuth inAuth)
			throws TcTddlException, TcTpmException, TcTcsException {
		TcTcsContextMgr.checkContextHandle(hContext);
		CheckPrecondition.notNull(wrappedKeyBlob, "wrappedKeyBlob");
		CheckPrecondition.notNull(inAuth, "inAuth"); // TODO (loadkey):
														// inAuth can be null
														// (i.e. no
		// authorization)

		Object[] retVal = TcTcsKeyManager.LoadKey2ByBlob(hContext,
				tcsUnwrappingKey, wrappedKeyBlob, inAuth);

		return retVal;
	}

	/***************************************************************************
	 * This method allows to flush a key from the key cache.
	 *
	 * @param hContext
	 *            The context the call is associated with.
	 * @param tcsKeyHandle
	 *            The TCS key handle of the key to be evicted.
	 *
	 *
	 * @throws TcTddlException,
	 *             TcTpmException
	 * @throws TcTcsException
	 */
	public static synchronized Object[] TcsipEvictKey(long hContext,
			long tcsKeyHandle) throws TcTddlException, TcTpmException,
			TcTcsException {
		TcTcsContextMgr.checkContextHandle(hContext);
		TcTcsContextMgr.getContextForHandle(hContext).checkKeyIsAssociated(
				tcsKeyHandle);

		Object[] retVal = TcTcsKeyManager.EvictKey(hContext, tcsKeyHandle);

		return retVal;
	}

	/***************************************************************************
	 * This method allows the TPM owner to read the public SRK key or the
	 * internal public EK key.
	 *
	 *
	 * @param hContext
	 * @param tcsKeyHandle
	 * @param inAuth
	 * @throws TcTddlException,
	 *             TcTpmException
	 * @throws TcTcsException
	 */
	public static synchronized Object[] TcsipOwnerReadInternalPub(
			long hContext, long tcsKeyHandle, TcTcsAuth inAuth)
			throws TcTddlException, TcTpmException, TcTcsException {
		TcTcsContextMgr.checkContextHandle(hContext);
		TcTcsContextMgr.getContextForHandle(hContext).checkKeyIsAssociated(
				tcsKeyHandle);
		CheckPrecondition.notNull(inAuth, "inAuth");
		TcTcsAuthCache.getInstance().ensureAuthsAreLoadedInTpm(
				new TcTcsAuth[] { inAuth });

		Object[] retVal = TcTcsKeyManager.OwnerReadInternalPub(hContext,
				tcsKeyHandle, inAuth);

		// legal return codes: TCS_SUCCESS, TCS_E_INVALID_CONTEXTHANDLE,
		// TCS_E_FAIL

		return retVal;
	}

	/***************************************************************************
	 * This method allows obtaining the public key data of a key loaded in the
	 * TPM. This information may have privacy concerns so the command must have
	 * authorization from the key owner.
	 *
	 * @param hContext
	 * @param tcsKeyHandle
	 * @param inAuth
	 * @throws TcTddlException,
	 *             TcTpmException
	 * @throws TcTcsException
	 */
	public static synchronized Object[] TcsipGetPubKey(long hContext,
			long tcsKeyHandle, TcTcsAuth inAuth) throws TcTddlException,
			TcTpmException, TcTcsException {
		TcTcsContextMgr.checkContextHandle(hContext);
		TcTcsContextMgr.getContextForHandle(hContext).checkKeyIsAssociated(
				tcsKeyHandle);
		CheckPrecondition.notNull(inAuth, "inAuth");
		TcTcsAuthCache.getInstance().ensureAuthsAreLoadedInTpm(
				new TcTcsAuth[] { inAuth });

		Object[] retVal = TcTcsKeyManager.GetPubKey(hContext, tcsKeyHandle,
				inAuth);

		// legal return codes: TCS_SUCCESS, TCS_E_KEY_CONTEXT_RELOAD,
		// TCS_E_INVALID_CONTEXTHANDLE,
		// TCS_E_FAIL

		return retVal;
	}

	/***************************************************************************
	 * This method allows creating a new key, which is wrapped by the already
	 * loaded wrapping key.
	 *
	 * @param hContext
	 * @param tcsHParentKey
	 * @param keyUsageAuth
	 * @param keyMigrationAuth
	 * @param keyInfo
	 * @param inAuth
	 * @throws TcTddlException,
	 *             TcTpmException
	 * @throws TcTcsException
	 */
	public static synchronized Object[] TcsipCreateWrapKey(long hContext,
			long tcsHParentKey, TcTpmEncauth keyUsageAuth,
			TcTpmEncauth keyMigrationAuth, TcITpmKeyNew keyInfo,
			TcTcsAuth inAuth) throws TcTddlException, TcTpmException,
			TcTcsException {
		TcTcsContextMgr.checkContextHandle(hContext);
		TcTcsContextMgr.getContextForHandle(hContext).checkKeyIsAssociated(
				tcsHParentKey);
		CheckPrecondition.notNull(keyUsageAuth, "keyUsageAuth");
		CheckPrecondition.notNull(keyMigrationAuth, "keyMigrationAuth");
		CheckPrecondition.notNull(keyInfo, "keyInfo");
		CheckPrecondition.notNull(inAuth, "inAuth");

		TcTcsAuthCache.getInstance().ensureAuthsAreLoadedInTpm(
				new TcTcsAuth[] { inAuth });

		long tpmParentKeyHandle = getKeyCache()
				.ensureKeyIsLoadedInTpm(tcsHParentKey);

		TcTddl dest = TcTddl.getInstance();
		Object[] retVal = TcTpmCmdStorage.TpmCreateWrapKey(dest,
				tpmParentKeyHandle, keyUsageAuth, keyMigrationAuth, keyInfo,
				inAuth);

		// legal return codes: TCS_SUCCESS, TCS_E_KM_LOADFAILED, TCS_E_FAIL

		return retVal;
	}

	// - - - - - Event Manager Methods - - - - -

	// not yet implemented

	// - - - - - Credential Manager Methods - - - - -

	/***************************************************************************
	 * This method performs the TPM operations necessary to create an identity
	 * key. It is identical to TcsipMakeIdentity except that it does not return
	 * the associated credentials. This can be used in conjunction with
	 * TcsipGetCredentials to duplicate the functionality of TcsipMakeIdentity.
	 *
	 * @param hContext
	 * @param identityAuth
	 * @param labelPrivCADigest
	 * @param idKeyParams
	 * @param inAuth1
	 * @param inAuth2
	 * @throws TcTddlException,
	 *             TcTpmException
	 * @throws TcTcsException
	 */
	public static synchronized Object[] TcsipMakeIdentity2(long hContext,
			TcTpmEncauth identityAuth, TcTpmDigest labelPrivCADigest,
			TcITpmKeyNew idKeyParams, TcTcsAuth inAuth1, TcTcsAuth inAuth2)
			throws TcTddlException, TcTpmException, TcTcsException {
		TcTcsContextMgr.checkContextHandle(hContext);
		CheckPrecondition.notNull(identityAuth, "identityAuth");
		CheckPrecondition.notNull(labelPrivCADigest, "labelPrivCADigest");
		CheckPrecondition.notNull(idKeyParams, "idKeyParams");
		CheckPrecondition.notNull(inAuth1, "inAuth1");
		CheckPrecondition.notNull(inAuth2, "inAuth2");

		TcTcsAuthCache.getInstance().ensureAuthsAreLoadedInTpm(
				new TcTcsAuth[] { inAuth1, inAuth2 });

		return TcTcsCredMgr.TcsipMakeIdentity2(hContext, identityAuth,
				labelPrivCADigest, idKeyParams, inAuth1, inAuth2);
	}

	/***************************************************************************
	 * This method allows creating a TPM identity and additionally returns the
	 * endorsement credential, the platform credential and the conformance
	 * credential. These three credentials are stored TCS vendor specific. For
	 * Infineon 1.1 TPMs, the EK credential is contained in the chip which is
	 * extracted by this method. For 1.2 TPMs, the EK credential is stored in
	 * the NV storage. If the TPM is an 1.2 TPM this method tries to read the EK
	 * credential form the NV storage.
	 *
	 * @param hContext
	 * @param identityAuth
	 * @param labelPrivCADigest
	 * @param idKeyParams
	 * @param inAuth1
	 * @param inAuth2
	 * @throws TcTddlException,
	 *             TcTpmException
	 * @throws TcTcsException
	 */
	public static synchronized Object[] TcsipMakeIdentity(long hContext,
			TcTpmEncauth identityAuth, TcTpmDigest labelPrivCADigest,
			TcITpmKeyNew idKeyParams, TcTcsAuth inAuth1, TcTcsAuth inAuth2)
			throws TcTddlException, TcTpmException, TcTcsException {
		TcTcsContextMgr.checkContextHandle(hContext);
		CheckPrecondition.notNull(identityAuth, "identityAuth");
		CheckPrecondition.notNull(labelPrivCADigest, "labelPrivCADigest");
		CheckPrecondition.notNull(idKeyParams, "idKeyParams");
		CheckPrecondition.notNull(inAuth1, "inAuth1");
		CheckPrecondition.notNull(inAuth2, "inAuth2");

		TcTcsAuthCache.getInstance().ensureAuthsAreLoadedInTpm(
				new TcTcsAuth[] { inAuth1, inAuth2 });

		return TcTcsCredMgr.TcsipMakeIdentity(hContext, identityAuth,
				labelPrivCADigest, idKeyParams, inAuth1, inAuth2);
	}

	/***************************************************************************
	 * This method returns the endorsement, platform, and conformance
	 * credentials for a platform. These are the same credentials returned by
	 * Tcsip_MakeIdentity; however this function only returns the credentials,
	 * it does not create an identity key. This function is intended to allow
	 * the TSP to retrieve the credentials when an identity key is created by a
	 * method other than TcsipMakeIdentity.<br>
	 *
	 * Implementation note: If possible (i.e. for Infineon 1.1 and 1.2 TPMs) the
	 * EK certificate is read directly from the TPM.
	 *
	 * @param hContext
	 * @throws TcTddlException
	 * @throws TcTpmException
	 * @throws TcTcsException
	 */
	public static synchronized Object[] TcsiGetCredentials(long hContext)
			throws TcTddlException, TcTpmException, TcTcsException {
		TcTcsContextMgr.checkContextHandle(hContext);

		return TcTcsCredMgr.TcsiGetCredentials(hContext);
	}

	// - - - - - Parameter Block Generator (PBG) Methods - - - -

	/***************************************************************************
	 * This method triggers a test of all TPM protected capabilities.
	 *
	 * @param hContext
	 * @throws TcTddlException,
	 *             TcTpmException
	 * @throws TcTcsException
	 */
	public static synchronized Object[] TcsipSelfTestFull(long hContext)
			throws TcTddlException, TcTpmException, TcTcsException {
		TcTcsContextMgr.checkContextHandle(hContext);

		TcTddl dest = TcTddl.getInstance();
		Object[] retVal = TcTpmCmdAdminTesting.TpmSelfTestFull(dest);

		return retVal;
	}

	/***************************************************************************
	 * This method informs the TPM that it may complete the self test of all TPM
	 * functions.
	 *
	 * @param hContext
	 * @throws TcTddlException,
	 *             TcTpmException
	 * @throws TcTcsException
	 */
	public static synchronized Object[] TcsipContinueSelfTest(long hContext)
			throws TcTddlException, TcTpmException, TcTcsException {
		TcTcsContextMgr.checkContextHandle(hContext);

		TcTddl dest = TcTddl.getInstance();
		Object[] retVal = TcTpmCmdAdminTesting.TpmContinueSelfTest(dest);

		return retVal;
	}

	/***************************************************************************
	 * This method provides manufacturer specific information regarding the
	 * results of the self-test. This command will work when the TPM is in
	 * self-test failure mode.
	 *
	 * @param hContext
	 * @throws TcTddlException,
	 *             TcTpmException
	 * @throws TcTcsException
	 */
	public static synchronized Object[] TcsipGetTestResult(long hContext)
			throws TcTddlException, TcTpmException, TcTcsException {
		TcTcsContextMgr.checkContextHandle(hContext);

		TcTddl dest = TcTddl.getInstance();
		Object[] retVal = TcTpmCmdAdminTesting.TpmGetTestResult(dest);

		return retVal;
	}

	/***************************************************************************
	 * This method determines if the TPM has a current owner. The TPM validates
	 * the assertion of physical access and then sets the value of
	 * TPM_PERSISTENT_FLAGS.ownership to the value in the state.
	 *
	 * @param hContext
	 * @param state
	 *
	 *
	 * @throws TcTddlException,
	 *             TcTpmException
	 * @throws TcTcsException
	 */
	public static synchronized Object[] TcsipSetOwnerInstall(long hContext,
			boolean state) throws TcTddlException, TcTpmException,
			TcTcsException {
		TcTcsContextMgr.checkContextHandle(hContext);

		TcTddl dest = TcTddl.getInstance();
		Object[] retVal = TcTpmCmdAdminOptIn.TpmSetOwnerInstall(dest, state);

		return retVal;
	}

	/***************************************************************************
	 * This method is used to change the status of the TPM_PERSISTENT_DISABLE
	 * flag.
	 *
	 * @param hContext
	 * @param disableState
	 * @param ownerAuth
	 * @throws TcTddlException,
	 *             TcTpmException
	 * @throws TcTcsException
	 */
	public static synchronized Object[] TcsipOwnerSetDisable(long hContext,
			boolean disableState, TcTcsAuth ownerAuth) throws TcTddlException,
			TcTpmException, TcTcsException {
		TcTcsContextMgr.checkContextHandle(hContext);
		CheckPrecondition.notNull(ownerAuth, "ownerAuth");
		TcTcsAuthCache.getInstance().ensureAuthsAreLoadedInTpm(
				new TcTcsAuth[] { ownerAuth });

		TcTddl dest = TcTddl.getInstance();
		Object[] retVal = TcTpmCmdAdminOptIn.TpmOwnerSetDisable(dest,
				disableState, ownerAuth);

		return retVal;
	}

	/***************************************************************************
	 * This method enables the TPM physical presence.
	 *
	 * @param hContext
	 *
	 * @throws TcTddlException,
	 *             TcTpmException
	 * @throws TcTcsException
	 */
	public static synchronized Object[] TcsipPhysicalEnable(long hContext)
			throws TcTddlException, TcTpmException, TcTcsException {
		TcTcsContextMgr.checkContextHandle(hContext);

		TcTddl dest = TcTddl.getInstance();
		Object[] retVal = TcTpmCmdAdminOptIn.TpmPhysicalEnable(dest);

		return retVal;
	}

	/***************************************************************************
	 * This method disables the TPM physical presence.
	 *
	 * @param hContext
	 * @throws TcTddlException,
	 *             TcTpmException
	 * @throws TcTcsException
	 */
	public static synchronized Object[] TcsipPhysicalDisable(long hContext)
			throws TcTddlException, TcTpmException, TcTcsException {
		TcTcsContextMgr.checkContextHandle(hContext);

		TcTddl dest = TcTddl.getInstance();
		Object[] retVal = TcTpmCmdAdminOptIn.TpmPhysicalDisable(dest);

		return retVal;
	}

	/***************************************************************************
	 * This method sets the TPM_PERSITSTENT_FLAGS.deactivated flag to the value
	 * in the state parameter.
	 *
	 * @param hContext
	 * @param state
	 * @throws TcTddlException,
	 *             TcTpmException
	 * @throws TcTcsException
	 */
	public static synchronized Object[] TcsipPhysicalSetDeactivated(
			long hContext, boolean state) throws TcTddlException,
			TcTpmException, TcTcsException {
		TcTcsContextMgr.checkContextHandle(hContext);

		TcTddl dest = TcTddl.getInstance();
		Object[] retVal = TcTpmCmdAdminOptIn.TpmPhysicalSetDeactivated(dest,
				state);

		return retVal;
	}

	/***************************************************************************
	 * This method sets the TPM_VOLATILE_FLAGS.deactivated to the value TRUE
	 * which temporarily deactivates the TPM.
	 *
	 * @param hContext
	 * @param operatorAuth
	 * @throws TcTddlException,
	 *             TcTpmException
	 * @throws TcTcsException
	 */
	public static synchronized Object[] TcsipSetTempDeactivated(long hContext,
			TcTcsAuth operatorAuth) throws TcTddlException, TcTpmException,
			TcTcsException {
		TcTcsContextMgr.checkContextHandle(hContext);
		CheckPrecondition.notNull(operatorAuth, "operatorAuth");
		TcTcsAuthCache.getInstance().ensureAuthsAreLoadedInTpm(
				new TcTcsAuth[] { operatorAuth });

		TcTddl dest = TcTddl.getInstance();
		Object[] retVal = TcTpmCmdAdminOptIn.TpmSetTempDeactivated(dest,
				operatorAuth);

		return retVal;
	}

	/***************************************************************************
	 * This method sets the TPM_VOLATILE_FLAGS.deactivated to the value TRUE
	 * which temporarily deactivates the TPM. This command requires physical
	 * presence.
	 *
	 * @param hContext
	 * @throws TcTddlException,
	 *             TcTpmException
	 * @throws TcTcsException
	 */
	public static synchronized Object[] TcsipSetTempDeactivatedNoAuth(
			long hContext) throws TcTddlException, TcTpmException,
			TcTcsException {
		TcTcsContextMgr.checkContextHandle(hContext);

		TcTddl dest = TcTddl.getInstance();
		Object[] retVal = TcTpmCmdAdminOptIn.tpmSetTempDeactivatedNoAuth(dest);

		return retVal;
	}

	/***************************************************************************
	 * Sets the operator authorization value for the platform.
	 *
	 * @param hContext
	 * @param operatorAuth
	 * @throws TcTddlException,
	 *             TcTpmException
	 * @throws TcTcsException
	 */
	public static synchronized Object[] TcsipSetOperatorAuth(long hContext,
			TcTpmSecret operatorAuth) throws TcTddlException, TcTpmException,
			TcTcsException {
		TcTcsContextMgr.checkContextHandle(hContext);
		CheckPrecondition.notNull(operatorAuth, "operatorAuth");

		TcTddl dest = TcTddl.getInstance();
		Object[] retVal = TcTpmCmdAdminOptIn.TpmSetOperatorAuth(dest,
				operatorAuth);

		return retVal;
	}

	/***************************************************************************
	 * This method inserts the Owner-authorization data and creates a new
	 * Storage Root Key (SRK). This function fails if there is already a TPM
	 * owner set. After inserting the authorization data, this function creates
	 * the SRK. To validate that the operation completes successfully, The TPM
	 * HMACs the response.
	 *
	 * @param hContext
	 * @param protocolID
	 * @param encOwnerAuth
	 * @param encSrkAuth
	 * @param srkParams
	 * @param inAuth
	 * @throws TcTddlException,
	 *             TcTpmException
	 * @throws TcTcsException
	 */
	public static synchronized Object[] TcsipTakeOwnership(long hContext,
			int protocolID, TcBlobData encOwnerAuth, TcBlobData encSrkAuth,
			TcITpmKeyNew srkParams, TcTcsAuth inAuth) throws TcTddlException,
			TcTpmException, TcTcsException {
		TcTcsContextMgr.checkContextHandle(hContext);
		CheckPrecondition.notNull(encOwnerAuth, "encOwnerAuth");
		CheckPrecondition.notNull(encSrkAuth, "encSrkAuth");
		CheckPrecondition.notNull(srkParams, "srkParams");
		CheckPrecondition.notNull(inAuth, "inAuth");
		TcTcsAuthCache.getInstance().ensureAuthsAreLoadedInTpm(
				new TcTcsAuth[] { inAuth });

		TcTddl dest = TcTddl.getInstance();
		Object[] retVal = TcTpmCmdAdminOwnership.TpmTakeOwnership(dest,
				protocolID, encOwnerAuth, encSrkAuth, srkParams, inAuth);

		if (getPsSystem() != null) {
			TcTssUuid srkUUID = new TcTssUuid().init(0L, 0, 0, (short) 0,
					(short) 0, new short[] { 0, 0, 0, 0, 0, 1 });

			TcITpmKey srk = (TcITpmKey) retVal[2];
			TcBlobData srkBlob = srk.getEncoded();

			try {
				// Try to remove possibly existing SRK from system persistent
				// storage
				getPsSystem().unregisterKey(srkUUID);

			} catch (TcTssException e) {
				if (e.getErrCode() != TcTcsErrors.TCS_E_KEY_NOT_REGISTERED) {
					throw new TcTcsException(e.getErrCode());
				}
			}

			try {
				getPsSystem().registerKey(null, srkUUID, srkBlob);
			} catch (TcTssException e) {
				throw new TcTcsException(e.getErrCode());
			}

		}

		return retVal;
	}

	/***************************************************************************
	 * This command clears the TPM under owner authorization.
	 *
	 * @param hContext
	 * @param ownerAuth
	 * @throws TcTddlException,
	 *             TcTpmException
	 * @throws TcTcsException
	 */
	public static synchronized Object[] TcsipOwnerClear(long hContext,
			TcTcsAuth ownerAuth) throws TcTddlException, TcTpmException,
			TcTcsException {
		TcTcsContextMgr.checkContextHandle(hContext);
		CheckPrecondition.notNull(ownerAuth, "ownerAuth");
		TcTcsAuthCache.getInstance().ensureAuthsAreLoadedInTpm(
				new TcTcsAuth[] { ownerAuth });

		TcTddl dest = TcTddl.getInstance();
		Object[] retVal = TcTpmCmdAdminOwnership.TpmOwnerClear(dest, ownerAuth);

		return retVal;
	}

	/***************************************************************************
	 * This method performs the clear operation under physical presence.
	 *
	 * @param hContext
	 * @throws TcTddlException,
	 *             TcTpmException
	 * @throws TcTcsException
	 */
	public static synchronized Object[] TcsipForceClear(long hContext)
			throws TcTddlException, TcTpmException, TcTcsException {
		TcTcsContextMgr.checkContextHandle(hContext);

		TcTddl dest = TcTddl.getInstance();
		Object[] retVal = TcTpmCmdAdminOwnership.TpmForceClear(dest);

		return retVal;
	}

	/***************************************************************************
	 * This command disables the ability to execute the OwnerClear command
	 * permanently.
	 *
	 * @param hContext
	 * @param ownerAuth
	 * @throws TcTddlException,
	 *             TcTpmException
	 * @throws TcTcsException
	 */
	public static synchronized Object[] TcsipDisableOwnerClear(long hContext,
			TcTcsAuth ownerAuth) throws TcTddlException, TcTpmException,
			TcTcsException {
		TcTcsContextMgr.checkContextHandle(hContext);
		CheckPrecondition.notNull(ownerAuth, "ownerAuth");
		TcTcsAuthCache.getInstance().ensureAuthsAreLoadedInTpm(
				new TcTcsAuth[] { ownerAuth });

		TcTddl dest = TcTddl.getInstance();
		Object[] retVal = TcTpmCmdAdminOwnership.TpmDisableOwnerClear(dest,
				ownerAuth);

		return retVal;
	}

	/***************************************************************************
	 * This command disables the execution of the ForceClear command until next
	 * startup cycle.
	 *
	 * @param hContext
	 * @throws TcTddlException,
	 *             TcTpmException
	 * @throws TcTcsException
	 */
	public static synchronized Object[] TcsipDisableForceClear(long hContext)
			throws TcTddlException, TcTpmException, TcTcsException {
		TcTcsContextMgr.checkContextHandle(hContext);

		TcTddl dest = TcTddl.getInstance();
		Object[] retVal = TcTpmCmdAdminOwnership.TpmDisableForceClear(dest);

		return retVal;
	}

	/***************************************************************************
	 * This method sets the physical presence flags.
	 *
	 * @param hContext
	 * @param physicalPresence
	 * @throws TcTddlException,
	 *             TcTpmException
	 * @throws TcTcsException
	 */
	public static synchronized Object[] TcsipPhysicalPresence(long hContext,
			int physicalPresence) throws TcTddlException, TcTpmException,
			TcTcsException {
		TcTcsContextMgr.checkContextHandle(hContext);

		TcTddl dest = TcTddl.getInstance();
		Object[] retVal = TcTpmCmdAdminOwnership.TscPhysicalPresence(dest,
				physicalPresence);

		return retVal;
	}

	/***************************************************************************
	 * This method allows the TPM to report back the requestor what type of TPM
	 * it is dealing with.
	 *
	 * @param hContext
	 * @param capArea
	 * @param subCap
	 * @throws TcTddlException,
	 *             TcTpmException
	 * @throws TcTcsException
	 */
	public static synchronized Object[] TcsipGetCapability(long hContext,
			long capArea, TcBlobData subCap) throws TcTddlException,
			TcTpmException, TcTcsException {
		TcTcsContextMgr.checkContextHandle(hContext);
		// subCap can be null

		TcTddl dest = TcTddl.getInstance();
		Object[] retVal = TcTpmCmdCapability.TpmGetCapability(dest, capArea,
				subCap);

		return retVal;
	}

	/***************************************************************************
	 * This method allows the caller to set values in the TPM. Information about
	 * the capArea and subCap is transmitted to the TPM without any
	 * interpretation by the TCS. The TPM will return an appropriate error on
	 * wrong values.
	 *
	 * @param hContext
	 * @param capArea
	 * @param subCap
	 * @param value
	 * @param ownerAuth
	 * @throws TcTddlException,
	 *             TcTpmException
	 * @throws TcTcsException
	 */
	public static synchronized Object[] TcsipSetCapability(long hContext,
			long capArea, TcBlobData subCap, TcBlobData value,
			TcTcsAuth ownerAuth) throws TcTddlException, TcTpmException,
			TcTcsException {
		TcTcsContextMgr.checkContextHandle(hContext);
		CheckPrecondition.notNull(subCap, "subCap");
		CheckPrecondition.notNull(value, "value");
		CheckPrecondition.notNull(ownerAuth, "ownerAuth");
		TcTcsAuthCache.getInstance().ensureAuthsAreLoadedInTpm(
				new TcTcsAuth[] { ownerAuth });
		// TODO: owner auth is optional

		TcTddl dest = TcTddl.getInstance();
		Object[] retVal = TcTpmCmdCapability.TpmSetCapability(dest, capArea,
				subCap, value, ownerAuth);

		return retVal;
	}

	/***************************************************************************
	 * This method enables the TPM owner to retrieve information belonging to
	 * the TPM owner.
	 *
	 * @param hContext
	 * @param ownerAuth
	 * @throws TcTddlException,
	 *             TcTpmException
	 * @throws TcTcsException
	 */
	public static synchronized Object[] TcsipGetCapabilityOwner(long hContext,
			TcTcsAuth ownerAuth) throws TcTddlException, TcTpmException,
			TcTcsException {
		TcTcsContextMgr.checkContextHandle(hContext);
		CheckPrecondition.notNull(ownerAuth, "ownerAuth");
		TcTcsAuthCache.getInstance().ensureAuthsAreLoadedInTpm(
				new TcTcsAuth[] { ownerAuth });

		TcTddl dest = TcTddl.getInstance();
		Object[] retVal = TcTpmCmdCapability.TpmGetCapabilityOwner(dest,
				ownerAuth);

		return retVal;
	}

	/***************************************************************************
	 * This method gets the digest of audited ordinals.
	 *
	 * @param hContext
	 * @param startOrdinal
	 * @throws TcTddlException,
	 *             TcTpmException
	 * @throws TcTcsException
	 */
	public static synchronized Object[] TcsipGetAuditDigest(long hContext,
			long startOrdinal) throws TcTddlException, TcTpmException,
			TcTcsException {
		TcTcsContextMgr.checkContextHandle(hContext);

		TcTddl dest = TcTddl.getInstance();
		Object[] retVal = TcTpmCmdAudit.TpmGetAuditDigest(dest, startOrdinal);

		return retVal;
	}

	/***************************************************************************
	 * This method gets the signed digest of audited ordinals.
	 *
	 * @param hContext
	 * @param tcsKeyHandle
	 * @param closeAudit
	 * @param antiReplay
	 * @param inAuth
	 * @throws TcTddlException,
	 *             TcTpmException
	 * @throws TcTcsException
	 */
	public static synchronized Object[] TcsipGetAuditDigestSigned(
			long hContext, long tcsKeyHandle, boolean closeAudit,
			TcTpmNonce antiReplay, TcTcsAuth inAuth) throws TcTddlException,
			TcTpmException, TcTcsException {
		TcTcsContextMgr.checkContextHandle(hContext);
		TcTcsContextMgr.getContextForHandle(hContext).checkKeyIsAssociated(
				tcsKeyHandle);
		CheckPrecondition.notNull(antiReplay, "antiReplay");
		CheckPrecondition.notNull(inAuth, "inAuth");
		TcTcsAuthCache.getInstance().ensureAuthsAreLoadedInTpm(
				new TcTcsAuth[] { inAuth });

		long tpmKeyHandle = getKeyCache().ensureKeyIsLoadedInTpm(tcsKeyHandle);

		TcTddl dest = TcTddl.getInstance();
		Object[] retVal = TcTpmCmdAudit.TpmGetAuditDigestSigned(dest,
				tpmKeyHandle, closeAudit, antiReplay, inAuth);

		return retVal;
	}

	/***************************************************************************
	 * This command sets the audit flag for a given ordinal. This command
	 * requires owner authorization.
	 *
	 * @param hContext
	 * @param ordinalToAudit
	 * @param auditState
	 * @param ownerAuth
	 * @throws TcTddlException,
	 *             TcTpmException
	 * @throws TcTcsException
	 */
	public static synchronized Object[] TcsipSetOrdinalAuditStatus(
			long hContext, TcTcsAuth ownerAuth, long ordinalToAudit,
			boolean auditState) throws TcTddlException, TcTpmException,
			TcTcsException {
		// Note:
		// TPM parameter order: ... auditState, ownerAuth
		// TCS parameter order: hContext, ownerAuth, ...

		TcTcsContextMgr.checkContextHandle(hContext);
		CheckPrecondition.notNull(ownerAuth, "ownerAuth");
		TcTcsAuthCache.getInstance().ensureAuthsAreLoadedInTpm(
				new TcTcsAuth[] { ownerAuth });

		TcTddl dest = TcTddl.getInstance();
		Object[] retVal = TcTpmCmdAudit.TpmSetOrdinalAuditStatus(dest,
				ordinalToAudit, auditState, ownerAuth);

		return retVal;
	}

	/***************************************************************************
	 * This command provides a mechanism that allows a vendor to update the
	 * protected capabilities once a TPM is in the field. Note that this command
	 * is vendor specific!
	 *
	 * @param hContext
	 * @param inData
	 * @param ownerAuth
	 * @throws TcTddlException
	 * @throws TcTpmException
	 * @throws TcTcsException
	 */
	public static synchronized Object[] TcsipFieldUpgrade(long hContext,
			TcBlobData inData, TcTcsAuth ownerAuth) throws TcTddlException,
			TcTpmException, TcTcsException {
		TcTcsContextMgr.checkContextHandle(hContext);
		CheckPrecondition.notNull(inData, "inData");
		CheckPrecondition.notNull(ownerAuth, "ownerAuth");
		TcTcsAuthCache.getInstance().ensureAuthsAreLoadedInTpm(
				new TcTcsAuth[] { ownerAuth });

		TcTddl dest = TcTddl.getInstance();
		Object[] retVal = TcTpmCmdManagement.TpmFieldUpgrade(dest, inData,
				ownerAuth);

		return retVal;
	}

	/***************************************************************************
	 * Redirected keys enable the output of a TPM to be directed to non-TCG
	 * security functions in the platform, without exposing that output to
	 * non-security functions. It sometimes is desirable to direct the TPM's
	 * output to specific platform functions without exposing that output to
	 * other platform functions. To enable this, the key in a leaf node of the
	 * TCG protected storage can be tagged as a "redirected" key. Any plaintext
	 * output data secured by a redirected key is passed by the TPM directly to
	 * specific platform functions and is not interpreted by the TPM. Since
	 * redirection can only affect leaf keys, redirection applies to: Unbind,
	 * Unseal, Quote and Sign.
	 *
	 * @param hContext
	 * @param tcsKeyHandle
	 * @param redirCmd
	 * @param inputData
	 * @param inAuth
	 * @throws TcTddlException,
	 *             TcTpmException
	 * @throws TcTcsException
	 */
	public static synchronized Object[] TcsipSetRedirection(long hContext,
			long tcsKeyHandle, long redirCmd, TcBlobData inputData,
			TcTcsAuth inAuth) throws TcTddlException, TcTpmException,
			TcTcsException {
		TcTcsContextMgr.checkContextHandle(hContext);
		TcTcsContextMgr.getContextForHandle(hContext).checkKeyIsAssociated(
				tcsKeyHandle);
		CheckPrecondition.notNull(inputData, "inputData");
		CheckPrecondition.notNull(inAuth, "inAuth");
		TcTcsAuthCache.getInstance().ensureAuthsAreLoadedInTpm(
				new TcTcsAuth[] { inAuth });

		long tpmKeyHandle = getKeyCache().ensureKeyIsLoadedInTpm(tcsKeyHandle);

		TcTddl dest = TcTddl.getInstance();
		Object[] retVal = TcTpmCmdManagement.TpmSetRedirection(dest,
				tpmKeyHandle, redirCmd, inputData, inAuth);

		return retVal;
	}

	/***************************************************************************
	 * Resets the lock that get set in a TPM after multiple false authorization
	 * attempts. This is used to prevent hammering attacks. This command
	 * requires owner authorization.
	 *
	 * @param hContext
	 * @param ownerAuth
	 * @throws TcTddlException,
	 *             TcTpmException
	 * @throws TcTcsException
	 */
	public static synchronized Object[] TcsipResetLockValue(long hContext,
			TcTcsAuth ownerAuth) throws TcTddlException, TcTpmException,
			TcTcsException {
		TcTcsContextMgr.checkContextHandle(hContext);
		CheckPrecondition.notNull(ownerAuth, "ownerAuth");
		TcTcsAuthCache.getInstance().ensureAuthsAreLoadedInTpm(
				new TcTcsAuth[] { ownerAuth });

		TcTddl dest = TcTddl.getInstance();

		Object[] retVal = TcTpmCmdManagement.TpmResetLockValue(dest, ownerAuth);

		return retVal;
	}

	/***************************************************************************
	 * This method allows software to explicitly state the future trusted
	 * configuration that the platform must be in for the secret to be revealed.
	 * The seal operation also implicitly includes the relevant platform
	 * configuration when the seal operation was performed.
	 *
	 * @param hContext
	 * @param tcsKeyHandle
	 * @param encAuth
	 * @param pcrInfo
	 * @param inData
	 * @param inAuth
	 * @throws TcTddlException,
	 *             TcTpmException
	 * @throws TcTcsException
	 */
	public static synchronized Object[] TcsipSeal(long hContext,
			long tcsKeyHandle, TcTpmEncauth encAuth, TcITpmPcrInfo pcrInfo,
			TcBlobData inData, TcTcsAuth inAuth) throws TcTddlException,
			TcTpmException, TcTcsException {
		TcTcsContextMgr.checkContextHandle(hContext);
		TcTcsContextMgr.getContextForHandle(hContext).checkKeyIsAssociated(
				tcsKeyHandle);
		CheckPrecondition.notNull(encAuth, "encAuth");
		// pcrInfo can be null
		CheckPrecondition.notNull(inData, "inData");
		CheckPrecondition.notNull(inAuth, "inAuth");
		TcTcsAuthCache.getInstance().ensureAuthsAreLoadedInTpm(
				new TcTcsAuth[] { inAuth });

		long tpmKeyHandle = getKeyCache().ensureKeyIsLoadedInTpm(tcsKeyHandle);

		TcTddl dest = TcTddl.getInstance();
		Object[] retVal = TcTpmCmdStorage.TpmSeal(dest, tpmKeyHandle, encAuth,
				pcrInfo, inData, inAuth);

		return retVal;
	}

	/***************************************************************************
	 * This method will reveal sealed data only if it was encrypted on this
	 * platform and the current configuration (defined by the named PCRs) is the
	 * one named as qualified to decrypt it. It decrypts the structure
	 * internally, checks the integrity of the resulting data and checks that
	 * the PCR named has the value named during TcsipSeal. Additionally, the
	 * caller must supply appropriate authorization data for the blob and the
	 * key that was used to seal that data.
	 *
	 * @param hContext
	 * @param tcsKeyHandle
	 * @param inData
	 * @param keyAuth
	 * @param dataAuth
	 * @throws TcTddlException,
	 *             TcTpmException
	 * @throws TcTcsException
	 */
	public static synchronized Object[] TcsipUnseal(long hContext,
			long tcsKeyHandle, TcITpmStoredData inData, TcTcsAuth keyAuth,
			TcTcsAuth dataAuth) throws TcTddlException, TcTpmException,
			TcTcsException {
		TcTcsContextMgr.checkContextHandle(hContext);
		TcTcsContextMgr.getContextForHandle(hContext).checkKeyIsAssociated(
				tcsKeyHandle);
		CheckPrecondition.notNull(inData, "inData");
		CheckPrecondition.notNull(keyAuth, "keyAuth");
		CheckPrecondition.notNull(dataAuth, "dataAuth");
		TcTcsAuthCache.getInstance().ensureAuthsAreLoadedInTpm(
				new TcTcsAuth[] { keyAuth, dataAuth });

		long tpmParentKeyHandle = getKeyCache()
				.ensureKeyIsLoadedInTpm(tcsKeyHandle);

		TcTddl dest = TcTddl.getInstance();
		Object[] retVal = TcTpmCmdStorage.TpmUnseal(dest, tpmParentKeyHandle,
				inData, keyAuth, dataAuth);

		return retVal;
	}

	/***************************************************************************
	 * This method takes the data blob that is the result of a bind command and
	 * decrypts it for export to the user. The caller must authorize the use of
	 * the key that will decrypt the incoming blob.
	 *
	 * @param hContext
	 * @param tcsKeyHandle
	 * @param inData
	 * @param inAuth
	 * @throws TcTddlException,
	 *             TcTpmException
	 * @throws TcTcsException
	 */
	public static synchronized Object[] TcsipUnBind(long hContext,
			long tcsKeyHandle, TcBlobData inData, TcTcsAuth inAuth)
			throws TcTddlException, TcTpmException, TcTcsException {
		TcTcsContextMgr.checkContextHandle(hContext);
		TcTcsContextMgr.getContextForHandle(hContext).checkKeyIsAssociated(
				tcsKeyHandle);
		CheckPrecondition.notNull(inData, "inData");
		CheckPrecondition.notNull(inAuth, "inAuth");
		TcTcsAuthCache.getInstance().ensureAuthsAreLoadedInTpm(
				new TcTcsAuth[] { inAuth });

		long tpmKeyHandle = getKeyCache().ensureKeyIsLoadedInTpm(tcsKeyHandle);

		TcTddl dest = TcTddl.getInstance();
		Object[] retVal = TcTpmCmdStorage.TpmUnBind(dest, tpmKeyHandle, inData,
				inAuth);

		return retVal;
	}

	/***************************************************************************
	 * This method allows software to explicitly state the future trusted
	 * configuration that the platform must be in for the secret to be revealed.
	 * It also includes the relevant platform configuration when the SealX
	 * command was performed.
	 *
	 * @param hContext
	 * @param tcsKeyHandle
	 * @param encAuth
	 * @param pcrInfo
	 * @param inData
	 * @param inAuth
	 * @throws TcTddlException,
	 *             TcTpmException
	 * @throws TcTcsException
	 */
	public static synchronized Object[] TcsipSealx(long hContext,
			long tcsKeyHandle, TcTpmEncauth encAuth, TcTpmPcrInfoLong pcrInfo,
			TcBlobData inData, TcTcsAuth inAuth) throws TcTddlException,
			TcTpmException, TcTcsException {
		TcTcsContextMgr.checkContextHandle(hContext);
		TcTcsContextMgr.getContextForHandle(hContext).checkKeyIsAssociated(
				tcsKeyHandle);
		CheckPrecondition.notNull(encAuth, "encAuth");
		CheckPrecondition.notNull(pcrInfo, "pcrInfo");
		CheckPrecondition.notNull(inData, "inData");
		CheckPrecondition.notNull(inAuth, "inAuth");
		TcTcsAuthCache.getInstance().ensureAuthsAreLoadedInTpm(
				new TcTcsAuth[] { inAuth });

		long tpmKeyHandle = getKeyCache().ensureKeyIsLoadedInTpm(tcsKeyHandle);

		TcTddl dest = TcTddl.getInstance();
		Object[] retVal = TcTpmCmdStorage.TpmSealx(dest, tpmKeyHandle, encAuth,
				pcrInfo, inData, inAuth);

		return retVal;
	}

	/***************************************************************************
	 * This method implements the first step in the process of moving a
	 * migratable key to a new parent key or platform. Execution of this command
	 * requires knowledge of the migrationAuth field of the key to be migrated.
	 *
	 * @param hContext
	 * @param tcsParentKeyHandle
	 * @param migrationType
	 * @param migrationKeyAuth
	 * @param encData
	 * @param parentAuth
	 * @param entityAuth
	 * @throws TcTddlException,
	 *             TcTpmException
	 * @throws TcTcsException
	 */
	public static synchronized Object[] TcsipCreateMigrationBlob(long hContext,
			long tcsParentKeyHandle, int migrationType,
			TcTpmMigrationkeyAuth migrationKeyAuth, TcBlobData encData,
			TcTcsAuth parentAuth, TcTcsAuth entityAuth) throws TcTddlException,
			TcTpmException, TcTcsException {
		TcTcsContextMgr.checkContextHandle(hContext);
		TcTcsContextMgr.getContextForHandle(hContext).checkKeyIsAssociated(
				tcsParentKeyHandle);
		CheckPrecondition.notNull(migrationKeyAuth, "migrationKeyAuth");
		CheckPrecondition.notNull(encData, "encData");
		CheckPrecondition.notNull(parentAuth, "parentAuth");
		CheckPrecondition.notNull(entityAuth, "entityAuth");
		TcTcsAuthCache.getInstance().ensureAuthsAreLoadedInTpm(
				new TcTcsAuth[] { parentAuth, entityAuth });

		long tpmParentKeyHandle = getKeyCache()
				.ensureKeyIsLoadedInTpm(tcsParentKeyHandle);

		TcTddl dest = TcTddl.getInstance();

		Object[] retVal = TcTpmCmdMigration.TpmCreateMigrationBlob(dest,
				tpmParentKeyHandle, migrationType, migrationKeyAuth, encData,
				parentAuth, entityAuth);

		return retVal;
	}

	/***************************************************************************
	 * This method takes a migration blob and creates a normal wrapped blob. The
	 * migrated blob must be loaded into the TPM using the normal LoadKey
	 * function.
	 *
	 * @param hContext
	 * @param tcsParentKeyHandle
	 * @param inData
	 * @param random
	 * @param parentAuth
	 * @throws TcTddlException,
	 *             TcTpmException
	 * @throws TcTcsException
	 */
	public static synchronized Object[] TcsipConvertMigrationBlob(
			long hContext, long tcsParentKeyHandle, TcBlobData inData,
			TcBlobData random, TcTcsAuth parentAuth) throws TcTddlException,
			TcTpmException, TcTcsException {
		TcTcsContextMgr.checkContextHandle(hContext);
		TcTcsContextMgr.getContextForHandle(hContext).checkKeyIsAssociated(
				tcsParentKeyHandle);
		CheckPrecondition.notNull(inData, "inData");
		CheckPrecondition.notNull(random, "random");
		CheckPrecondition.notNull(parentAuth, "parentAuth");
		TcTcsAuthCache.getInstance().ensureAuthsAreLoadedInTpm(
				new TcTcsAuth[] { parentAuth });

		long tpmParentKeyHandle = getKeyCache()
				.ensureKeyIsLoadedInTpm(tcsParentKeyHandle);

		TcTddl dest = TcTddl.getInstance();

		Object[] retVal = TcTpmCmdMigration.TpmConvertMigrationBlob(dest,
				tpmParentKeyHandle, inData, random, parentAuth);

		return retVal;
	}

	/***************************************************************************
	 * This method creates an authorization blob to allow the TPM owner to
	 * specify which migration facility they will use and allow users to migrate
	 * information without further involvement with the TPM owner.
	 *
	 * @param hContext
	 * @param migrationScheme
	 * @param migrationKey
	 * @param ownerAuth
	 * @throws TcTddlException,
	 *             TcTpmException
	 * @throws TcTcsException
	 */
	public static synchronized Object[] TcsipAuthorizeMigrationKey(
			long hContext, int migrationScheme, TcTpmPubkey migrationKey,
			TcTcsAuth ownerAuth) throws TcTddlException, TcTpmException,
			TcTcsException {
		TcTcsContextMgr.checkContextHandle(hContext);
		CheckPrecondition.notNull(migrationKey, "migrationKey");
		CheckPrecondition.notNull(ownerAuth, "ownerAuth");
		TcTcsAuthCache.getInstance().ensureAuthsAreLoadedInTpm(
				new TcTcsAuth[] { ownerAuth });

		TcTddl dest = TcTddl.getInstance();
		Object[] retVal = TcTpmCmdMigration.TpmAuthorizeMigrationKey(dest,
				migrationScheme, migrationKey, ownerAuth);

		return retVal;
	}

	/***************************************************************************
	 * This method performs the function of a migration authority. THis command
	 * is used to permit a TPM enabled system to be a migration authority. To
	 * prevent execution of this command using any other key as a parent key,
	 * this TPM operation works only if the keyUsage for the macKey is
	 * TPM_KEY_MIGRATABLE.
	 *
	 * @param hContext
	 * @param tcsMaKeyHandle
	 * @param pubKey
	 * @param inData
	 * @param ownerAuth
	 * @throws TcTddlException,
	 *             TcTpmException
	 * @throws TcTcsException
	 */
	public static synchronized Object[] TcsipMigrateKey(long hContext,
			long tcsMaKeyHandle, TcTpmPubkey pubKey, TcBlobData inData,
			TcTcsAuth ownerAuth) throws TcTddlException, TcTpmException,
			TcTcsException {
		TcTcsContextMgr.checkContextHandle(hContext);
		TcTcsContextMgr.getContextForHandle(hContext).checkKeyIsAssociated(
				tcsMaKeyHandle);
		CheckPrecondition.notNull(pubKey, "pubKey");
		CheckPrecondition.notNull(inData, "inData");
		CheckPrecondition.notNull(ownerAuth, "ownerAuth");
		TcTcsAuthCache.getInstance().ensureAuthsAreLoadedInTpm(
				new TcTcsAuth[] { ownerAuth });

		long tpmMaKeyHandle = getKeyCache().ensureKeyIsLoadedInTpm(tcsMaKeyHandle);

		TcTddl dest = TcTddl.getInstance();
		Object[] retVal = TcTpmCmdMigration.TpmMigrateKey(dest, tpmMaKeyHandle,
				pubKey, inData, ownerAuth);

		return retVal;
	}

	/***************************************************************************
	 * This command is used by the owner to order the usage of a CMK with
	 * delegated authorization.
	 *
	 * @param hContext
	 * @param restriction
	 * @param ownerAuth
	 * @throws TcTddlException,
	 *             TcTpmException
	 * @throws TcTcsException
	 */
	public static synchronized Object[] TcsipCmkSetRestrictions(long hContext,
			long restriction, TcTcsAuth ownerAuth) throws TcTddlException,
			TcTpmException, TcTcsException {
		TcTcsContextMgr.checkContextHandle(hContext);
		CheckPrecondition.notNull(ownerAuth, "ownerAuth");
		TcTcsAuthCache.getInstance().ensureAuthsAreLoadedInTpm(
				new TcTcsAuth[] { ownerAuth });

		TcTddl dest = TcTddl.getInstance();
		Object[] retVal = TcTpmCmdMigration.TpmCmkSetRestrictions(dest,
				restriction, ownerAuth);

		return retVal;
	}

	/***************************************************************************
	 * This command is used to create an authorization ticket, to allow the TPM
	 * owner to specify/select one or more migration authorities they approve
	 * and allow user to generate CMKs without further involvement of the owner.
	 *
	 * @param hContext
	 * @param migrationAuthorityDigest
	 * @param ownerAuth
	 * @throws TcTddlException,
	 *             TcTpmException
	 * @throws TcTcsException
	 */
	public static synchronized Object[] TcsipCmkApproveMA(long hContext,
			TcTpmDigest migrationAuthorityDigest, TcTcsAuth ownerAuth)
			throws TcTddlException, TcTpmException, TcTcsException {
		TcTcsContextMgr.checkContextHandle(hContext);
		CheckPrecondition.notNull(migrationAuthorityDigest,
				"migrationAuthorityDigest");
		CheckPrecondition.notNull(ownerAuth, "ownerAuth");
		TcTcsAuthCache.getInstance().ensureAuthsAreLoadedInTpm(
				new TcTcsAuth[] { ownerAuth });

		TcTddl dest = TcTddl.getInstance();
		Object[] retVal = TcTpmCmdMigration.TpmCmkApproveMA(dest,
				migrationAuthorityDigest, ownerAuth);

		return retVal;
	}

	/***************************************************************************
	 * This command both generates and creates a secure storage bundle for
	 * asymmetric keys whose migration is controlled/restricted by a migration
	 * authority. Only this command can be used to create these kind of keys.
	 *
	 * @param hContext
	 * @param tcsParentKeyHandle
	 * @param keyDataUsageAuth
	 * @param keyInfo
	 * @param migrationAuthorityApproval
	 * @param migrationAuthorityDigest
	 * @param inAuth
	 * @throws TcTddlException,
	 *             TcTpmException
	 * @throws TcTcsException
	 */
	public static synchronized Object[] TcsipCmkCreateKey(long hContext,
			long tcsParentKeyHandle, TcTpmEncauth keyDataUsageAuth,
			TcTpmDigest migrationAuthorityApproval,
			TcTpmDigest migrationAuthorityDigest, TcTpmKey12 keyInfo,
			TcTcsAuth inAuth) throws TcTddlException, TcTpmException,
			TcTcsException {
		// Note:
		// TPM parameter order: ... keyDataUsageAuth, keyInfo, ...
		// TCS parameter order: ... migrationAuthorityDigest, keyInfo, ...

		TcTcsContextMgr.checkContextHandle(hContext);
		TcTcsContextMgr.getContextForHandle(hContext).checkKeyIsAssociated(
				tcsParentKeyHandle);
		CheckPrecondition.notNull(keyDataUsageAuth, "keyDataUsageAuth");
		CheckPrecondition.notNull(keyInfo, "keyInfo");
		CheckPrecondition.notNull(migrationAuthorityApproval,
				"migrationAuthorityApproval");
		CheckPrecondition.notNull(migrationAuthorityDigest,
				"migrationAuthorityDigest");
		CheckPrecondition.notNull(inAuth, "inAuth");
		TcTcsAuthCache.getInstance().ensureAuthsAreLoadedInTpm(
				new TcTcsAuth[] { inAuth });

		long tpmParentKeyHandle = getKeyCache()
				.ensureKeyIsLoadedInTpm(tcsParentKeyHandle);

		TcTddl dest = TcTddl.getInstance();
		Object[] retVal = TcTpmCmdMigration.TpmCmkCreateKey(dest,
				tpmParentKeyHandle, keyDataUsageAuth, keyInfo,
				migrationAuthorityApproval, migrationAuthorityDigest, inAuth);

		return retVal;
	}

	/***************************************************************************
	 * This owner controlled command uses a public key to verify the signature
	 * over a digest.
	 *
	 * @param hContext
	 * @param pubVerificationKey
	 * @param signedData
	 * @param signatureValue
	 * @param ownerAuth
	 * @throws TcTddlException,
	 *             TcTpmException
	 * @throws TcTcsException
	 */
	public static synchronized Object[] TcsipCmkCreateTicket(long hContext,
			TcTpmPubkey pubVerificationKey, TcTpmDigest signedData,
			TcBlobData signatureValue, TcTcsAuth ownerAuth)
			throws TcTddlException, TcTpmException, TcTcsException {
		TcTcsContextMgr.checkContextHandle(hContext);
		CheckPrecondition.notNull(pubVerificationKey, "pubVerificationKey");
		CheckPrecondition.notNull(signedData, "signedData");
		CheckPrecondition.notNull(signatureValue, "signatureValue");
		CheckPrecondition.notNull(ownerAuth, "ownerAuth");
		TcTcsAuthCache.getInstance().ensureAuthsAreLoadedInTpm(
				new TcTcsAuth[] { ownerAuth });

		TcTddl dest = TcTddl.getInstance();
		Object[] retVal = TcTpmCmdMigration.TpmCmkCreateTicket(dest,
				pubVerificationKey, signedData, signatureValue, ownerAuth);

		return retVal;
	}

	/***************************************************************************
	 * This command is similar to TcspiCreateMigrationBlob, except that it uses
	 * migration authority data whose migration data are independent from
	 * tpmProof. It is possible for the parameter restrictTicket to be null.
	 *
	 * @param hContext
	 * @param tcsParentKeyHandle
	 * @param migrationType
	 * @param migrationKeyAuth
	 * @param pubSourceKeyDigest
	 * @param msaList
	 * @param restrictTicket
	 * @param sigTicket
	 * @param encData
	 * @param parentAuth
	 * @throws TcTddlException,
	 *             TcTpmException
	 * @throws TcTcsException
	 */
	public static synchronized Object[] TcsipCmkCreateBlob(long hContext,
			long tcsParentKeyHandle, int migrationType,
			TcTpmMigrationkeyAuth migrationKeyAuth,
			TcTpmDigest pubSourceKeyDigest, TcTpmMsaComposite msaList,
			TcBlobData restrictTicket, TcBlobData sigTicket,
			TcBlobData encData, TcTcsAuth parentAuth) throws TcTddlException,
			TcTpmException, TcTcsException {
		TcTcsContextMgr.checkContextHandle(hContext);
		TcTcsContextMgr.getContextForHandle(hContext).checkKeyIsAssociated(
				tcsParentKeyHandle);
		CheckPrecondition.notNull(migrationKeyAuth, "migrationKeyAuth");
		CheckPrecondition.notNull(pubSourceKeyDigest, "pubSourceKeyDigest");
		CheckPrecondition.notNull(msaList, "msaList");
		// restrictTicket can be null
		// sigTicket can be null
		CheckPrecondition.notNull(encData, "encData");
		CheckPrecondition.notNull(parentAuth, "parentAuth");
		TcTcsAuthCache.getInstance().ensureAuthsAreLoadedInTpm(
				new TcTcsAuth[] { parentAuth });

		long tpmParentKeyHandle = getKeyCache()
				.ensureKeyIsLoadedInTpm(tcsParentKeyHandle);

		TcTddl dest = TcTddl.getInstance();
		Object[] retVal = TcTpmCmdMigration.TpmCmkCreateBlob(dest,
				tpmParentKeyHandle, migrationType, migrationKeyAuth,
				pubSourceKeyDigest, msaList, restrictTicket, sigTicket,
				encData, parentAuth);

		return retVal;
	}

	/***************************************************************************
	 * This command is used as the final step to finish migrating a key to a new
	 * TPM.
	 *
	 * Note that the related TPM command migrates private keys only. The
	 * migration of the associated public keys us not specified by the TPM. The
	 * application (i.e. TSP) must generate a TPM_KEYxx structure before the
	 * migrated key can be used be the target TPM in a LoadKeyX command.
	 *
	 * @param hContext
	 * @param tcsParentKeyHandle
	 * @param restrictTicket
	 * @param sigTicket
	 * @param migratedKey
	 * @param msaList
	 * @param random
	 * @param parentAuth
	 * @throws TcTddlException,
	 *             TcTpmException
	 * @throws TcTcsException
	 */
	public static synchronized Object[] TcsipCmkConvertMigration(long hContext,
			long tcsParentKeyHandle, TcTpmCmkAuth restrictTicket,
			TcTpmDigest sigTicket, TcTpmKey12 migratedKey,
			TcTpmMsaComposite msaList, TcBlobData random, TcTcsAuth parentAuth)
			throws TcTddlException, TcTpmException, TcTcsException {
		TcTcsContextMgr.checkContextHandle(hContext);
		TcTcsContextMgr.getContextForHandle(hContext).checkKeyIsAssociated(
				tcsParentKeyHandle);
		CheckPrecondition.notNull(restrictTicket, "restrictTicket");
		CheckPrecondition.notNull(sigTicket, "sigTicket");
		CheckPrecondition.notNull(migratedKey, "migratedKey");
		CheckPrecondition.notNull(msaList, "msaList");
		CheckPrecondition.notNull(random, "random");
		CheckPrecondition.notNull(parentAuth, "parentAuth");
		TcTcsAuthCache.getInstance().ensureAuthsAreLoadedInTpm(
				new TcTcsAuth[] { parentAuth });

		long tpmParentKeyHandle = getKeyCache()
				.ensureKeyIsLoadedInTpm(tcsParentKeyHandle);

		TcTddl dest = TcTddl.getInstance();
		Object[] retVal = TcTpmCmdMigration.TpmCmkConvertMigration(dest,
				tpmParentKeyHandle, restrictTicket, sigTicket, migratedKey,
				msaList, random, parentAuth);

		return retVal;
	}

	/***************************************************************************
	 * This method creates a TPM maintenance archive.
	 *
	 * @param hContext
	 * @param generateRandom
	 * @param ownerAuth
	 * @throws TcTddlException,
	 *             TcTpmException
	 * @throws TcTcsException
	 */
	public static synchronized Object[] TcsipCreateMaintenanceArchive(
			long hContext, boolean generateRandom, TcTcsAuth ownerAuth)
			throws TcTddlException, TcTpmException, TcTcsException {
		TcTcsContextMgr.checkContextHandle(hContext);
		CheckPrecondition.notNull(ownerAuth, "ownerAuth");
		TcTcsAuthCache.getInstance().ensureAuthsAreLoadedInTpm(
				new TcTcsAuth[] { ownerAuth });

		TcTddl dest = TcTddl.getInstance();
		Object[] retVal = TcTpmCmdMaintenance.TpmCreateMaintenanceArchive(dest,
				generateRandom, ownerAuth);

		return retVal;
	}

	/***************************************************************************
	 * This method loads a TPM maintenance archive that has been massaged by the
	 * manufacturer to load into another TPM.
	 *
	 * @param hContext
	 * @param inData
	 * @param ownerAuth
	 * @throws TcTddlException
	 * @throws TcTpmException
	 * @throws TcTcsException
	 */
	public static synchronized Object[] TcsipLoadMaintenanceArchive(
			long hContext, TcBlobData inData, TcTcsAuth ownerAuth)
			throws TcTddlException, TcTpmException, TcTcsException {
		TcTcsContextMgr.checkContextHandle(hContext);
		CheckPrecondition.notNull(inData, "inData");
		CheckPrecondition.notNull(ownerAuth, "ownerAuth");
		TcTcsAuthCache.getInstance().ensureAuthsAreLoadedInTpm(
				new TcTcsAuth[] { ownerAuth });

		TcTddl dest = TcTddl.getInstance();
		Object[] retVal = TcTpmCmdMaintenance.TpmLoadMaintenanceArchive(dest,
				inData, ownerAuth);

		return retVal;
	}

	/***************************************************************************
	 * This method is a permanent action that prevents ANYONE from creating a
	 * TPM maintenance archive until a new TPM owner is set.
	 *
	 * @param hContext
	 * @param ownerAuth
	 * @throws TcTddlException
	 * @throws TcTpmException
	 * @throws TcTcsException
	 */
	public static synchronized Object[] TcsipKillMaintenanceFeature(
			long hContext, TcTcsAuth ownerAuth) throws TcTddlException,
			TcTpmException, TcTcsException {
		TcTcsContextMgr.checkContextHandle(hContext);
		CheckPrecondition.notNull(ownerAuth, "ownerAuth");
		TcTcsAuthCache.getInstance().ensureAuthsAreLoadedInTpm(
				new TcTcsAuth[] { ownerAuth });

		TcTddl dest = TcTddl.getInstance();
		Object[] retVal = TcTpmCmdMaintenance.TpmKillMaintenanceFeature(dest,
				ownerAuth);

		return retVal;
	}

	/***************************************************************************
	 * This method loads the TPM manufactuerer's public key for use in the
	 * maintenance process.
	 *
	 * @param hContext
	 * @param antiReplay
	 * @param pubKey
	 * @throws TcTddlException,
	 *             TcTpmException
	 * @throws TcTcsException
	 */
	public static synchronized Object[] TcsipLoadManuMaintPub(long hContext,
			TcTpmNonce antiReplay, TcTpmPubkey pubKey) throws TcTddlException,
			TcTpmException, TcTcsException {
		TcTcsContextMgr.checkContextHandle(hContext);
		CheckPrecondition.notNull(antiReplay, "antiReplay");
		CheckPrecondition.notNull(pubKey, "pubKey");

		TcTddl dest = TcTddl.getInstance();
		Object[] retVal = TcTpmCmdMaintenance.TpmLoadManuMaintPub(dest,
				antiReplay, pubKey);

		return retVal;
	}

	/***************************************************************************
	 * This command is used to check whether the manufactuerer's public
	 * maintenance key in a TPM has the expected value.
	 *
	 * @param hContext
	 * @param antiReplay
	 * @throws TcTddlException,
	 *             TcTpmException
	 * @throws TcTcsException
	 */
	public static synchronized Object[] TcsipReadManuMaintPub(long hContext,
			TcTpmNonce antiReplay) throws TcTddlException, TcTpmException,
			TcTcsException {
		TcTcsContextMgr.checkContextHandle(hContext);
		CheckPrecondition.notNull(antiReplay, "antiReplay");

		TcTddl dest = TcTddl.getInstance();
		Object[] retVal = TcTpmCmdMaintenance.TpmReadManuMaintPub(dest,
				antiReplay);

		return retVal;
	}

	/***************************************************************************
	 * This method signs a digest and returns the resulting digital signature.
	 * This command uses a properly authorized signature key.
	 *
	 * @param hContext
	 * @param tcsKeyHandle
	 * @param areaToSign
	 * @param inAuth
	 *
	 * @throws TcTddlException,
	 *             TcTpmException
	 * @throws TcTcsException
	 */
	public static synchronized Object[] TcsipSign(long hContext,
			long tcsKeyHandle, TcBlobData areaToSign, TcTcsAuth inAuth)
			throws TcTddlException, TcTpmException, TcTcsException {
		TcTcsContextMgr.checkContextHandle(hContext);
		CheckPrecondition.notNull(areaToSign, "areaToSign");
		CheckPrecondition.notNull(inAuth, "inAuth");
		TcTcsAuthCache.getInstance().ensureAuthsAreLoadedInTpm(
				new TcTcsAuth[] { inAuth });

		long tpmKeyHandle = getKeyCache().ensureKeyIsLoadedInTpm(tcsKeyHandle);

		TcTddl dest = TcTddl.getInstance();
		Object[] retVal = TcTpmCmdCrypto.TpmSign(dest, tpmKeyHandle,
				areaToSign, inAuth);

		return retVal;
	}

	/***************************************************************************
	 * This method returns the next bytesRequested bytes from the random number
	 * generator to the caller.
	 *
	 * @param hContext
	 * @param bytesRequested
	 * @throws TcTddlException,
	 *             TcTpmException
	 * @throws TcTcsException
	 */
	public static synchronized Object[] TcsipGetRandom(long hContext,
			long bytesRequested) throws TcTddlException, TcTpmException,
			TcTcsException {
		TcTcsContextMgr.checkContextHandle(hContext);

		TcTddl dest = TcTddl.getInstance();
		Object[] retVal = TcTpmCmdCrypto.TpmGetRandom(dest, bytesRequested);

		return retVal;
	}

	/***************************************************************************
	 * This method adds entropy to the RNG state.
	 *
	 * @param hContext
	 * @param inData
	 * @throws TcTddlException,
	 *             TcTpmException
	 * @throws TcTcsException
	 */
	public static synchronized Object[] TcsipStirRandom(long hContext,
			TcBlobData inData) throws TcTddlException, TcTpmException,
			TcTcsException {
		TcTcsContextMgr.checkContextHandle(hContext);
		CheckPrecondition.notNull(inData, "inData");

		TcTddl dest = TcTddl.getInstance();
		Object[] retVal = TcTpmCmdCrypto.TpmStirRandom(dest, inData);

		return retVal;
	}

	/***************************************************************************
	 * This method allows a key to certify the public portion of certain storage
	 * and signing keys.
	 *
	 * @param hContext
	 * @param tcsCertHandle
	 * @param tcsKeyHandle
	 * @param antiReplay
	 * @param certAuth
	 * @param keyAuth
	 * @throws TcTddlException,
	 *             TcTpmException
	 * @throws TcTcsException
	 */
	public static synchronized Object[] TcsipCertifyKey(long hContext,
			long tcsCertHandle, long tcsKeyHandle, TcTpmNonce antiReplay,
			TcTcsAuth certAuth, TcTcsAuth keyAuth) throws TcTddlException,
			TcTpmException, TcTcsException {
		TcTcsContextMgr.checkContextHandle(hContext);
		TcTcsContextMgr.getContextForHandle(hContext).checkKeyIsAssociated(
				tcsKeyHandle);
		TcTcsContextMgr.getContextForHandle(hContext).checkKeyIsAssociated(
				tcsCertHandle);
		CheckPrecondition.notNull(antiReplay, "antiReplay");
		CheckPrecondition.notNull(certAuth, "certAuth");
		CheckPrecondition.notNull(keyAuth, "keyAuth");
		TcTcsAuthCache.getInstance().ensureAuthsAreLoadedInTpm(
				new TcTcsAuth[] { certAuth, keyAuth });

		long tpmCertHandle = getKeyCache().ensureKeyIsLoadedInTpm(tcsCertHandle);
		long tpmKeyHandle = getKeyCache().ensureKeyIsLoadedInTpm(tcsKeyHandle);

		TcTddl dest = TcTddl.getInstance();
		Object[] retVal = TcTpmCmdCrypto.TpmCertifyKey(dest, tpmCertHandle,
				tpmKeyHandle, antiReplay, certAuth, keyAuth);

		return retVal;
	}

	/***************************************************************************
	 * This method allows a key to certify the public portion of certifiable
	 * migratable storage and signing keys.
	 *
	 * @param hContext
	 * @param tcsKeyHandle
	 * @param tcsCertHandle
	 * @param migrationPubDigest
	 * @param antiReplay
	 * @param keyAuth
	 * @param certAuth
	 * @throws TcTddlException,
	 *             TcTpmException
	 * @throws TcTcsException
	 */
	public static synchronized Object[] TcsipCertifyKey2(long hContext,
			long tcsCertHandle, long tcsKeyHandle,
			TcTpmDigest migrationPubDigest, TcTpmNonce antiReplay,
			TcTcsAuth certAuth, TcTcsAuth keyAuth) throws TcTddlException,
			TcTpmException, TcTcsException {
		// Note:
		// - TPM parameter order: keyHandle, certHandle; keyAuth, certAuth
		// - TCS parameter order: certHandle, keyHandle; certAuth, keyAuth

		TcTcsContextMgr.checkContextHandle(hContext);
		TcTcsContextMgr.getContextForHandle(hContext).checkKeyIsAssociated(
				tcsKeyHandle);
		TcTcsContextMgr.getContextForHandle(hContext).checkKeyIsAssociated(
				tcsCertHandle);
		CheckPrecondition.notNull(migrationPubDigest, "migrationPubDigest");
		CheckPrecondition.notNull(antiReplay, "antiReplay");
		CheckPrecondition.notNull(certAuth, "certAuth");
		CheckPrecondition.notNull(keyAuth, "keyAuth");
		TcTcsAuthCache.getInstance().ensureAuthsAreLoadedInTpm(
				new TcTcsAuth[] { certAuth, keyAuth });

		long tpmCertHandle = getKeyCache().ensureKeyIsLoadedInTpm(tcsCertHandle);
		long tpmKeyHandle = getKeyCache().ensureKeyIsLoadedInTpm(tcsKeyHandle);

		TcTddl dest = TcTddl.getInstance();
		Object[] retVal = TcTpmCmdCrypto.TpmCertifyKey2(dest, tpmKeyHandle,
				tpmCertHandle, migrationPubDigest, antiReplay, keyAuth,
				certAuth);

		return new Object[] { retVal[0], retVal[2], retVal[1], retVal[3],
				retVal[4] };
	}

	/***************************************************************************
	 * This method generates the endorsement key pair.
	 *
	 * @param hContext
	 * @param antiReplay
	 * @param keyInfo
	 * @throws TcTddlException,
	 *             TcTpmException
	 * @throws TcTcsException
	 */
	public static synchronized Object[] TcsipCreateEndorsementKeyPair(
			long hContext, TcTpmNonce antiReplay, TcTpmKeyParms keyInfo)
			throws TcTddlException, TcTpmException, TcTcsException {
		TcTcsContextMgr.checkContextHandle(hContext);
		CheckPrecondition.notNull(antiReplay, "antiReplay");
		CheckPrecondition.notNull(keyInfo, "keyInfo");

		TcTddl dest = TcTddl.getInstance();
		Object[] retVal = TcTpmCmdEkHandling.TpmCreateEndorsementKeyPair(dest,
				antiReplay, keyInfo);

		return retVal;
	}

	/***************************************************************************
	 * This method generates the revocable endorsement key pair.
	 *
	 * @param hContext
	 * @param antiReplay
	 * @param keyInfo
	 * @param generateReset
	 * @param inputEKreset
	 * @throws TcTddlException,
	 *             TcTpmException
	 * @throws TcTcsException
	 */
	public static synchronized Object[] TcsipCreateRevocableEK(long hContext,
			TcTpmNonce antiReplay, TcTpmKeyParms keyInfo,
			boolean generateReset, TcTpmNonce inputEKreset)
			throws TcTddlException, TcTpmException, TcTcsException {
		TcTcsContextMgr.checkContextHandle(hContext);
		CheckPrecondition.notNull(antiReplay, "antiReplay");
		CheckPrecondition.notNull(keyInfo, "keyInfo");

		TcTddl dest = TcTddl.getInstance();
		Object[] retVal = TcTpmCmdEkHandling.TpmCreateRevocableEK(dest,
				antiReplay, keyInfo, generateReset, inputEKreset);

		return retVal;
	}

	/***************************************************************************
	 * This method clears the TPM revocable endorsement key pair.
	 *
	 * @param hContext
	 * @param ekReset
	 * @throws TcTddlException,
	 *             TcTpmException
	 * @throws TcTcsException
	 */
	public static synchronized Object[] TcsipRevokeEndorsementKeyPair(
			long hContext, TcTpmNonce ekReset) throws TcTddlException,
			TcTpmException, TcTcsException {
		TcTcsContextMgr.checkContextHandle(hContext);
		CheckPrecondition.notNull(ekReset, "ekReset");

		TcTddl dest = TcTddl.getInstance();
		Object[] retVal = TcTpmCmdEkHandling.TpmRevokeTrust(dest, ekReset);

		return retVal;
	}

	/***************************************************************************
	 * This method returns the public portion of the endorsement key.
	 *
	 * @param hContext
	 * @param antiReplay
	 * @throws TcTddlException,
	 *             TcTpmException
	 * @throws TcTcsException
	 */
	public static synchronized Object[] TcsipReadPubek(long hContext,
			TcTpmNonce antiReplay) throws TcTddlException, TcTpmException,
			TcTcsException {
		TcTcsContextMgr.checkContextHandle(hContext);
		CheckPrecondition.notNull(antiReplay, "antiReplay");

		TcTddl dest = TcTddl.getInstance();
		Object[] retVal = TcTpmCmdEkHandling.TpmReadPubek(dest, antiReplay);

		return retVal;
	}

	/***************************************************************************
	 * The purpose of this method is twofold: The first purpose is to obtain
	 * assurance that the credential in the TPM_SYM_CA_ATTESTATION is for this
	 * TPM. The second purpose is to obtain the session key used to encrypt the
	 * TPM_IDENTITY_CREDENTIAL. This function checks that the symmetric session
	 * key corresponds to a TPM-identity before releasing that session key. Only
	 * the owner of the TPM has the privilege of activating a TPM identity. The
	 * owner may authorize this function using either the TPM_OIAP or TPM_OSAP
	 * authorization protocols.
	 *
	 * @param hContext
	 * @param tcsIdKeyHandle
	 * @param blob
	 * @param inKeyAuth
	 * @param inOwnerAuth
	 * @throws TcTddlException,
	 *             TcTpmException
	 * @throws TcTcsException
	 */
	public static synchronized Object[] TcsipActivateTpmIdentity(long hContext,
			long tcsIdKeyHandle, TcBlobData blob, TcTcsAuth inKeyAuth,
			TcTcsAuth inOwnerAuth) throws TcTddlException, TcTpmException,
			TcTcsException {
		TcTcsContextMgr.checkContextHandle(hContext);
		TcTcsContextMgr.getContextForHandle(hContext).checkKeyIsAssociated(
				tcsIdKeyHandle);
		CheckPrecondition.notNull(blob, "blob");
		CheckPrecondition.notNull(inKeyAuth, "inKeyAuth");
		CheckPrecondition.notNull(inOwnerAuth, "inOwnerAuth");
		TcTcsAuthCache.getInstance().ensureAuthsAreLoadedInTpm(
				new TcTcsAuth[] { inKeyAuth, inOwnerAuth });

		long tpmIdKeyHandle = getKeyCache().ensureKeyIsLoadedInTpm(tcsIdKeyHandle);

		TcTddl dest = TcTddl.getInstance();
		Object[] retVal = TcTpmCmdIdentity.TpmActivateIdentity(dest,
				tpmIdKeyHandle, blob, inKeyAuth, inOwnerAuth);

		return retVal;
	}

	/***************************************************************************
	 * This command causes the modification of a specific PCR register.
	 *
	 * @param hContext
	 * @param pcrNum
	 * @param inDigest
	 * @throws TcTddlException,
	 *             TcTpmException
	 * @throws TcTcsException
	 */
	public static synchronized Object[] TcsipExtend(long hContext, long pcrNum,
			TcTpmDigest inDigest) throws TcTddlException, TcTpmException,
			TcTcsException {
		TcTcsContextMgr.checkContextHandle(hContext);
		CheckPrecondition.notNull(inDigest, "inDigest");

		TcTddl dest = TcTddl.getInstance();
		Object[] retVal = TcTpmCmdIntegrity.TpmExtend(dest, pcrNum, inDigest);

		return retVal;
	}

	/***************************************************************************
	 * This method provides a non-cryptographic reporting of the contents of a
	 * named PCR.
	 *
	 * @param hContext
	 * @param pcrNum
	 * @throws TcTddlException,
	 *             TcTpmException
	 * @throws TcTcsException
	 */
	public static synchronized Object[] TcsipPcrRead(long hContext, long pcrNum)
			throws TcTddlException, TcTpmException, TcTcsException {
		TcTcsContextMgr.checkContextHandle(hContext);

		TcTddl dest = TcTddl.getInstance();
		Object[] retVal = TcTpmCmdIntegrity.TpmPcrRead(dest, pcrNum);

		return retVal;
	}

	/***************************************************************************
	 * This command provides cryptographic reporting of PCR values. A loaded key
	 * is required for operation. This command uses the key to sign a statement
	 * that names the current value of a chosen PCR and externally supplied data
	 * (which may be a nonce supplied by a challenger).
	 *
	 * @param hContext
	 * @param tcsKeyHandle
	 * @param antiReplay
	 * @param targetPCR
	 * @param inAuth
	 * @throws TcTddlException,
	 *             TcTpmException
	 * @throws TcTcsException
	 */
	public static synchronized Object[] TcsipQuote(long hContext,
			long tcsKeyHandle, TcTpmNonce antiReplay,
			TcTpmPcrSelection targetPCR, TcTcsAuth inAuth)
			throws TcTddlException, TcTpmException, TcTcsException {
		TcTcsContextMgr.checkContextHandle(hContext);
		TcTcsContextMgr.getContextForHandle(hContext).checkKeyIsAssociated(
				tcsKeyHandle);
		CheckPrecondition.notNull(antiReplay, "antiReplay");
		CheckPrecondition.notNull(targetPCR, "targetPCR");
		CheckPrecondition.notNull(inAuth, "inAuth");
		TcTcsAuthCache.getInstance().ensureAuthsAreLoadedInTpm(
				new TcTcsAuth[] { inAuth });

		long tpmKeyHandle = getKeyCache().ensureKeyIsLoadedInTpm(tcsKeyHandle);

		TcTddl dest = TcTddl.getInstance();
		Object[] retVal = TcTpmCmdIntegrity.TpmQuote(dest, tpmKeyHandle,
				antiReplay, targetPCR, inAuth);

		return retVal;
	}

	/***************************************************************************
	 * This method resets a PCR register. Whether or not it succeeds may depend
	 * on the locality executing the command. PCRs can be defined in a platform
	 * specific specification to allow reset of certain PCRs only for certain
	 * localities. The one exception to this is PCR 15, which can always be
	 * reset in a 1.2 implementation (This is to allow software testing). This
	 * command will reset either ALL of the PCRs selected in pcrSelection or
	 * NONE of them. Note: On IFX 1.2 TPMs, PCR 16 instead of 15 seems the one
	 * that can always be reset.
	 *
	 * @param hContext
	 * @param pcrSelection
	 * @throws TcTddlException,
	 *             TcTpmException
	 * @throws TcTcsException
	 */
	public static synchronized Object[] TcsipPcrReset(long hContext,
			TcTpmPcrSelection pcrSelection) throws TcTddlException,
			TcTpmException, TcTcsException {
		TcTcsContextMgr.checkContextHandle(hContext);
		CheckPrecondition.notNull(pcrSelection, "pcrSelection");

		TcTddl dest = TcTddl.getInstance();
		Object[] retVal = TcTpmCmdIntegrity.TpmPcrReset(dest, pcrSelection);

		return retVal;
	}

	/***************************************************************************
	 * This command provides cryptographic reporting of PCR values. A loaded key
	 * is required for operation. This method uses the key to sign a statement
	 * that names the current value of a chosen PCR and externally supplied data
	 * (which my be a nonce supplied by a challenger).
	 *
	 * @param hContext
	 * @param tcsKeyHandle
	 * @param antiReplay
	 * @param targetPCR
	 * @param addVersion
	 * @param inAuth
	 * @throws TcTddlException,
	 *             TcTpmException
	 * @throws TcTcsException
	 */
	public static synchronized Object[] TcsipQuote2(long hContext,
			long tcsKeyHandle, TcTpmNonce antiReplay,
			TcTpmPcrSelection targetPCR, boolean addVersion, TcTcsAuth inAuth)
			throws TcTddlException, TcTpmException, TcTcsException {
		TcTcsContextMgr.checkContextHandle(hContext);
		TcTcsContextMgr.getContextForHandle(hContext).checkKeyIsAssociated(
				tcsKeyHandle);
		CheckPrecondition.notNull(antiReplay, "antiReplay");
		CheckPrecondition.notNull(targetPCR, "targetPCR");
		CheckPrecondition.notNull(inAuth, "inAuth");
		TcTcsAuthCache.getInstance().ensureAuthsAreLoadedInTpm(
				new TcTcsAuth[] { inAuth });

		long tpmKeyHandle = getKeyCache().ensureKeyIsLoadedInTpm(tcsKeyHandle);

		TcTddl dest = TcTddl.getInstance();
		Object[] retVal = TcTpmCmdIntegrity.TpmQuote2(dest, tpmKeyHandle,
				antiReplay, targetPCR, addVersion, inAuth);

		return retVal;
	}

	/***************************************************************************
	 * This method allows the owner of an entity to change the authorization
	 * data for the entity.
	 *
	 * @param hContext
	 * @param tcsParentKeyHandle
	 * @param protocolID
	 * @param newAuth
	 * @param entityType
	 * @param encData
	 * @param ownerAuth
	 * @param entityAuth
	 * @throws TcTddlException,
	 *             TcTpmException
	 * @throws TcTcsException
	 */
	public static synchronized Object[] TcsipChangeAuth(long hContext,
			long tcsParentKeyHandle, int protocolID, TcTpmEncauth newAuth,
			int entityType, TcBlobData encData, TcTcsAuth ownerAuth,
			TcTcsAuth entityAuth) throws TcTddlException, TcTpmException,
			TcTcsException {
		TcTcsContextMgr.checkContextHandle(hContext);
		TcTcsContextMgr.getContextForHandle(hContext).checkKeyIsAssociated(
				tcsParentKeyHandle);
		CheckPrecondition.notNull(newAuth, "newAuth");
		CheckPrecondition.notNull(encData, "encData");
		CheckPrecondition.notNull(ownerAuth, "ownerAuth");
		CheckPrecondition.notNull(entityAuth, "entityAuth");
		TcTcsAuthCache.getInstance().ensureAuthsAreLoadedInTpm(
				new TcTcsAuth[] { ownerAuth, entityAuth });

		long tpmParentKeyHandle = getKeyCache()
				.ensureKeyIsLoadedInTpm(tcsParentKeyHandle);

		TcTddl dest = TcTddl.getInstance();

		Object[] retVal = TcTpmCmdChangeAuth.TpmChangeAuth(dest,
				tpmParentKeyHandle, protocolID, newAuth, entityType, encData,
				ownerAuth, entityAuth);

		return retVal;
	}

	/***************************************************************************
	 * This method allows the owner of an entity to change the authorization
	 * data fro the TPM owner or the SRK.
	 *
	 * @param hContext
	 * @param protocolID
	 * @param newAuth
	 * @param entityType
	 * @param ownerAuth
	 * @throws TcTddlException,
	 *             TcTpmException
	 * @throws TcTcsException
	 */
	public static synchronized Object[] TcsipChangeAuthOwner(long hContext,
			int protocolID, TcTpmEncauth newAuth, int entityType,
			TcTcsAuth ownerAuth) throws TcTddlException, TcTpmException,
			TcTcsException {
		TcTcsContextMgr.checkContextHandle(hContext);
		CheckPrecondition.notNull(newAuth, "newAuth");
		CheckPrecondition.notNull(ownerAuth, "ownerAuth");
		TcTcsAuthCache.getInstance().ensureAuthsAreLoadedInTpm(
				new TcTcsAuth[] { ownerAuth });

		TcTddl dest = TcTddl.getInstance();
		Object[] retVal = TcTpmCmdChangeAuth.TpmChangeAuthOwner(dest,
				protocolID, newAuth, entityType, ownerAuth);

		return retVal;
	}

	/***************************************************************************
	 * This method allows the creation of an authorization handle and the
	 * tracking of the handle by the TPM. THe TPM generates the handle and
	 * nonce.
	 *
	 * @param hContext
	 * @throws TcTddlException,
	 *             TcTpmException
	 * @throws TcTcsException
	 */
	public static synchronized Object[] TcsipOIAP(long hContext)
			throws TcTddlException, TcTpmException, TcTcsException {
		TcTcsContextMgr.checkContextHandle(hContext);

		return TcTcsAuthManager.startOIAP(hContext);
	}

	/***************************************************************************
	 * This method creates the authorization handle, the shared secret and
	 * generates nonceEven and nonceEvenOSAP.
	 *
	 * @param hContext
	 * @param entityType
	 * @param entityValue
	 * @param nonceOddOSAP
	 * @throws TcTddlException,
	 *             TcTpmException
	 * @throws TcTcsException
	 */
	public static synchronized Object[] TcsipOSAP(long hContext,
			int entityType, long entityValue, TcTpmNonce nonceOddOSAP)
			throws TcTddlException, TcTpmException, TcTcsException {
		TcTcsContextMgr.checkContextHandle(hContext);

		if (entityType == TcTpmConstants.TPM_ET_KEYHANDLE) {
			entityValue = getKeyCache().ensureKeyIsLoadedInTpm(entityValue);
		}

		return TcTcsAuthManager.startOSAP(hContext, entityType, entityValue,
				nonceOddOSAP);
	}

	/***************************************************************************
	 * This method opens a delegated authorization session.
	 *
	 * @param hContext
	 * @param entityType
	 * @param tcsKeyHandle
	 * @param nonceOddDSAP
	 * @param entityValue
	 * @throws TcTddlException,
	 *             TcTpmException
	 * @throws TcTcsException
	 */
	public static synchronized Object[] TcsipDSAP(long hContext,
			int entityType, long tcsKeyHandle, TcTpmNonce nonceOddDSAP,
			TcBlobData entityValue) throws TcTddlException, TcTpmException,
			TcTcsException {
		TcTcsContextMgr.checkContextHandle(hContext);
		TcTcsContextMgr.getContextForHandle(hContext).checkKeyIsAssociated(
				tcsKeyHandle);
		CheckPrecondition.notNull(entityValue, "entityValue");

		return TcTcsAuthManager.startDSAP(hContext, entityType, tcsKeyHandle,
				nonceOddDSAP, entityValue);
	}

	/***************************************************************************
	 * This command is authorized either by the TPM owner or by physical
	 * presence. If no owner is installed, the command requires no privilege to
	 * execute. The command uses the opCode parameter with values:
	 * <ul>
	 * <li> TPM_FAMILY_CREATE to create a new family
	 * <li> TPM_FAMILY_INVALIDATE to invalidate an existing family
	 * <li> TPM_FAMILY_ENABLE to enable/disable use of a family and all the rows
	 * that belong to that family
	 * <li> TPM_FAMILY_ADMIN to lock or unlock a family against further
	 * modification. If a family is locked while there is no owner it cannot be
	 * unlocked until after ownership is established.
	 * </ul>
	 *
	 * @param hContext
	 * @param familyID
	 * @param opFlag
	 * @param opData
	 * @param ownerAuth
	 * @throws TcTddlException,
	 *             TcTpmException
	 * @throws TcTcsException
	 */
	public static synchronized Object[] TcsipDelegateManage(long hContext,
			long familyID, long opFlag, TcBlobData opData, TcTcsAuth ownerAuth)
			throws TcTddlException, TcTpmException, TcTcsException {
		TcTcsContextMgr.checkContextHandle(hContext);
		CheckPrecondition.notNull(opData, "opData");
		CheckPrecondition.notNull(ownerAuth, "ownerAuth");
		TcTcsAuthCache.getInstance().ensureAuthsAreLoadedInTpm(
				new TcTcsAuth[] { ownerAuth });

		TcTddl dest = TcTddl.getInstance();
		Object[] retVal = TcTpmCmdDelegation.TpmDelegateManage(dest, familyID,
				opFlag, opData, ownerAuth);

		return retVal;
	}

	/***************************************************************************
	 * This method is used to delegate the privilege to us a key by creating a
	 * blob that can be used TPM_DSAP. THese blob cannot be used as input data
	 * for loading owner delegation, because the internal TPM delegate table is
	 * used to store owner delegations only.
	 *
	 * @param hContext
	 * @param tcsKeyHandle
	 * @param publicInfo
	 * @param encDelAuth
	 * @param keyAuth
	 * @throws TcTddlException,
	 *             TcTpmException
	 * @throws TcTcsException
	 */
	public static synchronized Object[] TcsipDelegateCreateKeyDelegation(
			long hContext, long tcsKeyHandle, TcTpmDelegatePublic publicInfo,
			TcTpmEncauth encDelAuth, TcTcsAuth keyAuth) throws TcTddlException,
			TcTpmException, TcTcsException {
		TcTcsContextMgr.checkContextHandle(hContext);
		TcTcsContextMgr.getContextForHandle(hContext).checkKeyIsAssociated(
				tcsKeyHandle);
		CheckPrecondition.notNull(publicInfo, "publicInfo");
		CheckPrecondition.notNull(encDelAuth, "encDelAuth");
		CheckPrecondition.notNull(keyAuth, "keyAuth");
		TcTcsAuthCache.getInstance().ensureAuthsAreLoadedInTpm(
				new TcTcsAuth[] { keyAuth });

		long tpmKeyHandle = getKeyCache().ensureKeyIsLoadedInTpm(tcsKeyHandle);

		TcTddl dest = TcTddl.getInstance();
		Object[] retVal = TcTpmCmdDelegation.TpmDelegateCreateKeyDelegation(
				dest, tpmKeyHandle, publicInfo, encDelAuth, keyAuth);

		return retVal;
	}

	/***************************************************************************
	 * This method is used to delegate owner privileges to use a set of command
	 * ordinals by creating a blob. This blob can in turn be used as input data
	 * for TPM_DSAP or DelegateLoadOwnerDelegation to provide proof of
	 * privilege. DelegateCreateKeyDelegation must be used to delegate privilege
	 * to use a key.
	 *
	 * @param hContext
	 * @param increment
	 * @param publicInfo
	 * @param encDelAuth
	 * @param ownerAuth
	 * @throws TcTddlException,
	 *             TcTpmException
	 * @throws TcTcsException
	 */
	public static synchronized Object[] TcsipDelegateCreateOwnerDelegation(
			long hContext, boolean increment, TcTpmDelegatePublic publicInfo,
			TcTpmEncauth encDelAuth, TcTcsAuth ownerAuth)
			throws TcTddlException, TcTpmException, TcTcsException {
		TcTcsContextMgr.checkContextHandle(hContext);
		CheckPrecondition.notNull(publicInfo, "publicInfo");
		CheckPrecondition.notNull(encDelAuth, "encDelAuth");
		CheckPrecondition.notNull(ownerAuth, "ownerAuth");
		TcTcsAuthCache.getInstance().ensureAuthsAreLoadedInTpm(
				new TcTcsAuth[] { ownerAuth });

		TcTddl dest = TcTddl.getInstance();
		Object[] retVal = TcTpmCmdDelegation.TpmDelegateCreateOwnerDelegation(
				dest, increment, publicInfo, encDelAuth, ownerAuth);

		return retVal;
	}

	/***************************************************************************
	 * This method is used to load an owner delegation blob into the TPM
	 * non-volatile delegation table. If an owner is installed the owner blob
	 * must be created with DelegateCreateOwnerDelegation. If an owner is not
	 * installed, the owner blob by be created outside the TPM and its
	 * TPM_DELEGATE_SENSITIVE component must be left unencrypted.
	 *
	 * @param hContext
	 * @param index
	 * @param blob
	 * @param ownerAuth
	 * @throws TcTddlException,
	 *             TcTpmException
	 * @throws TcTcsException
	 */
	public static synchronized Object[] TcsipDelegateLoadOwnerDelegation(
			long hContext, long index, TcTpmDelegateOwnerBlob blob,
			TcTcsAuth ownerAuth) throws TcTddlException, TcTpmException,
			TcTcsException {
		TcTcsContextMgr.checkContextHandle(hContext);
		CheckPrecondition.notNull(blob, "blob");
		CheckPrecondition.notNull(ownerAuth, "ownerAuth");
		TcTcsAuthCache.getInstance().ensureAuthsAreLoadedInTpm(
				new TcTcsAuth[] { ownerAuth });

		TcTddl dest = TcTddl.getInstance();
		Object[] retVal = TcTpmCmdDelegation.TpmDelegateLoadOwnerDelegation(
				dest, index, blob, ownerAuth);

		return retVal;
	}

	/***************************************************************************
	 * This command is used to read from the TPM the public contents of the
	 * family and delegate tables that are stored on the TPM. Such data is
	 * required during external verification of tables.
	 *
	 * There are no restrictions on the execution of this command. Anyone can
	 * read this information regardless of the state of the PCRs, regardless of
	 * whether they know any specific authorization value and regardless whether
	 * or not the enable and admin bits are set one way or the other.
	 *
	 * @param hContext
	 * @throws TcTddlException,
	 *             TcTpmException
	 * @throws TcTcsException
	 */
	public static synchronized Object[] TcsipDelegateReadTable(long hContext)
			throws TcTddlException, TcTpmException, TcTcsException {
		TcTcsContextMgr.checkContextHandle(hContext);

		TcTddl dest = TcTddl.getInstance();
		Object[] retVal = TcTpmCmdDelegation.TpmDelegateReadTable(dest);

		return retVal;
	}

	/***************************************************************************
	 * This method sets the cerificationCount in an entity (a blob or a
	 * delegation row) to the current family value, in order that the
	 * delegations represented by that entity will continue to be accepted by
	 * the TPM.
	 *
	 * @param hContext
	 * @param inputData
	 * @param ownerAuth
	 * @throws TcTddlException,
	 *             TcTpmException
	 * @throws TcTcsException
	 */
	public static synchronized Object[] TcsipDelegateUpdateVerificationCount(
			long hContext, TcBlobData inputData, TcTcsAuth ownerAuth)
			throws TcTddlException, TcTpmException, TcTcsException {
		TcTcsContextMgr.checkContextHandle(hContext);
		CheckPrecondition.notNull(inputData, "inputData");
		CheckPrecondition.notNull(ownerAuth, "ownerAuth");
		TcTcsAuthCache.getInstance().ensureAuthsAreLoadedInTpm(
				new TcTcsAuth[] { ownerAuth });

		TcTddl dest = TcTddl.getInstance();
		Object[] retVal = TcTpmCmdDelegation.TpmDelegateUpdateVerification(
				dest, inputData, ownerAuth);

		return retVal;
	}

	/***************************************************************************
	 * This method interprets a delegate blob and returns success or failure,
	 * depending on whether the blob is currently valid.
	 *
	 * @param hContext
	 * @param delegation
	 * @throws TcTddlException,
	 *             TcTpmException
	 * @throws TcTcsException
	 */
	public static synchronized Object[] TcsipDelegateVerifyDelegation(
			long hContext, TcBlobData delegation) throws TcTddlException,
			TcTpmException, TcTcsException {
		TcTcsContextMgr.checkContextHandle(hContext);
		CheckPrecondition.notNull(delegation, "delegation");

		TcTddl dest = TcTddl.getInstance();
		Object[] retVal = TcTpmCmdDelegation.TpmDelegateVerifyDelegation(dest,
				delegation);

		return retVal;
	}

	/***************************************************************************
	 * This command sets aside space in the TPM NVRAM and defines the access
	 * requirements necessary to read and write that space. If this function is
	 * called twice, the first time it will create the space and the second time
	 * delete it.
	 *
	 * @param hContext
	 * @param pubInfo
	 * @param encAuth
	 * @param inAuth
	 * @throws TcTddlException,
	 *             TcTpmException
	 * @throws TcTcsException
	 */
	public static synchronized Object[] TcsipNvDefineOrReleaseSpace(
			long hContext, TcTpmNvDataPublic pubInfo, TcTpmEncauth encAuth,
			TcTcsAuth inAuth) throws TcTddlException, TcTpmException,
			TcTcsException {
		TcTcsContextMgr.checkContextHandle(hContext);
		CheckPrecondition.notNull(pubInfo, "pubInfo");
		CheckPrecondition.notNull(encAuth, "encAuth");

		if (inAuth != null) {
			TcTcsAuthCache.getInstance().ensureAuthsAreLoadedInTpm(new TcTcsAuth[] { inAuth });
		}

		TcTddl dest = TcTddl.getInstance();
		Object[] retVal = TcTpmCmdNvStorage.TpmNvDefineSpace(dest, pubInfo,
				encAuth, inAuth);

		return retVal;
	}

	/***************************************************************************
	 * This command writes the value to a defined area. The write can be TPM
	 * owner authorized or unauthorized and protected by other attributes and
	 * will work when no TPM owner is present.
	 *
	 * @param hContext
	 * @param nvIndex
	 * @param offset
	 * @param data
	 * @param inAuth
	 * @throws TcTddlException,
	 *             TcTpmException
	 * @throws TcTcsException
	 */
	public static synchronized Object[] TcsipNvWriteValue(long hContext,
			long nvIndex, long offset, TcBlobData data, TcTcsAuth inAuth)
			throws TcTddlException, TcTpmException, TcTcsException {
		TcTcsContextMgr.checkContextHandle(hContext);
		CheckPrecondition.notNull(data, "data");
		CheckPrecondition.notNull(inAuth, "inAuth");
		TcTcsAuthCache.getInstance().ensureAuthsAreLoadedInTpm(
				new TcTcsAuth[] { inAuth });

		TcTddl dest = TcTddl.getInstance();
		Object[] retVal = TcTpmCmdNvStorage.TpmNvWriteValue(dest, nvIndex,
				offset, data, inAuth);

		return retVal;
	}

	/***************************************************************************
	 * This command writes a previously defined area. The area must require
	 * authorization to write. This command is for using when authorization
	 * other than the owner authorization is to be used.
	 *
	 * @param hContext
	 * @param nvIndex
	 * @param offset
	 * @param data
	 * @param inAuth
	 * @throws TcTddlException,
	 *             TcTpmException
	 * @throws TcTcsException
	 */
	public static synchronized Object[] TcsipNvWriteValueAuth(long hContext,
			long nvIndex, long offset, TcBlobData data, TcTcsAuth inAuth)
			throws TcTddlException, TcTpmException, TcTcsException {
		TcTcsContextMgr.checkContextHandle(hContext);
		CheckPrecondition.notNull(data, "data");
		CheckPrecondition.notNull(inAuth, "inAuth");
		TcTcsAuthCache.getInstance().ensureAuthsAreLoadedInTpm(
				new TcTcsAuth[] { inAuth });

		TcTddl dest = TcTddl.getInstance();
		Object[] retVal = TcTpmCmdNvStorage.TpmNvWriteValueAuth(dest, nvIndex,
				offset, data, inAuth);

		return retVal;
	}

	/***************************************************************************
	 * This method reads a value from the NV store. This command uses optional
	 * owner authorization.
	 *
	 * @param hContext
	 * @param nvIndex
	 * @param offset
	 * @param dataSz
	 * @param inAuth1
	 * @throws TcTddlException,
	 *             TcTpmException
	 * @throws TcTcsException
	 */
	public static synchronized Object[] TcsipNvReadValue(long hContext,
			long nvIndex, long offset, long dataSz, TcTcsAuth inAuth1)
			throws TcTddlException, TcTpmException, TcTcsException {
		TcTcsContextMgr.checkContextHandle(hContext);
		// inAuth1 can be null
		if (inAuth1 != null) {
			TcTcsAuthCache.getInstance().ensureAuthsAreLoadedInTpm(
					new TcTcsAuth[] { inAuth1 });
		}

		TcTddl dest = TcTddl.getInstance();
		Object[] retVal = TcTpmCmdNvStorage.TpmNvReadValue(dest, nvIndex,
				offset, dataSz, inAuth1);

		return retVal;
	}

	/***************************************************************************
	 * This method reads a value from the NV store. This command uses optional
	 * owner authentication.
	 *
	 * @param hContext
	 * @param nvIndex
	 * @param offset
	 * @param dataLength
	 * @param inAuth
	 * @throws TcTddlException,
	 *             TcTpmException
	 * @throws TcTcsException
	 */
	public static synchronized Object[] TcsipNvReadValueAuth(long hContext,
			long nvIndex, long offset, long dataLength, TcTcsAuth inAuth)
			throws TcTddlException, TcTpmException, TcTcsException {
		TcTcsContextMgr.checkContextHandle(hContext);
		CheckPrecondition.notNull(inAuth, "inAuth");
		TcTcsAuthCache.getInstance().ensureAuthsAreLoadedInTpm(
				new TcTcsAuth[] { inAuth });

		TcTddl dest = TcTddl.getInstance();
		Object[] retVal = TcTpmCmdNvStorage.TpmNvReadValueAuth(dest, nvIndex,
				offset, dataLength, inAuth);

		return retVal;
	}

	/***************************************************************************
	 * This method reads the current tick out of the TPM.
	 *
	 * @param hContext
	 * @throws TcTddlException,
	 *             TcTpmException
	 * @throws TcTcsException
	 */
	public static synchronized Object[] TcsipReadCurrentTicks(long hContext)
			throws TcTddlException, TcTpmException, TcTcsException {
		TcTcsContextMgr.checkContextHandle(hContext);

		TcTddl dest = TcTddl.getInstance();
		Object[] retVal = TcTpmCmdTiming.TpmGetTicks(dest);

		return retVal;
	}

	/***************************************************************************
	 * This method is similar to a time stamp: it associates a tick value with a
	 * blob, indicating that the blob existed at some point earlier than the
	 * time corresponding to the tick value.
	 *
	 * @param hContext
	 * @param keyHandle
	 * @param antiReplay
	 * @param digestToStamp
	 * @param privAuth
	 * @throws TcTddlException,
	 *             TcTpmException
	 * @throws TcTcsException
	 */
	public static synchronized Object[] TcsipTickStampBlob(long hContext,
			long keyHandle, TcTpmNonce antiReplay, TcTpmDigest digestToStamp,
			TcTcsAuth privAuth) throws TcTddlException, TcTpmException,
			TcTcsException {
		TcTcsContextMgr.checkContextHandle(hContext);
		CheckPrecondition.notNull(antiReplay, "antiReplay");
		CheckPrecondition.notNull(digestToStamp, "digestToStamp");
		CheckPrecondition.notNull(privAuth, "privAuth");
		TcTcsAuthCache.getInstance().ensureAuthsAreLoadedInTpm(
				new TcTcsAuth[] { privAuth });

		long tpmKeyHandle = getKeyCache().ensureKeyIsLoadedInTpm(keyHandle);

		TcTddl dest = TcTddl.getInstance();
		Object[] retVal = TcTpmCmdTiming.TpmTickStampBlob(dest, tpmKeyHandle,
				antiReplay, digestToStamp, privAuth);

		return retVal;
	}

	/***************************************************************************
	 * TODO (transport): implement Tcsip method signature
	 */
	public static synchronized Object[] TcsEstablishTransport(long hContext,
			long tcsEncKeyHandle, TcTpmTransportPublic transPublic,
			TcBlobData secret, TcTcsAuth inAuth1) throws TcTddlException,
			TcTpmException, TcTcsException {
		TcTcsContextMgr.checkContextHandle(hContext);
		TcTcsContextMgr.getContextForHandle(hContext).checkKeyIsAssociated(
				tcsEncKeyHandle);
		CheckPrecondition.notNull(transPublic, "transPublic");
		CheckPrecondition.notNull(secret, "secret");
		if (tcsEncKeyHandle != TcTpmConstants.TPM_KH_TRANSPORT) {
			CheckPrecondition.notNull(inAuth1, "inAuth1");
			TcTcsAuthCache.getInstance().ensureAuthsAreLoadedInTpm(
					new TcTcsAuth[] { inAuth1 });
		}

		long tpmEncKeyHandle = getKeyCache()
				.ensureKeyIsLoadedInTpm(tcsEncKeyHandle);

		TcTddl dest = TcTddl.getInstance();

		Object[] retVal = TcTpmCmdTransport.TpmEstablishTransport(dest,
				tpmEncKeyHandle, transPublic, secret, inAuth1);

		return retVal;
	}

	/***************************************************************************
	 * TODO (transport): implement Tcsip method signature
	 */
	public static synchronized Object[] TcsExecuteTransport(long hContext,
			TcBlobData wrappedCmd, long transHandle, TcTcsAuth inAuth1)
			throws TcTddlException, TcTpmException, TcTcsException {
		TcTcsContextMgr.checkContextHandle(hContext);
		CheckPrecondition.notNull(wrappedCmd, "wrappedCmd");
		CheckPrecondition.notNull(inAuth1, "inAuth1");
		TcTcsAuthCache.getInstance().ensureAuthsAreLoadedInTpm(
				new TcTcsAuth[] { inAuth1 });

		TcTddl dest = TcTddl.getInstance();

		Object[] retVal = TcTpmCmdTransport.TpmExecuteTransport(dest,
				wrappedCmd, transHandle, inAuth1);

		return retVal;
	}

	/***************************************************************************
	 * TODO (transport): implement Tcsip method signature
	 */
	public static synchronized Object[] TcsReleaseTransportSigned(
			long hContext, long tcsKeyHandle, TcTpmNonce antiReplay,
			long transHandle, TcTcsAuth inAuth1, TcTcsAuth inAuth2)
			throws TcTddlException, TcTpmException, TcTcsException {
		TcTcsContextMgr.checkContextHandle(hContext);
		TcTcsContextMgr.getContextForHandle(hContext).checkKeyIsAssociated(
				tcsKeyHandle);
		CheckPrecondition.notNull(antiReplay, "antiReplay");
		CheckPrecondition.notNull(inAuth1, "inAuth1");
		CheckPrecondition.notNull(inAuth2, "inAuth2");
		TcTcsAuthCache.getInstance().ensureAuthsAreLoadedInTpm(
				new TcTcsAuth[] { inAuth1, inAuth2 });

		long tpmKeyHandle = getKeyCache().ensureKeyIsLoadedInTpm(tcsKeyHandle);

		TcTddl dest = TcTddl.getInstance();

		Object[] retVal = TcTpmCmdTransport.TpmReleaseTransportSigned(dest,
				tpmKeyHandle, antiReplay, transHandle, inAuth1, inAuth2);

		return retVal;
	}

	/***************************************************************************
	 * This method creates a new counter in the TPM. It does NOT select that
	 * counter. Counter creation assigns an authorization value to the counter
	 * and sets the counters original start value to be one more that the
	 * internal base counter. The label length has to be 4.
	 *
	 * @param hContext
	 * @param encAuth
	 * @param label
	 * @param ownerAuth
	 * @throws TcTddlException,
	 *             TcTpmException
	 * @throws TcTcsException
	 */
	public static synchronized Object[] TcsipCreateCounter(long hContext,
			TcBlobData label, TcTpmEncauth encAuth, TcTcsAuth ownerAuth)
			throws TcTddlException, TcTpmException, TcTcsException {
		// Note:
		// TPM parameter order: encAuth, label
		// TCS parameter order: label, encAuth

		TcTcsContextMgr.checkContextHandle(hContext);
		CheckPrecondition.notNull(encAuth, "encAuth");
		CheckPrecondition.notNull(ownerAuth, "ownerAuth");
		CheckPrecondition.notNull(label, "label");
		CheckPrecondition.equal(label.getLengthAsLong(), 4, "label");
		TcTcsAuthCache.getInstance().ensureAuthsAreLoadedInTpm(
				new TcTcsAuth[] { ownerAuth });

		TcTddl dest = TcTddl.getInstance();
		Object[] retVal = TcTpmCmdMonotonicCnt.TpmCreateCounter(dest, encAuth,
				label, ownerAuth);

		return retVal;
	}

	/***************************************************************************
	 * This method selects a counter if one has not yet been selected, and
	 * increments that counter register. If a counter has already been selected
	 * and it is different from the one requested, the increment counter will
	 * fail. To change the selected counter, the TPM must go through a startup
	 * cycle.
	 *
	 * @param hContext
	 * @param countID
	 * @param counterAuth
	 * @throws TcTddlException,
	 *             TcTpmException
	 * @throws TcTcsException
	 */
	public static synchronized Object[] TcsipIncrementCounter(long hContext,
			long countID, TcTcsAuth counterAuth) throws TcTddlException,
			TcTpmException, TcTcsException {
		TcTcsContextMgr.checkContextHandle(hContext);
		CheckPrecondition.notNull(counterAuth, "counterAuth");
		TcTcsAuthCache.getInstance().ensureAuthsAreLoadedInTpm(
				new TcTcsAuth[] { counterAuth });

		TcTddl dest = TcTddl.getInstance();
		Object[] retVal = TcTpmCmdMonotonicCnt.TpmIncrementCounter(dest,
				countID, counterAuth);

		return retVal;
	}

	/***************************************************************************
	 * This method reads the current value of a counter register.
	 *
	 * @param hContext
	 * @param countID
	 * @throws TcTddlException,
	 *             TcTpmException
	 * @throws TcTcsException
	 */
	public static synchronized Object[] TcsipReadCounter(long hContext,
			long countID) throws TcTddlException, TcTpmException,
			TcTcsException {
		TcTcsContextMgr.checkContextHandle(hContext);

		TcTddl dest = TcTddl.getInstance();
		Object[] retVal = TcTpmCmdMonotonicCnt.TpmReadCounter(dest, countID);

		return retVal;
	}

	/***************************************************************************
	 * This method releases a counter so that no reads or increments of the
	 * indicated counter will succeed. It invalidates all information regarding
	 * that counter, including the counter handle.
	 *
	 * @param hContext
	 * @param countID
	 * @param counterAuth
	 * @throws TcTddlException,
	 *             TcTpmException
	 * @throws TcTcsException
	 */
	public static synchronized Object[] TcsipReleaseCounter(long hContext,
			long countID, TcTcsAuth counterAuth) throws TcTddlException,
			TcTpmException, TcTcsException {
		TcTcsContextMgr.checkContextHandle(hContext);
		CheckPrecondition.notNull(counterAuth, "counterAuth");
		TcTcsAuthCache.getInstance().ensureAuthsAreLoadedInTpm(
				new TcTcsAuth[] { counterAuth });

		TcTddl dest = TcTddl.getInstance();
		Object[] retVal = TcTpmCmdMonotonicCnt.TpmReleaseCounter(dest, countID,
				counterAuth);

		return retVal;
	}

	/***************************************************************************
	 * This method releases a counter so that no reads or increments of the
	 * indicated counter will succeed. It invalidates all information regarding
	 * that counter, including the counter handle. It differs from
	 * TcsipReleaseCounter in that it requires TPM owner authorization instead
	 * of authorization for the counter.
	 *
	 * @param hContext
	 * @param countID
	 * @param ownerAuth
	 * @throws TcTddlException,
	 *             TcTpmException
	 * @throws TcTcsException
	 */
	public static synchronized Object[] TcsipReleaseCounterOwner(long hContext,
			long countID, TcTcsAuth ownerAuth) throws TcTddlException,
			TcTpmException, TcTcsException {
		TcTcsContextMgr.checkContextHandle(hContext);
		CheckPrecondition.notNull(ownerAuth, "ownerAuth");
		TcTcsAuthCache.getInstance().ensureAuthsAreLoadedInTpm(
				new TcTcsAuth[] { ownerAuth });

		TcTddl dest = TcTddl.getInstance();
		Object[] retVal = TcTpmCmdMonotonicCnt.TpmReleaseCounterOwner(dest,
				countID, ownerAuth);

		return retVal;
	}

	/***************************************************************************
	 * This method executes a TPM DAA join command.
	 *
	 * @param hContext
	 * @param handle
	 * @param stage
	 * @param inputData0
	 * @param inputData1
	 * @param ownerAuth
	 * @throws TcTddlException,
	 *             TcTpmException
	 * @throws TcTcsException
	 */
	public static synchronized Object[] TcsipDaaJoin(long hContext,
			long handle, short stage, TcBlobData inputData0,
			TcBlobData inputData1, TcTcsAuth ownerAuth) throws TcTddlException,
			TcTpmException, TcTcsException {
		TcTcsContextMgr.checkContextHandle(hContext);
		CheckPrecondition.notNull(inputData0, "inputData0");
		CheckPrecondition.notNull(inputData1, "inputData1");
		CheckPrecondition.notNull(ownerAuth, "ownerAuth");
		TcTcsAuthCache.getInstance().ensureAuthsAreLoadedInTpm(
				new TcTcsAuth[] { ownerAuth });

		TcTddl dest = TcTddl.getInstance();
		Object[] retVal = TcTpmCmdDaa.TpmDaaJoin(dest, handle, stage,
				inputData0, inputData1, ownerAuth);

		return retVal;
	}

	/***************************************************************************
	 * This method executes a TPM DAA sign command.
	 *
	 * @param hContext
	 * @param handle
	 * @param stage
	 * @param inputData0
	 * @param inputData1
	 * @param ownerAuth
	 * @throws TcTddlException,
	 *             TcTpmException
	 * @throws TcTcsException
	 */
	public static synchronized Object[] TcsipDaaSign(long hContext,
			long handle, short stage, TcBlobData inputData0,
			TcBlobData inputData1, TcTcsAuth ownerAuth) throws TcTddlException,
			TcTpmException, TcTcsException {
		TcTcsContextMgr.checkContextHandle(hContext);
		CheckPrecondition.notNull(inputData0, "inputData0");
		CheckPrecondition.notNull(inputData1, "inputData1");
		CheckPrecondition.notNull(ownerAuth, "ownerAuth");
		TcTcsAuthCache.getInstance().ensureAuthsAreLoadedInTpm(
				new TcTcsAuth[] { ownerAuth });

		TcTddl dest = TcTddl.getInstance();
		Object[] retVal = TcTpmCmdDaa.TpmDaaSign(dest, handle, stage,
				inputData0, inputData1, ownerAuth);

		return retVal;
	}

	/***************************************************************************
	 * This method allows the TPM driver to clear out information in an
	 * authorization handle. The TPM may maintain the authorization session even
	 * though a key attached to it has been unloaded or the authorization
	 * session itself has been unloaded in some way.
	 *
	 * @param hContext
	 * @param handle
	 * @throws TcTddlException,
	 *             TcTpmException
	 * @throws TcTcsException
	 */
	public static synchronized Object[] TcsipTerminateHandle(long hContext,
			long handle) throws TcTddlException, TcTpmException, TcTcsException {
		TcTcsContextMgr.checkContextHandle(hContext);

		TcTddl dest = TcTddl.getInstance();
		Object[] retVal = TcTpmCmdDeprKey.TpmTerminateHandle(dest, handle);

		return retVal;
	}

	/***************************************************************************
	 * This method provides write access to the Data Integrity Registers.
	 *
	 * @param hContext
	 * @param dirIndex
	 * @param newContents
	 * @param inAuth
	 * @throws TcTddlException,
	 *             TcTpmException
	 * @throws TcTcsException
	 */
	public static synchronized Object[] TcsipDirWriteAuth(long hContext,
			long dirIndex, TcTpmDigest newContents, TcTcsAuth inAuth)
			throws TcTddlException, TcTpmException, TcTcsException {
		TcTcsContextMgr.checkContextHandle(hContext);
		CheckPrecondition.notNull(newContents, "newContents");
		CheckPrecondition.notNull(inAuth, "inAuth");
		TcTcsAuthCache.getInstance().ensureAuthsAreLoadedInTpm(
				new TcTcsAuth[] { inAuth });

		TcTddl dest = TcTddl.getInstance();
		Object[] retVal = TcTpmCmdDeprDir.TpmDirWriteAuth(dest, dirIndex,
				newContents, inAuth);

		return retVal;
	}

	/***************************************************************************
	 * This method provides read access to the Data Integrity Registers.
	 *
	 * @param hContext
	 * @param dirIndex
	 * @throws TcTddlException,
	 *             TcTpmException
	 * @throws TcTcsException
	 */
	public static synchronized Object[] TcsipDirRead(long hContext,
			long dirIndex) throws TcTddlException, TcTpmException,
			TcTcsException {
		TcTcsContextMgr.checkContextHandle(hContext);

		TcTddl dest = TcTddl.getInstance();
		Object[] retVal = TcTpmCmdDeprDir.TpmDirRead(dest, dirIndex);

		return retVal;
	}

	/***************************************************************************
	 * This method starts the process of changing authorization for an entity.
	 * It sets the OIAP session that must be retained for use by its twin
	 * TcsipChangeAuthAsymFinish command.
	 *
	 * @param hContext
	 * @param tcsKeyHandle
	 * @param antiReplay
	 * @param tempKeyInfo
	 * @param inAuth
	 * @throws TcTddlException,
	 *             TcTpmException
	 * @throws TcTcsException
	 */
	public static synchronized Object[] TcsipChangeAuthAsymStart(long hContext,
			long tcsKeyHandle, TcTpmNonce antiReplay,
			TcTpmKeyParms tempKeyInfo, TcTcsAuth inAuth)
			throws TcTddlException, TcTpmException, TcTcsException {
		TcTcsContextMgr.checkContextHandle(hContext);
		CheckPrecondition.notNull(antiReplay, "antiReplay");
		CheckPrecondition.notNull(tempKeyInfo, "tempKey");
		CheckPrecondition.notNull(inAuth, "inAuth");
		TcTcsAuthCache.getInstance().ensureAuthsAreLoadedInTpm(
				new TcTcsAuth[] { inAuth });

		// Note: The reason why this method is part of the KeyManager is that
		// the outgoing ephHandle
		// has to be translated from a TPM to TCS key handle.
		return TcTcsKeyManager.ChangeAuthAsymStart(hContext, tcsKeyHandle,
				antiReplay, tempKeyInfo, inAuth);
	}

	/***************************************************************************
	 * This method completes the process of changing authorization for an
	 * entity.
	 *
	 * @param hContext
	 * @param tcsParentKeyHandle
	 * @param tcsEphHandle
	 * @param entityType
	 * @param newAuthLink
	 * @param encNewAuth
	 * @param encData
	 * @param inAuth
	 * @throws TcTddlException,
	 *             TcTpmException
	 * @throws TcTcsException
	 */
	public static synchronized Object[] TcsipChangeAuthAsymFinish(
			long hContext, long tcsParentKeyHandle, long tcsEphHandle,
			int entityType, TcTpmDigest newAuthLink, TcBlobData encNewAuth,
			TcBlobData encData, TcTcsAuth inAuth) throws TcTddlException,
			TcTpmException, TcTcsException {
		TcTcsContextMgr.checkContextHandle(hContext);
		TcTcsContextMgr.getContextForHandle(hContext).checkKeyIsAssociated(
				tcsParentKeyHandle);
		TcTcsContextMgr.getContextForHandle(hContext).checkKeyIsAssociated(
				tcsEphHandle);
		CheckPrecondition.notNull(newAuthLink, "newAuthLink");
		CheckPrecondition.notNull(encNewAuth, "encNewAuth");
		CheckPrecondition.notNull(encData, "encData");
		CheckPrecondition.notNull(inAuth, "inAuth");
		TcTcsAuthCache.getInstance().ensureAuthsAreLoadedInTpm(
				new TcTcsAuth[] { inAuth });

		long tpmParentKeyHandle = getKeyCache()
				.ensureKeyIsLoadedInTpm(tcsParentKeyHandle);
		long tpmEphHandle = getKeyCache().ensureKeyIsLoadedInTpm(tcsEphHandle);

		TcTddl dest = TcTddl.getInstance();

		Object[] retVal = TcTpmCmdDeprChangeAuth.TpmChangeAuthAsymFinish(dest,
				tpmParentKeyHandle, tpmEphHandle, entityType, newAuthLink,
				encNewAuth, encData, inAuth);

		return retVal;
	}

	/***************************************************************************
	 * This method allows the TPM owner to read the public endorsement key.
	 *
	 * @param hContext
	 * @param ownerAuth
	 * @throws TcTddlException,
	 *             TcTpmException
	 * @throws TcTcsException
	 */
	public static synchronized Object[] TcsipOwnerReadPubek(long hContext,
			TcTcsAuth ownerAuth) throws TcTddlException, TcTpmException,
			TcTcsException {
		TcTcsContextMgr.checkContextHandle(hContext);
		CheckPrecondition.notNull(ownerAuth, "ownerAuth");
		TcTcsAuthCache.getInstance().ensureAuthsAreLoadedInTpm(
				new TcTcsAuth[] { ownerAuth });

		TcTddl dest = TcTddl.getInstance();
		Object[] retVal = TcTpmCmdDeprMisc.TpmOwnerReadPubek(dest, ownerAuth);

		return retVal;
	}

	/***************************************************************************
	 * This method returns the public portion of the endorsement key.
	 *
	 * @param hContext
	 * @param ownerAuth
	 * @throws TcTddlException,
	 *             TcTpmException
	 * @throws TcTcsException
	 */
	public static synchronized Object[] TcsipDisablePubekRead(long hContext,
			TcTcsAuth ownerAuth) throws TcTddlException, TcTpmException,
			TcTcsException {
		TcTcsContextMgr.checkContextHandle(hContext);
		CheckPrecondition.notNull(ownerAuth, "ownerAuth");
		TcTcsAuthCache.getInstance().ensureAuthsAreLoadedInTpm(
				new TcTcsAuth[] { ownerAuth });

		TcTddl dest = TcTddl.getInstance();
		Object[] retVal = TcTpmCmdDeprMisc.TpmDisablePubekRead(dest, ownerAuth);

		return retVal;
	}

	/***************************************************************************
	 * Vendor specific for Infineon 1.1b TPMs. This command reads the EK
	 * certificate from an Infineon 1.1b TPM.
	 *
	 * @param hContext
	 * @param index
	 * @param antiReplay
	 * @throws TcTddlException
	 * @throws TcTpmException
	 * @throws TcTcsException
	 */
	public static synchronized Object[] TcsipIfxReadTpm11EkCert(long hContext, byte index,
			TcBlobData antiReplay) throws TcTddlException, TcTpmException,
			TcTcsException {
		TcTcsContextMgr.checkContextHandle(hContext);

		TcTddl dest = TcTddl.getInstance();
		Object[] retVal = TcTpmCmdVendorSpecific.IfxReadTpm11EkCert(dest,
				index, antiReplay);

		return retVal;
	}

	// ==============================================================================================
	// functions not to be exported (according to TSS spec)

	public static synchronized Object[] TcsSHA1Start(long hContext)
			throws TcTddlException, TcTpmException, TcTcsException {
		TcTcsContextMgr.checkContextHandle(hContext);

		TcTddl dest = TcTddl.getInstance();

		Object[] retVal = TcTpmCmdCrypto.TpmSHA1Start(dest);

		return retVal;
	}

	public static synchronized Object[] TcsSHA1Update(long hContext,
			long numBytes, TcBlobData hashData) throws TcTddlException,
			TcTpmException, TcTcsException {
		TcTcsContextMgr.checkContextHandle(hContext);
		CheckPrecondition.notNull(hashData, "hashData");

		TcTddl dest = TcTddl.getInstance();

		Object[] retVal = TcTpmCmdCrypto
				.TpmSHA1Update(dest, numBytes, hashData);

		return retVal;
	}

	public static synchronized Object[] TcsSHA1Complete(long hContext,
			TcBlobData hashData) throws TcTddlException, TcTpmException,
			TcTcsException {
		TcTcsContextMgr.checkContextHandle(hContext);
		CheckPrecondition.notNull(hashData, "hashData");

		TcTddl dest = TcTddl.getInstance();

		Object[] retVal = TcTpmCmdCrypto.TpmSHA1Complete(dest, hashData);

		return retVal;
	}

	public static synchronized Object[] TcsSHA1CompleteExtend(long hContext,
			long pcrNum, TcBlobData hashData) throws TcTddlException,
			TcTpmException, TcTcsException {
		TcTcsContextMgr.checkContextHandle(hContext);
		CheckPrecondition.notNull(hashData, "hashData");

		TcTddl dest = TcTddl.getInstance();

		Object[] retVal = TcTpmCmdCrypto.TpmSHA1CompleteExtend(dest, pcrNum,
				hashData);

		return retVal;
	}

}
