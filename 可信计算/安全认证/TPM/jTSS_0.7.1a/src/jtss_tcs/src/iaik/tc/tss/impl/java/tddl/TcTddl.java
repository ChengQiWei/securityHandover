/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.impl.java.tddl;

import iaik.tc.tss.api.constants.tcs.TcTddlErrors;
import iaik.tc.tss.api.constants.tpm.TcTpmConstants;
import iaik.tc.tss.api.constants.tpm.TcTpmOrdinals;
import iaik.tc.tss.api.exceptions.tcs.TcTcsException;
import iaik.tc.tss.api.exceptions.tcs.TcTddlException;
import iaik.tc.tss.api.exceptions.tcs.TcTpmException;
import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.tss.api.structs.tpm.TcTpmKeyHandleList;
import iaik.tc.tss.impl.java.tcs.TcTcsCommon;
import iaik.tc.tss.impl.java.tcs.TcTcsProperties;
import iaik.tc.tss.impl.java.tcs.authmgr.TcTcsAuthCache;
import iaik.tc.tss.impl.java.tcs.pbg.TcTpmCmdCapability;
import iaik.tc.tss.impl.java.tcs.pbg.TcTpmCmdDeprMisc;
import iaik.tc.tss.impl.java.tcs.pbg.TcTpmCmdEviction;
import iaik.tc.tss.impl.java.tcs.sessmgr.TcTcsSessManager;
import iaik.tc.utils.logging.Log;
import iaik.tc.utils.logging.LogLevels;
import iaik.tc.utils.misc.OsDetection;

/**
 * This class defines the interface to be implemented by the TDDL layer
 * according to the TSS specification. The set of functions can be split into 2
 * parts: Those functions absolutely required if the TDDL is used by a TSS (the
 * functions comprise open, isOpen, transmit and close) and the functions that
 * are required if the TDDL is used as a standalone facility. These functions
 * comprise the remaining TDDL functions specified by the TSS specification. For
 * that reason, TDDL implementations might be limited to the aforementioned set
 * of absolutely required functions.
 * 
 */
public abstract class TcTddl implements TcIStreamDest {

	/** Singleton pattern: The TDDL instance. */
	protected static TcTddl tddl_ = null;

	private static boolean created = false;

	private static void createInstance() throws TcTddlException {
		// maybe we have already an instance but initialization failed
		if (tddl_ == null) {
			// check if there is an implementation selected in the ini file
			String tddlClassName = "";

			try {
				tddlClassName = TcTcsProperties.getInstance().getProperty(
						TcTcsProperties.TCS_INI_SEC_TDDL,
						TcTcsProperties.TCS_INI_KEY_TDDL_TDDLIMPLEMENTATION);

				if (tddlClassName != "") {

					tddl_ = (TcTddl) Class.forName(tddlClassName).newInstance();
					tddl_.open();
				}

			} catch (TcTcsException e) {
				Log.info("Unable to open TCS configuration file for TDDL implementation settings.");
				tddl_ = null;
			} catch (Exception e) {
				Log.info("Unable to instantiate TDDL implementation ("
						+ tddlClassName
						+ "). Check the TCS configuration file.");
				tddl_ = null;
			}
		}

		if (tddl_ == null) {
			// no implementation was selected in the .ini file. Therefore start
			// autodetection
			if (OsDetection.operatingSystemIs(OsDetection.OS_LINUX)) {
				tddl_ = new TcTddlLinux();
				// TODO make this a config option for debugging
				Log.setLogLevel(TcTddlLinux.class, LogLevels.INFO);
			} else if (OsDetection.operatingSystemIsWindows()) {
				tddl_ = new TcTddlVista();
			} else {
				String msg = "This operating system currently is not supported "
						+ "(os.name: " + System.getProperty("os.name") + ").";
				Log.err(msg);

				// There is no point in trying this again if OS is not supported
				created = true;

				throw new TcTddlException(TcTddlErrors.TDDL_E_FAIL, msg);
			}
		}

		try {
			if (tddl_ == null) {
				// tddl_ cannot be null, but better be safe than sorry
				throw new TcTddlException(TcTddlErrors.TDDL_E_FAIL,
						"tddl_ is null - this should never happen");
			} else if (!tddl_.isOpen()) {
				tddl_.open();
			}
		} catch (TcTddlException e) {
			tddl_ = null;
			throw e;
		}

		initializeTPM();
		created = true;
	}

	/***************************************************************************
	 * The TDDL layer is implemented as a Singleton. This method returns the
	 * instance of the TDDL.
	 * 
	 * @return TDDL instance.
	 * 
	 * @throws TcTddlException
	 *             This exception is thrown if no TDDL implementation that fits
	 *             the underlying operating system could be found.
	 */
	public static TcTddl getInstance() throws TcTddlException {
		if (!created) {
			createInstance();
		}

		if (tddl_ == null) {
			// createInstance() was not able to create a TDDL in a previous run
			// usually this should result in an earlier exception which reveals
			// the actual cause.
			throw new TcTddlException(TcTddlErrors.TDDL_E_FAIL,
					"no instance found");
		}

		return tddl_;
	}

	/***************************************************************************
	 * This method ensures that the connection to the TPM device is closed upon
	 * garbage collection.
	 */
	protected void finalize() throws Throwable {
		close();
	}

	/**
	 * This replaces a static block in TcTcsi found in previous versions of
	 * jTSS.<br>
	 * Since jTSS is the only entity in control of a TPM, we clear all stored
	 * sessions when we take over.
	 */
	private static void initializeTPM() throws TcTddlException {
		if (tddl_ == null) {
			// do not call this method before creating an instance!
			throw new TcTddlException(TcTddlErrors.TDDL_E_FAIL,
					"no TDDL instance - should not happen");
		}

		// Note: TPM Emu from ETHZ has some problems with 1.2 session
		// management.
		// Therefore 1.1 reset is used.

		try {
			if (TcTcsCommon.isOrdinalSupported(tddl_, TcTpmOrdinals.TPM_ORD_SaveContext)
					&& !TcTcsCommon.tpmManufacturerIs(tddl_, TcTcsCommon.TPM_MAN_ETHZ)) {
				// reset TPM resources (TPM 1.2)
				TcTcsSessManager.getInstance().evictAllSavedSessions(tddl_);
				evictAllAuthSessions();
			} else if (TcTcsCommon.isOrdinalSupported(tddl_, TcTpmOrdinals.TPM_ORD_Reset)
					|| TcTcsCommon.tpmManufacturerIs(tddl_, TcTcsCommon.TPM_MAN_ETHZ)) {
				// reset TPM resources (TPM 1.1)
				TcTpmCmdDeprMisc.TpmReset(tddl_);
			} else {
				Log.warn("Unable to reset TPM resources.");
			}
		} catch (TcTpmException e) {
			throw new TcTddlException(TcTddlErrors.TDDL_E_FAIL,
					"TcTpmException: " + e.getMessage());
		}
	}

	/**
	 * since we can't rely on higher level API methods we have to provide this
	 * here ourself.
	 * 
	 * @see {@link TcTcsAuthCache#evictAllAuthSessions()}
	 */
	private static void evictAllAuthSessions() throws TcTddlException,
			TcTpmException {
		// First: check which method to use:
		// taken from TcTcsAuthCache.getInstance()
		if (!(tddl_ instanceof TcTddlSocket)
				&& (OsDetection.operatingSystemIsWindows())) {
			// TcTcsAuthCacheVista();
			// do nothing
		} else {
			if (TcTcsCommon.isOrdinalSupported(tddl_,
					TcTpmOrdinals.TPM_ORD_LoadContext)) {
				// TcTcsAuthCacheTpm12();

				// Second: evictAllAuthSessions()

				TcBlobData subCap = TcBlobData
						.newUINT32(TcTpmConstants.TPM_RT_AUTH);
				Object[] tpmOutData = TcTpmCmdCapability.TpmGetCapability(
						tddl_, TcTpmConstants.TPM_CAP_HANDLE, subCap);

				TcTpmKeyHandleList savedSessions = new TcTpmKeyHandleList(
						(TcBlobData) tpmOutData[1]);
				for (int i = 0; i < savedSessions.getHandle().length; i++) {
					TcTpmCmdEviction.TpmFlushSpecific(tddl_,
							savedSessions.getHandle()[i],
							TcTpmConstants.TPM_RT_AUTH);
				}
			} else {
				// TcTcsAuthCacheTpm11() or TcTcsAuthCacheTpm11NoSwap();
				// do nothing
			}
		}
	}

	// set of required functions (includes transmit defined in the implemented
	// interface)

	public abstract void open() throws TcTddlException;

	public abstract boolean isOpen();

	public abstract void close() throws TcTddlException;

	// set of "not required" functions in case the TDDL is used by a TSS

	public abstract void cancel() throws TcTddlException;

	public abstract void getCapability() throws TcTddlException;

	public abstract void setCapability() throws TcTddlException;

	public abstract void getStatus() throws TcTddlException;

	public abstract void setStatus() throws TcTddlException;

	public abstract void powerManagement() throws TcTddlException;

	public abstract void powerManagementControl() throws TcTddlException;

}
