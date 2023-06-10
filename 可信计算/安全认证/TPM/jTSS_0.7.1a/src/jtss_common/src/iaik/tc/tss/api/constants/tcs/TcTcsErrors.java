/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.api.constants.tcs;


import iaik.tc.utils.misc.Utils;

public class TcTcsErrors {

	// Making constructor unavailable
	private TcTcsErrors()
	{
	}

	/** definition for TPM layer */
	public static final long TSS_LAYER_TPM = 0x0000L;

	/** definition for TDDL layer */
	public static final long TSS_LAYER_TDDL = 0x1000L;

	/** definition for TCS layer */
	public static final long TSS_LAYER_TCS = 0x2000L;

	/** definition for TSP layer */
	public static final long TSS_LAYER_TSP = 0x3000L;

	/** error code base */
	protected static final long TSS_E_BASE = 0x00000000L; // duplicated from TcTssErrors

	/**
	 * The context handle supplied is invalid.
	 */
	public static final long TCS_E_INVALID_CONTEXTHANDLE = TSS_E_BASE + 0x0C1L;

	/**
	 * The key handle supplied is invalid.
	 */
	public static final long TCS_E_INVALID_KEYHANDLE = TSS_E_BASE + 0x0C2L;

	/**
	 * The authorization session handle supplied is invalid.
	 */
	public static final long TCS_E_INVALID_AUTHHANDLE = TSS_E_BASE + 0x0C3L;

	/**
	 * The auth session has been closed by the TPM
	 */
	public static final long TCS_E_INVALID_AUTHSESSION = TSS_E_BASE + 0x0C4L;

	/**
	 * The key has been unloaded.
	 */
	public static final long TCS_E_INVALID_KEY = TSS_E_BASE + 0x0C5L;

	/**
	 * Key addressed by the application key handle does not match the key addressed by the given UUID.
	 */
	public static final long TCS_E_KEY_MISMATCH = TSS_E_BASE + 0x0C8L;

	/**
	 * Key addressed by Key's UUID cannot be loaded because one of the required parent keys needs
	 * authorization.
	 */
	public static final long TCS_E_KM_LOADFAILED = TSS_E_BASE + 0x0CAL;

	/**
	 * The Key Cache Manager could not reload the key into the TPM.
	 */
	public static final long TCS_E_KEY_CONTEXT_RELOAD = TSS_E_BASE + 0x0CCL;

	/**
	 * Bad memory index
	 */
	public static final long TCS_E_BAD_INDEX = TSS_E_BASE + 0x0CDL;

	/**
	 * These TCS_E_ macros are defined by name in the TSS spec, however they are defined to have the
	 * same values as the TSS_E_ equivalents.
	 */
	public static final long TCS_SUCCESS = 0x00000000L;

	public static final long TCS_E_KEY_ALREADY_REGISTERED = TSS_E_BASE + 0x008L;

	// Note: TSS_E_KEY_NOT_REGISTERED is missing in the TCG header files
	// public static final long TCS_E_KEY_NOT_REGISTERED = TcTssErrors.TSS_E_KEY_NOT_REGISTERED;
	// for the time being, jTSS defines an own value for this constant:
	public static final long TCS_E_KEY_NOT_REGISTERED = TSS_E_BASE + 0x009L;
	
	public static final long TCS_E_BAD_PARAMETER = TSS_E_BASE + 0x003L;

	public static final long TCS_E_OUTOFMEMORY = TSS_E_BASE + 0x005L;

	// Note: TSS_E_SIZE is missing in the TCG header files
	// public static final long TCS_E_SIZE = TcTssErrors.TSS_E_SIZE;

	public static final long TCS_E_NOTIMPL = TSS_E_BASE + 0x006L;

	public static final long TCS_E_INTERNAL_ERROR = TSS_E_BASE + 0x004L;

	// TSS_E_FAIL is returned by the TrouSerS TCS; therefore it is added to this file although it is
	// not part of the TCG header files.
	public static final long TCS_E_FAIL = TSS_E_BASE + 0x002L;


	/*************************************************************************************************
	 * This method returns an error message including the error code, the error type and the error
	 * message.
	 */
	public static String errToString(final long errCode)
	{
		StringBuffer retVal = new StringBuffer();

		retVal.append("TCS error:");
		retVal.append(Utils.getNL());
		retVal.append("  error code: ");
		retVal.append(Utils.longToHex(errCode));
		retVal.append(Utils.getNL());
		retVal.append("  error message: ");
		retVal.append(getErrMsg(errCode));
		retVal.append(Utils.getNL());

		return retVal.toString();
	}


	/*************************************************************************************************
	 * This method returns the error string for the given error code.
	 */
	public static String getErrMsg(final long errCode)
	{
		String retVal = "unknown";

		switch ((int) errCode) {
			case (int) TCS_E_INVALID_CONTEXTHANDLE:
				retVal = "The context handle supplied is invalid.";
				break;
			case (int) TCS_E_INVALID_KEYHANDLE:
				retVal = "The key handle supplied is invalid.";
				break;
			case (int) TCS_E_INVALID_AUTHHANDLE:
				retVal = "The authorization session handle supplied is invalid.";
				break;
			case (int) TCS_E_INVALID_AUTHSESSION:
				retVal = "The auth session has been closed by the TPM";
				break;
			case (int) TCS_E_INVALID_KEY:
				retVal = "The key has been unloaded.";
				break;
			case (int) TCS_E_KEY_MISMATCH:
				retVal = "Key addressed by the application key handle does not match the key addressed by the given UUID.";
				break;
			case (int) TCS_E_KM_LOADFAILED:
				retVal = "Key addressed by Key's UUID cannot be loaded because one of the required parent keys needs authorization.";
				break;
			case (int) TCS_E_KEY_CONTEXT_RELOAD:
				retVal = "The Key Cache Manager could not reload the key into the TPM.";
				break;
			case (int) TCS_E_BAD_INDEX:
				retVal = "Bad memory index";
				break;
			case (int) TCS_E_NOTIMPL:
				retVal = "Functionality is not implemented";
				break;
			case (int) TCS_E_FAIL:
				retVal = "An internal error has been detected, but the source is unknown. (TCS_E_FAIL)";
				break;
			case (int) TCS_SUCCESS:
				retVal = "Success.";
				break;
		}

		return retVal;
	}

}
