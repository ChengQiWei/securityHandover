/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.api.constants.tcs;


import iaik.tc.utils.misc.Utils;

public class TcTddlErrors {

	// Making constructor unavailable
	private TcTddlErrors()
	{
	}


	/* TDDL Errors Codes */

	public static final long TDDL_E_FAIL = TcTcsErrors.TSS_E_BASE + 0x002L;

	public static final long TDDL_E_TIMEOUT = TcTcsErrors.TSS_E_BASE + 0x012L;

	/**
	 * The connection was already established.
	 */
	public static final long TDDL_E_ALREADY_OPENED = TcTcsErrors.TSS_E_BASE + 0x081L;

	/**
	 * The device was not connected.
	 */
	public static final long TDDL_E_ALREADY_CLOSED = TcTcsErrors.TSS_E_BASE + 0x082L;

	/**
	 * The receive buffer is too small.
	 */
	public static final long TDDL_E_INSUFFICIENT_BUFFER = TcTcsErrors.TSS_E_BASE + 0x083L;

	/**
	 * The command has already completed.
	 */
	public static final long TDDL_E_COMMAND_COMPLETED = TcTcsErrors.TSS_E_BASE + 0x084L;

	/**
	 * TPM aborted processing of command.
	 */
	public static final long TDDL_E_COMMAND_ABORTED = TcTcsErrors.TSS_E_BASE + 0x085L;

	/**
	 * The request could not be performed because of an I/O device error.
	 */
	public static final long TDDL_E_IOERROR = TcTcsErrors.TSS_E_BASE + 0x087L;

	/**
	 * Unsupported TAG is requested
	 */
	public static final long TDDL_E_BADTAG = TcTcsErrors.TSS_E_BASE + 0x088L;

	/**
	 * the requested TPM component was not found
	 */
	public static final long TDDL_E_COMPONENT_NOT_FOUND = TcTcsErrors.TSS_E_BASE + 0x089L;

	
	/*************************************************************************************************
	 * This method returns an error message including the error code, the error type and the error
	 * message.
	 */
	public static String errToString(final long errCode)
	{
		StringBuffer retVal = new StringBuffer();

		retVal.append("TDDL error:");
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

			case (int) TDDL_E_ALREADY_OPENED:
				retVal = "The connection was already established.";
				break;
			case (int) TDDL_E_ALREADY_CLOSED:
				retVal = "The device was not connected.";
				break;
			case (int) TDDL_E_INSUFFICIENT_BUFFER:
				retVal = "The receive buffer is too small.";
				break;
			case (int) TDDL_E_COMMAND_COMPLETED:
				retVal = "The command has already completed.";
				break;
			case (int) TDDL_E_COMMAND_ABORTED:
				retVal = "TPM aborted processing of command.";
				break;
			case (int) TDDL_E_IOERROR:
				retVal = "The request could not be performed because of an IO device error.";
				break;
			case (int) TDDL_E_BADTAG:
				retVal = "Unsupported TAG is requested";
				break;
			case (int) TDDL_E_COMPONENT_NOT_FOUND:
				retVal = "The requested TPM component was not found";
				break;
		}
		
		return retVal;
	}

}
