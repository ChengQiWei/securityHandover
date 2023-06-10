/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.api.exceptions.common;


import iaik.tc.tss.api.constants.tcs.TcTcsErrors;
import iaik.tc.tss.api.exceptions.tcs.TcTpmException;
import iaik.tc.utils.misc.Utils;

/**
 * This exception forms the base for all other TSS exceptions. It holds the error code as specified
 * by the TCG and the corresponding error message. Error codes, as defined by the TSS spec are 32bit
 * unsigned integer values. Bits 16 to 31 are reserved for OS specific error coded. Bits 12 to 15
 * specify the TSS layer the error comes from. This can be {@link TcTcsErrors#TSS_LAYER_TPM},
 * {@link TcTcsErrors#TSS_LAYER_TDDL}, {@link TcTcsErrors#TSS_LAYER_TCS} or
 * {@link TcTcsErrors#TSS_LAYER_TSP}. To get the layer the exception belongs to, use the
 * {@link TcTssException#getErrLayer()} method. Bits 0 to 11 finally define the actual error code.
 * Use {@link TcTssException#getErrCode()} to get this value. To obtain the full error code (not
 * decomposed into its individual parts), use the {@link TcTssException#getErrCodeFull()} method.
 * <br>
 * Note that this class is an abstract class which means that this exception can not be thrown
 * directly. Instead of that, for every TSS layer a specific exception is defined that inherits
 * from this exception (e.g. {@link TcTpmException}. That means when catching a TcTssException,
 * the layer the exception comes from can be determine by using the instanceOf operation instead
 * of using the {@link TcTssException#getErrLayer()} method.
 */
public abstract class TcTssException extends Exception {

	private static final long serialVersionUID = 1L;

	/**
	 * Full error code.
	 */
	protected long errCodeFull_ = 0;

	/**
	 * OS specific error code.
	 */
	protected long errOsSpecific_ = 0;

	/**
	 * TSS error layer.
	 */
	protected long errLayer_ = 0;

	/**
	 * TCG defined error code.
	 */
	protected long errCode_ = 0;

	/**
	 * Error message.
	 */
	protected String message_ = "";


	/*************************************************************************************************
	 * This constructor takes the error code that is represented by this exception. The error message
	 * is looked up based on this error code.
	 * 
	 * @param errCode The error code represented by the exception.
	 */
	public TcTssException(final long errCode)
	{
		errCodeFull_ = errCode;
		errOsSpecific_ = errCode & 0xffff0000;
		errLayer_ = errCode & 0x0000f000;
		errCode_ = errCode & 0x00000fff;
		message_ = Utils.getNL() + errToString(null);
	}


	/*************************************************************************************************
	 * This constructor takes the error code that is represented by this exception. The error message
	 * is looked up based on this error code. Additionally, a custom error message is appended to this
	 * default error message.
	 * 
	 * @param errCode The error code represented by the exception.
	 * @param message Additional error message.
	 */
	public TcTssException(final long errCode, String message)
	{
		this(errCode);

		message_ = errToString(message);
	}


	/*************************************************************************************************
	 * This method returns the error layer represented by this exception.
	 */
	public long getErrLayer()
	{
		return errLayer_;
	}


	/*************************************************************************************************
	 * This method returns the error code represented by this exception. Note that the layer part has
	 * already been removed from this error code. To get the error layer use the
	 * {@link TcTssException#getErrLayer()} method.
	 */
	public long getErrCode()
	{
		return errCode_;
	}


	/*************************************************************************************************
	 * This method returns the OS specific part of the error code. This will be all zeros most of the
	 * time. Deprecated due to spelling error.
	 */
	@Deprecated
	public long getErrOsSpeific()
	{
		return errOsSpecific_;
	}

	/*************************************************************************************************
	 * This method returns the OS specific part of the error code. This will be all zeros most of the
	 * time.
	 */
	public long getErrOsSpecific()
	{
		return errOsSpecific_;
	}

	
	/*************************************************************************************************
	 * This method returns the full error code. That is the error code NOT decomposed into individual
	 * parts (OS specific, layer, code).
	 */
	public long getErrCodeFull()
	{
		return errCodeFull_;
	}


	/*************************************************************************************************
	 * Returns the error message.
	 */
	public String getMessage()
	{
		return message_;
	}


	/*************************************************************************************************
	 * This method is used internally to get the error message that belongs to the error code. This
	 * method has to be implemented by child classes.  
	 */
	protected abstract String getErrMsg();


	/*************************************************************************************************
	 * This method returns a string representation of the error code and its corresponding error
	 * message.
	 */
	protected String errToString(String additionalMsg)
	{
		StringBuffer retVal = new StringBuffer();

		String strLayer = null;
		switch ((int) errLayer_) {
			case (int) TcTcsErrors.TSS_LAYER_TPM:
				strLayer = "TPM";
				break;
			case (int) TcTcsErrors.TSS_LAYER_TDDL:
				strLayer = "TDDL";
				break;
			case (int) TcTcsErrors.TSS_LAYER_TCS:
				strLayer = "TCS";
				break;
			case (int) TcTcsErrors.TSS_LAYER_TSP:
				strLayer = "TSP";
				break;

			default:
				break;
		}

		retVal.append(Utils.getNL());
		retVal.append("TSS Error:");
		retVal.append(Utils.getNL());

		retVal.append("error layer:                ");
		retVal.append(Utils.longToHex(errLayer_));
		retVal.append(" (");
		retVal.append(strLayer);
		retVal.append(")");
		retVal.append(Utils.getNL());

		retVal.append("error code (without layer): ");
		retVal.append(Utils.longToHex(errCode_));
		retVal.append(Utils.getNL());

		retVal.append("error code (full):          ");
		retVal.append(Utils.longToHex(errCodeFull_));
		retVal.append(Utils.getNL());

		retVal.append("error message: ");
		retVal.append(getErrMsg());
		retVal.append(Utils.getNL());

		if (additionalMsg != null) {
			retVal.append("additional info: ");
			retVal.append(additionalMsg);
			retVal.append(Utils.getNL());
		}

		return retVal.toString();
	}

}
