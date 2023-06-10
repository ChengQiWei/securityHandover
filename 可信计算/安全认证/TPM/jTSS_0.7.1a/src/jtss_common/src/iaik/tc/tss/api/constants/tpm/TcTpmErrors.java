/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.api.constants.tpm;


import iaik.tc.utils.misc.Utils;


/**
 * This class contains error codes returned by the TPM to indicate error conditions. 
 */
public class TcTpmErrors {

	// Making constructor unavailable.
	private TcTpmErrors()
	{
	}

	/* TPM Errors Codes */

	public static final long TPM_E_BASE = 0;

	public static final long TPM_E_NON_FATAL = 0x00000800;

	/** Successful completion of the TPM operation. */
	public static final long TPM_SUCCESS = TPM_E_BASE;

	/** Authentication failed */
	public static final long TPM_E_AUTHFAIL = TPM_E_BASE + 0x00000001;

	/** The index to a PCR, DIR or other register is incorrect */
	public static final long TPM_E_BADINDEX = TPM_E_BASE + 0x00000002;

	/** One or more parameter is bad */
	public static final long TPM_E_BAD_PARAMETER = TPM_E_BASE + 0x00000003;

	/**
	 * An operation completed successfully but the auditing of that operation failed.
	 */
	public static final long TPM_E_AUDITFAILURE = TPM_E_BASE + 0x00000004;

	/**
	 * The clear disable flag is set and all clear operations now require physical access
	 */
	public static final long TPM_E_CLEAR_DISABLED = TPM_E_BASE + 0x00000005;

	/** The TPM is deactivated */
	public static final long TPM_E_DEACTIVATED = TPM_E_BASE + 0x00000006;

	/** The TPM is disabled */
	public static final long TPM_E_DISABLED = TPM_E_BASE + 0x00000007;

	/** The target command has been disabled */
	public static final long TPM_E_DISABLED_CMD = TPM_E_BASE + 0x00000008;

	/** The operation failed */
	public static final long TPM_E_FAIL = TPM_E_BASE + 0x00000009;

	/** The ordinal was unknown or inconsistent */
	public static final long TPM_E_BAD_ORDINAL = TPM_E_BASE + 0x0000000a;

	/** The ability to install an owner is disabled */
	public static final long TPM_E_INSTALL_DISABLED = TPM_E_BASE + 0x0000000b;

	/** The key handle can not be interpreted */
	public static final long TPM_E_INVALID_KEYHANDLE = TPM_E_BASE + 0x0000000c;

	/** The key handle points to an invalid key */
	public static final long TPM_E_KEYNOTFOUND = TPM_E_BASE + 0x0000000d;

	/** Unacceptable encryption scheme */
	public static final long TPM_E_INAPPROPRIATE_ENC = TPM_E_BASE + 0x0000000e;

	/** Migration authorization failed */
	public static final long TPM_E_MIGRATEFAIL = TPM_E_BASE + 0x0000000f;

	/** PCR information could not be interpreted */
	public static final long TPM_E_INVALID_PCR_INFO = TPM_E_BASE + 0x00000010;

	/** No room to load key. */
	public static final long TPM_E_NOSPACE = TPM_E_BASE + 0x00000011;

	/** There is no SRK set */
	public static final long TPM_E_NOSRK = TPM_E_BASE + 0x00000012;

	/** An encrypted blob is invalid or was not created by this TPM */
	public static final long TPM_E_NOTSEALED_BLOB = TPM_E_BASE + 0x00000013;

	/** There is already an Owner */
	public static final long TPM_E_OWNER_SET = TPM_E_BASE + 0x00000014;

	/**
	 * The TPM has insufficient internal resources to perform the requested action.
	 */
	public static final long TPM_E_RESOURCES = TPM_E_BASE + 0x00000015;

	/** A random string was too short */
	public static final long TPM_E_SHORTRANDOM = TPM_E_BASE + 0x00000016;

	/** The TPM does not have the space to perform the operation. */
	public static final long TPM_E_SIZE = TPM_E_BASE + 0x00000017;

	/** The named PCR value does not match the current PCR value. */
	public static final long TPM_E_WRONGPCRVAL = TPM_E_BASE + 0x00000018;

	/** The paramSize argument to the command has the incorrect value */
	public static final long TPM_E_BAD_PARAM_SIZE = TPM_E_BASE + 0x00000019;

	/** There is no existing SHA-1 thread. */
	public static final long TPM_E_SHA_THREAD = TPM_E_BASE + 0x0000001a;

	/**
	 * The calculation is unable to proceed because the existing SHA-1 thread has already encountered
	 * an error.
	 */
	public static final long TPM_E_SHA_ERROR = TPM_E_BASE + 0x0000001b;

	/** Self-test has failed and the TPM has shutdown. */
	public static final long TPM_E_FAILEDSELFTEST = TPM_E_BASE + 0x0000001c;

	/**
	 * The authorization for the second key in a 2 key function failed authorization
	 */
	public static final long TPM_E_AUTH2FAIL = TPM_E_BASE + 0x0000001d;

	/** The tag value sent to for a command is invalid */
	public static final long TPM_E_BADTAG = TPM_E_BASE + 0x0000001e;

	/** An IO error occurred transmitting information to the TPM */
	public static final long TPM_E_IOERROR = TPM_E_BASE + 0x0000001f;

	/** The encryption process had a problem. */
	public static final long TPM_E_ENCRYPT_ERROR = TPM_E_BASE + 0x00000020;

	/** The decryption process did not complete. */
	public static final long TPM_E_DECRYPT_ERROR = TPM_E_BASE + 0x00000021;

	/** An invalid handle was used. */
	public static final long TPM_E_INVALID_AUTHHANDLE = TPM_E_BASE + 0x00000022;

	/** The TPM has no EK installed */
	public static final long TPM_E_NO_ENDORSEMENT = TPM_E_BASE + 0x00000023;

	/** The usage of a key is not allowed */
	public static final long TPM_E_INVALID_KEYUSAGE = TPM_E_BASE + 0x00000024;

	/** The submitted entity type is not allowed */
	public static final long TPM_E_WRONG_ENTITYTYPE = TPM_E_BASE + 0x00000025;

	/**
	 * The command was received in the wrong sequence relative to TPM_Init and a subsequent
	 * TPM_Startup
	 */
	public static final long TPM_E_INVALID_POSTINIT = TPM_E_BASE + 0x00000026;

	/** Signed data cannot include additional DER information */
	public static final long TPM_E_INAPPROPRIATE_SIG = TPM_E_BASE + 0x00000027;

	/** The key properties in TPM_KEY_PARMs are not supported by this TPM */
	public static final long TPM_E_BAD_KEY_PROPERTY = TPM_E_BASE + 0x00000028;

	/** The migration properties of this key are incorrect. */
	public static final long TPM_E_BAD_MIGRATION = TPM_E_BASE + 0x00000029;

	/**
	 * The signature or encryption scheme for this key is incorrect or not permitted in this
	 * situation.
	 */
	public static final long TPM_E_BAD_SCHEME = TPM_E_BASE + 0x0000002a;

	/**
	 * The size of the data (or blob) parameter is bad or inconsistent with the referenced key
	 */
	public static final long TPM_E_BAD_DATASIZE = TPM_E_BASE + 0x0000002b;

	/**
	 * A mode parameter is bad, such as capArea or subCapArea for TPM_GetCapability, physicalPresence
	 * parameter for TPM_PhysicalPresence, or migrationType for TPM_CreateMigrationBlob.
	 */
	public static final long TPM_E_BAD_MODE = TPM_E_BASE + 0x0000002c;

	/**
	 * Either the physicalPresence or physicalPresenceLock bits have the wrong value
	 */
	public static final long TPM_E_BAD_PRESENCE = TPM_E_BASE + 0x0000002d;

	/** The TPM cannot perform this version of the capability */
	public static final long TPM_E_BAD_VERSION = TPM_E_BASE + 0x0000002e;

	/** The TPM does not allow for wrapped transport sessions */
	public static final long TPM_E_NO_WRAP_TRANSPORT = TPM_E_BASE + 0x0000002f;

	/**
	 * TPM audit construction failed and the underlying command was returning a failure code also
	 */
	public static final long TPM_E_AUDITFAIL_UNSUCCESSFUL = TPM_E_BASE + 0x00000030;

	/**
	 * TPM audit construction failed and the underlying command was returning success
	 */
	public static final long TPM_E_AUDITFAIL_SUCCESSFUL = TPM_E_BASE + 0x00000031;

	/**
	 * Attempt to reset a PCR register that does not have the resettable attribute
	 */
	public static final long TPM_E_NOTRESETABLE = TPM_E_BASE + 0x00000032;

	/**
	 * Attempt to reset a PCR register that requires locality and locality modifier not part of
	 * command transport
	 */
	public static final long TPM_E_NOTLOCAL = TPM_E_BASE + 0x00000033;

	/** Make identity blob not properly typed */
	public static final long TPM_E_BAD_TYPE = TPM_E_BASE + 0x00000034;

	/**
	 * When saving context identified resource type does not match actual resource
	 */
	public static final long TPM_E_INVALID_RESOURCE = TPM_E_BASE + 0x00000035;

	/**
	 * The TPM is attempting to execute a command only available when in FIPS mode
	 */
	public static final long TPM_E_NOTFIPS = TPM_E_BASE + 0x00000036;

	/** The command is attempting to use an invalid family ID */
	public static final long TPM_E_INVALID_FAMILY = TPM_E_BASE + 0x00000037;

	/** The permission to manipulate the NV storage is not available */
	public static final long TPM_E_NO_NV_PERMISSION = TPM_E_BASE + 0x00000038;

	/** The operation requires a signed command */
	public static final long TPM_E_REQUIRES_SIGN = TPM_E_BASE + 0x00000039;

	/** Wrong operation to load an NV key */
	public static final long TPM_E_KEY_NOTSUPPORTED = TPM_E_BASE + 0x0000003a;

	/** NV_LoadKey blob requires both owner and blob authorization */
	public static final long TPM_E_AUTH_CONFLICT = TPM_E_BASE + 0x0000003b;

	/** The NV area is locked and not writable */
	public static final long TPM_E_AREA_LOCKED = TPM_E_BASE + 0x0000003c;

	/** The locality is incorrect for the attempted operation */
	public static final long TPM_E_BAD_LOCALITY = TPM_E_BASE + 0x0000003d;

	/** The NV area is read only and can't be written to */
	public static final long TPM_E_READ_ONLY = TPM_E_BASE + 0x0000003e;

	/** There is no protection on the write to the NV area */
	public static final long TPM_E_PER_NOWRITE = TPM_E_BASE + 0x0000003f;

	/** The family count value does not match */
	public static final long TPM_E_FAMILYCOUNT = TPM_E_BASE + 0x00000040;

	/** The NV area has already been written to */
	public static final long TPM_E_WRITE_LOCKED = TPM_E_BASE + 0x00000041;

	/** The NV area attributes conflict */
	public static final long TPM_E_BAD_ATTRIBUTES = TPM_E_BASE + 0x00000042;

	/** The structure tag and version are invalid or inconsistent */
	public static final long TPM_E_INVALID_STRUCTURE = TPM_E_BASE + 0x00000043;

	/**
	 * The key is under control of the TPM Owner and can only be evicted by the TPM Owner.
	 */
	public static final long TPM_E_KEY_OWNER_CONTROL = TPM_E_BASE + 0x00000044;

	/** The counter handle is incorrect */
	public static final long TPM_E_BAD_COUNTER = TPM_E_BASE + 0x00000045;

	/** The write is not a complete write of the area */
	public static final long TPM_E_NOT_FULLWRITE = TPM_E_BASE + 0x00000046;

	/** The gap between saved context counts is too large */
	public static final long TPM_E_CONTEXT_GAP = TPM_E_BASE + 0x00000047;

	/** The maximum number of NV writes without an owner has been exceeded */
	public static final long TPM_E_MAXNVWRITES = TPM_E_BASE + 0x00000048;

	/** No operator AuthData value is set */
	public static final long TPM_E_NOOPERATOR = TPM_E_BASE + 0x00000049;

	/** The resource pointed to by context is not loaded */
	public static final long TPM_E_RESOURCEMISSING = TPM_E_BASE + 0x0000004a;

	/** The delegate administration is locked */
	public static final long TPM_E_DELEGATE_LOCK = TPM_E_BASE + 0x0000004b;

	/** Attempt to manage a family other then the delegated family */
	public static final long TPM_E_DELEGATE_FAMILY = TPM_E_BASE + 0x0000004c;

	/** Delegation table management not enabled */
	public static final long TPM_E_DELEGATE_ADMIN = TPM_E_BASE + 0x0000004d;

	/** There was a command executed outside of an exclusive transport session */
	public static final long TPM_E_TRANSPORT_NOTEXCLUSIVE = TPM_E_BASE + 0x0000004e;

	/** Attempt to context save a owner evict controlled key */
	public static final long TPM_E_OWNER_CONTROL = TPM_E_BASE + 0x0000004f;

	/** The DAA command has no resources available to execute the command */
	public static final long TPM_E_DAA_RESOURCES = TPM_E_BASE + 0x00000050;

	/** The consistency check on DAA parameter inputData0 has failed. */
	public static final long TPM_E_DAA_INPUT_DATA0 = TPM_E_BASE + 0x00000051;

	/** The consistency check on DAA parameter inputData1 has failed. */
	public static final long TPM_E_DAA_INPUT_DATA1 = TPM_E_BASE + 0x00000052;

	/** The consistency check on DAA_issuerSettings has failed. */
	public static final long TPM_E_DAA_ISSUER_SETTINGS = TPM_E_BASE + 0x00000053;

	/** The consistency check on DAA_tpmSpecific has failed. */
	public static final long TPM_E_DAA_TPM_SETTINGS = TPM_E_BASE + 0x00000054;

	/**
	 * The atomic process indicated by the submitted DAA command is not the expected process.
	 */
	public static final long TPM_E_DAA_STAGE = TPM_E_BASE + 0x00000055;

	/** The issuer's validity check has detected an inconsistency */
	public static final long TPM_E_DAA_ISSUER_VALIDITY = TPM_E_BASE + 0x00000056;

	/** The consistency check on w has failed. */
	public static final long TPM_E_DAA_WRONG_W = TPM_E_BASE + 0x00000057;

	/** The handle is incorrect */
	public static final long TPM_E_BAD_HANDLE = TPM_E_BASE + 0x00000058;

	/** Delegation is not correct */
	public static final long TPM_E_BAD_DELEGATE = TPM_E_BASE + 0x00000059;

	/** The context blob is invalid */
	public static final long TPM_E_BADCONTEXT = TPM_E_BASE + 0x0000005a;

	/** Too many contexts held by the TPM */
	public static final long TPM_E_TOOMANYCONTEXTS = TPM_E_BASE + 0x0000005b;

	/** Migration authority signature validation failure */
	public static final long TPM_E_MA_TICKET_SIGNATURE = TPM_E_BASE + 0x0000005c;

	/** Migration destination not authenticated */
	public static final long TPM_E_MA_DESTINATION = TPM_E_BASE + 0x0000005d;

	/** Migration source incorrect */
	public static final long TPM_E_MA_SOURCE = TPM_E_BASE + 0x0000005e;

	/** Incorrect migration authority */
	public static final long TPM_E_MA_AUTHORITY = TPM_E_BASE + 0x0000005f;

	/** Attempt to revoke the EK and the EK is not revocable */
	public static final long TPM_E_PERMANENTEK = TPM_E_BASE + 0x00000061;

	/** Bad signature of CMK ticket */
	public static final long TPM_E_BAD_SIGNATURE = TPM_E_BASE + 0x00000062;

	/** There is no room in the context list for additional contexts */
	public static final long TPM_E_NOCONTEXTSPACE = TPM_E_BASE + 0x00000063;

	/**
	 * The TPM is too busy to respond to the command immediately, but the command could be resubmitted
	 * at a later time. The TPM MAY return TPM_Retry for any command at any time.
	 */
	public static final long TPM_E_RETRY = TPM_E_BASE + TPM_E_NON_FATAL;

	/** SelfTestFull has not been run */
	public static final long TPM_E_NEEDS_SELFTEST = TPM_E_BASE + TPM_E_NON_FATAL + 1;

	/** The TPM is currently executing a full self test */
	public static final long TPM_E_DOING_SELFTEST = TPM_E_BASE + TPM_E_NON_FATAL + 2;

	/**
	 * The TPM is defending against dictionary attacks and is in some time-out period.
	 */
	public static final long TPM_E_DEFEND_LOCK_RUNNING = TPM_E_BASE + TPM_E_NON_FATAL + 3;

	/* NON-TCG TPM Error codes */
	
	/** This error code is returned by the TBS of Windows Vista if a command is blocked by the TBS. */
	public static final long TPM_E_TBS_COMMAND_BLOCKED = 0x80280400;
	
	
	
	/* TPM Error Code Decoding */

	// The following error type flags are not TCG specified
	/** Unknown error type. */
	public static final long ERR_TYPE_UNKNOWN = 0x0;

	/** No Error (TPM success) */
	public static final long ERR_TYPE_TPM_SUCCESS = 0x1;

	/** Fatal TPM defined error. */
	public static final long ERR_TYPE_TPM_FATAL = 0x11;

	/** Fatal vendor defined error. */
	public static final long ERR_TYPE_TPM_NONFATAL = 0x12;

	/** Non-fatal TPM defined error. */
	public static final long ERR_TYPE_VENDOR_FATAL = 0x21;

	/** Non-fatal vendor defined error. */
	public static final long ERR_TYPE_VENDOR_NONFATAL = 0x22;


	/*************************************************************************************************
	 * This method takes an error received from the TPM and returns the specific type of the error
	 * (one of ERR_TYPE_XXX). Not that ERR_TYPE_XXX are not TCG constants. The error ranges are define
	 * in the Return Codes chapter of the TPM specification.
	 */
	public static long getErrorType(final long errCode)
	{
		long errType = ERR_TYPE_UNKNOWN;

		if (errCode == TPM_SUCCESS) {
			errType = ERR_TYPE_TPM_SUCCESS;
		} else if (errCode >= 0x00000001 && errCode <= 0x000003ff) {
			errType = ERR_TYPE_TPM_FATAL;
		} else if (errCode >= 0x00000400 && errCode <= 0x000007ff) {
			errType = ERR_TYPE_VENDOR_FATAL;
		} else if (errCode >= 0x00000800 && errCode <= 0x00000bff) {
			errType = ERR_TYPE_TPM_NONFATAL;
		} else if (errCode >= 0x00000c00 && errCode <= 0x00000fff) {
			errType = ERR_TYPE_VENDOR_NONFATAL;
		}

		return errType;
	}


	/*************************************************************************************************
	 * This method takes an error received from the TPM and returns a String representation the
	 * specific type of the error.
	 */
	public static String getErrorTypeAsString(final long errCode)
	{
		String retVal;

		switch ((int) getErrorType(errCode)) {
			case ((int) ERR_TYPE_TPM_SUCCESS):
				retVal = "success";
				break;
			case ((int) ERR_TYPE_TPM_FATAL):
				retVal = "TPM (TCG) defined fatal error";
				break;
			case ((int) ERR_TYPE_VENDOR_FATAL):
				retVal = "Vendor defined fatal error";
				break;
			case ((int) ERR_TYPE_TPM_NONFATAL):
				retVal = "TPM (TCG) defined non-fatal error";
				break;
			case ((int) ERR_TYPE_VENDOR_NONFATAL):
				retVal = "Vendor defined non-fatal error";
				break;
			default:
				retVal = "unknown";
		}

		return retVal;
	}


	/*************************************************************************************************
	 * This method returns an error message including the error code, the error type and the error
	 * message.
	 */
	public static String errToString(final long errCode)
	{
		StringBuffer retVal = new StringBuffer();

		retVal.append("TPM error: ");
		retVal.append(Utils.getNL());
		retVal.append("  error code: ");
		retVal.append(Utils.longToHex(errCode));
		retVal.append(Utils.getNL());
		retVal.append("  error type: ");
		retVal.append(getErrorTypeAsString(errCode));
		retVal.append(Utils.getNL());
		retVal.append("  error text: ");
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
			case (int) TPM_SUCCESS:
				retVal = "Success.";
				break;
			case (int) TPM_E_AUTHFAIL:
				retVal = "Authentication failed";
				break;
			case (int) TPM_E_BADINDEX:
				retVal = "The index to a PCR, DIR or other register is incorrect";
				break;
			case (int) TPM_E_BAD_PARAMETER:
				retVal = "One or more parameter is bad";
				break;
			case (int) TPM_E_AUDITFAILURE:
				retVal = "An operation completed successfully but the auditing of that operation failed.";
				break;
			case (int) TPM_E_CLEAR_DISABLED:
				retVal = "The clear disable flag is set and all clear operations now require physical access";
				break;
			case (int) TPM_E_DEACTIVATED:
				retVal = "The TPM is deactivated";
				break;
			case (int) TPM_E_DISABLED:
				retVal = "The TPM is disabled";
				break;
			case (int) TPM_E_DISABLED_CMD:
				retVal = "The target command has been disabled";
				break;
			case (int) TPM_E_FAIL:
				retVal = "The operation failed";
				break;
			case (int) TPM_E_BAD_ORDINAL:
				retVal = "The ordinal was unknown or inconsistent";
				break;
			case (int) TPM_E_INSTALL_DISABLED:
				retVal = "The ability to install an owner is disabled";
				break;
			case (int) TPM_E_INVALID_KEYHANDLE:
				retVal = "The key handle can not be interpreted";
				break;
			case (int) TPM_E_KEYNOTFOUND:
				retVal = "The key handle points to an invalid key";
				break;
			case (int) TPM_E_INAPPROPRIATE_ENC:
				retVal = "Unacceptable encryption scheme";
				break;
			case (int) TPM_E_MIGRATEFAIL:
				retVal = "Migration authorization failed";
				break;
			case (int) TPM_E_INVALID_PCR_INFO:
				retVal = "PCR information could not be interpreted";
				break;
			case (int) TPM_E_NOSPACE:
				retVal = "No room to load key.";
				break;
			case (int) TPM_E_NOSRK:
				retVal = "There is no SRK set";
				break;
			case (int) TPM_E_NOTSEALED_BLOB:
				retVal = "An encrypted blob is invalid or was not created by this TPM";
				break;
			case (int) TPM_E_OWNER_SET:
				retVal = "There is already an Owner";
				break;
			case (int) TPM_E_RESOURCES:
				retVal = "The TPM has insufficient internal resources to perform the requested action.";
				break;
			case (int) TPM_E_SHORTRANDOM:
				retVal = "A random string was too short";
				break;
			case (int) TPM_E_SIZE:
				retVal = "The TPM does not have the space to perform the operation.";
				break;
			case (int) TPM_E_WRONGPCRVAL:
				retVal = "The named PCR value does not match the current PCR value.";
				break;
			case (int) TPM_E_BAD_PARAM_SIZE:
				retVal = "The paramSize argument to the command has the incorrect value";
				break;
			case (int) TPM_E_SHA_THREAD:
				retVal = "There is no existing SHA-1 thread.";
				break;
			case (int) TPM_E_SHA_ERROR:
				retVal = "The calculation is unable to proceed because the existing SHA-1 thread has already encountered an error.";
				break;
			case (int) TPM_E_FAILEDSELFTEST:
				retVal = "Self-test has failed and the TPM has shutdown.";
				break;
			case (int) TPM_E_AUTH2FAIL:
				retVal = "The authorization for the second key in a 2 key function failed authorization";
				break;
			case (int) TPM_E_BADTAG:
				retVal = "The tag value sent to for a command is invalid";
				break;
			case (int) TPM_E_IOERROR:
				retVal = "An IO error occurred transmitting information to the TPM";
				break;
			case (int) TPM_E_ENCRYPT_ERROR:
				retVal = "The encryption process had a problem.";
				break;
			case (int) TPM_E_DECRYPT_ERROR:
				retVal = "The decryption process did not complete.";
				break;
			case (int) TPM_E_INVALID_AUTHHANDLE:
				retVal = "An invalid handle was used.";
				break;
			case (int) TPM_E_NO_ENDORSEMENT:
				retVal = "The TPM has no EK installed";
				break;
			case (int) TPM_E_INVALID_KEYUSAGE:
				retVal = "The usage of a key is not allowed";
				break;
			case (int) TPM_E_WRONG_ENTITYTYPE:
				retVal = "The submitted entity type is not allowed";
				break;
			case (int) TPM_E_INVALID_POSTINIT:
				retVal = "The command was received in the wrong sequence relative to TPM_Init and a subsequent TPM_Startup";
				break;
			case (int) TPM_E_INAPPROPRIATE_SIG:
				retVal = "Signed data cannot include additional DER information";
				break;
			case (int) TPM_E_BAD_KEY_PROPERTY:
				retVal = "The key properties in TPM_KEY_PARMs are not supported by this TPM";
				break;
			case (int) TPM_E_BAD_MIGRATION:
				retVal = "The migration properties of this key are incorrect.";
				break;
			case (int) TPM_E_BAD_SCHEME:
				retVal = "The signature or encryption scheme for this key is incorrect or not permitted in this situation.";
				break;
			case (int) TPM_E_BAD_DATASIZE:
				retVal = "The size of the data (or blob) parameter is bad or inconsistent with the referenced key";
				break;
			case (int) TPM_E_BAD_MODE:
				retVal = "A mode parameter is bad, such as capArea or subCapArea for TPM_GetCapability, physicalPresence parameter for TPM_PhysicalPresence, or migrationType for TPM_CreateMigrationBlob.";
				break;
			case (int) TPM_E_BAD_PRESENCE:
				retVal = "Either the physicalPresence or physicalPresenceLock bits have the wrong value";
				break;
			case (int) TPM_E_BAD_VERSION:
				retVal = "The TPM cannot perform this version of the capability";
				break;
			case (int) TPM_E_NO_WRAP_TRANSPORT:
				retVal = "The TPM does not allow for wrapped transport sessions";
				break;
			case (int) TPM_E_AUDITFAIL_UNSUCCESSFUL:
				retVal = "TPM audit construction failed and the underlying command was returning a failure code also";
				break;
			case (int) TPM_E_AUDITFAIL_SUCCESSFUL:
				retVal = "TPM audit construction failed and the underlying command was returning success";
				break;
			case (int) TPM_E_NOTRESETABLE:
				retVal = "Attempt to reset a PCR register that does not have the resettable attribute";
				break;
			case (int) TPM_E_NOTLOCAL:
				retVal = "Attempt to reset a PCR register that requires locality and locality modifier not part of command transport";
				break;
			case (int) TPM_E_BAD_TYPE:
				retVal = "Make identity blob not properly typed";
				break;
			case (int) TPM_E_INVALID_RESOURCE:
				retVal = "When saving context identified resource type does not match actual resource";
				break;
			case (int) TPM_E_NOTFIPS:
				retVal = "The TPM is attempting to execute a command only available when in FIPS mode";
				break;
			case (int) TPM_E_INVALID_FAMILY:
				retVal = "The command is attempting to use an invalid family ID";
				break;
			case (int) TPM_E_NO_NV_PERMISSION:
				retVal = "The permission to manipulate the NV storage is not available";
				break;
			case (int) TPM_E_REQUIRES_SIGN:
				retVal = "The operation requires a signed command";
				break;
			case (int) TPM_E_KEY_NOTSUPPORTED:
				retVal = "Wrong operation to load an NV key";
				break;
			case (int) TPM_E_AUTH_CONFLICT:
				retVal = "NV_LoadKey blob requires both owner and blob authorization";
				break;
			case (int) TPM_E_AREA_LOCKED:
				retVal = "The NV area is locked and not writable";
				break;
			case (int) TPM_E_BAD_LOCALITY:
				retVal = "The locality is incorrect for the attempted operation";
				break;
			case (int) TPM_E_READ_ONLY:
				retVal = "The NV area is read only and can't be written to";
				break;
			case (int) TPM_E_PER_NOWRITE:
				retVal = "There is no protection on the write to the NV area";
				break;
			case (int) TPM_E_FAMILYCOUNT:
				retVal = "The family count value does not match";
				break;
			case (int) TPM_E_WRITE_LOCKED:
				retVal = "The NV area has already been written to";
				break;
			case (int) TPM_E_BAD_ATTRIBUTES:
				retVal = "The NV area attributes conflict";
				break;
			case (int) TPM_E_INVALID_STRUCTURE:
				retVal = "The structure tag and version are invalid or inconsistent";
				break;
			case (int) TPM_E_KEY_OWNER_CONTROL:
				retVal = "The key is under control of the TPM Owner and can only be evicted by the TPM Owner.";
				break;
			case (int) TPM_E_BAD_COUNTER:
				retVal = "The counter handle is incorrect";
				break;
			case (int) TPM_E_NOT_FULLWRITE:
				retVal = "The write is not a complete write of the area";
				break;
			case (int) TPM_E_CONTEXT_GAP:
				retVal = "The gap between saved context counts is too large";
				break;
			case (int) TPM_E_MAXNVWRITES:
				retVal = "The maximum number of NV writes without an owner has been exceeded";
				break;
			case (int) TPM_E_NOOPERATOR:
				retVal = "No operator AuthData value is set";
				break;
			case (int) TPM_E_RESOURCEMISSING:
				retVal = "The resource pointed to by context is not loaded";
				break;
			case (int) TPM_E_DELEGATE_LOCK:
				retVal = "The delegate administration is locked";
				break;
			case (int) TPM_E_DELEGATE_FAMILY:
				retVal = "Attempt to manage a family other then the delegated family";
				break;
			case (int) TPM_E_DELEGATE_ADMIN:
				retVal = "Delegation table management not enabled";
				break;
			case (int) TPM_E_TRANSPORT_NOTEXCLUSIVE:
				retVal = "There was a command executed outside of an exclusive transport session";
				break;
			case (int) TPM_E_OWNER_CONTROL:
				retVal = "Attempt to context save a owner evict controlled key";
				break;
			case (int) TPM_E_DAA_RESOURCES:
				retVal = "The DAA command has no resources available to execute the command";
				break;
			case (int) TPM_E_DAA_INPUT_DATA0:
				retVal = "The consistency check on DAA parameter inputData0 has failed.";
				break;
			case (int) TPM_E_DAA_INPUT_DATA1:
				retVal = "The consistency check on DAA parameter inputData1 has failed.";
				break;
			case (int) TPM_E_DAA_ISSUER_SETTINGS:
				retVal = "The consistency check on DAA_issuerSettings has failed.";
				break;
			case (int) TPM_E_DAA_TPM_SETTINGS:
				retVal = "The consistency check on DAA_tpmSpecific has failed.";
				break;
			case (int) TPM_E_DAA_STAGE:
				retVal = "The atomic process indicated by the submitted DAA command is not the expected process.";
				break;
			case (int) TPM_E_DAA_ISSUER_VALIDITY:
				retVal = "The issuer's validity check has detected an inconsistency";
				break;
			case (int) TPM_E_DAA_WRONG_W:
				retVal = "The consistency check on w has failed.";
				break;
			case (int) TPM_E_BAD_HANDLE:
				retVal = "The handle is incorrect";
				break;
			case (int) TPM_E_BAD_DELEGATE:
				retVal = "Delegation is not correct";
				break;
			case (int) TPM_E_BADCONTEXT:
				retVal = "The context blob is invalid";
				break;
			case (int) TPM_E_TOOMANYCONTEXTS:
				retVal = "Too many contexts held by the TPM";
				break;
			case (int) TPM_E_MA_TICKET_SIGNATURE:
				retVal = "Migration authority signature validation failure";
				break;
			case (int) TPM_E_MA_DESTINATION:
				retVal = "Migration destination not authenticated";
				break;
			case (int) TPM_E_MA_SOURCE:
				retVal = "Migration source incorrect";
				break;
			case (int) TPM_E_MA_AUTHORITY:
				retVal = "Incorrect migration authority";
				break;
			case (int) TPM_E_PERMANENTEK:
				retVal = "Attempt to revoke the EK and the EK is not revocable";
				break;
			case (int) TPM_E_BAD_SIGNATURE:
				retVal = "Bad signature of CMK ticket";
				break;
			case (int) TPM_E_NOCONTEXTSPACE:
				retVal = "There is no room in the context list for additional contexts";
				break;
			case (int) TPM_E_RETRY:
				retVal = "The TPM is too busy to respond to the command immediately, but the command could be resubmitted at a later time. The TPM MAY return TPM_Retry for any command at any time.";
				break;
			case (int) TPM_E_NEEDS_SELFTEST:
				retVal = "SelfTestFull has not been run";
				break;
			case (int) TPM_E_DOING_SELFTEST:
				retVal = "The TPM is currently executing a full self test";
				break;
			case (int) TPM_E_DEFEND_LOCK_RUNNING:
				retVal = "The TPM is defending against dictionary attacks and is in some time-out period.";
				break;
			case (int) TPM_E_TBS_COMMAND_BLOCKED:
				retVal = "Windows Vista TBS error: The requested TPM command is blocked. To use it, unblock it in the TPM Management Console or the Group Policies.";
				break;
		}

		return retVal;
	}

}
