/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.api.constants.tsp;


import iaik.tc.tss.api.constants.tcs.TcTcsErrors;
import iaik.tc.utils.misc.Utils;

/**
 * This class contains TSP level error codes. 
 */
public class TcTssErrors {

	// Making constructor unavailable.
	private TcTssErrors()
	{
	}

	/** definition for TPM layer */
	public static final long TSS_LAYER_TPM = TcTcsErrors.TSS_LAYER_TPM;

	/** definition for TDDL layer */
	public static final long TSS_LAYER_TDDL = TcTcsErrors.TSS_LAYER_TDDL;

	/** definition for TCS layer */
	public static final long TSS_LAYER_TCS = TcTcsErrors.TSS_LAYER_TCS;

	/** definition for TSP layer */
	public static final long TSS_LAYER_TSP = TcTcsErrors.TSS_LAYER_TSP;

	// definitions for the start points of layer specific error codes
	public static final long TSS_COMMON_OFFSET = 0x000L;

	public static final long TSS_TDDL_OFFSET = 0x080L;

	public static final long TSS_TCSI_OFFSET = 0x0C0L;

	public static final long TSS_TSPI_OFFSET = 0x100L;

	public static final long TSS_VENDOR_OFFSET = 0x800L;

	public static final long TSS_MAX_ERROR = 0xFFFL;

	public static final long TSS_LEVEL_SUCCESS = 0x00;

	public static final long TSS_LEVEL_INFO = 0x40000000L;

	public static final long TSS_LEVEL_WARNING = 0x80000000L;

	public static final long TSS_LEVEL_ERROR = 0xC0000000L;

	/**
	 * facility number for TCPA return codes
	 */
	public static final long FACILITY_TSS = 0x28L;

	/**
	 * shift the facility info to the code position
	 * 
	 */
	public static final long FACILITY_TSS_CODEPOS = FACILITY_TSS << 16;

	/**
	 * bit position for the custom flag in return code
	 */
	public static final long TSS_CUSTOM_CODEFLAG = 0x20000000L;

	/**
	 * TSS error return codes
	 */
	public static final long TSS_E_BASE = 0x00000000L;

	public static final long TSS_W_BASE = 0x00000000L;

	public static final long TSS_I_BASE = 0x00000000L;

	/**
	 * basic error return codes common to all TSS Service Provider Interface methods and returned by
	 * all TSS SW stack components
	 */

	/**
	 * Successful completion of the operation.
	 */
	public static final long TSS_SUCCESS = 0x00000000L;

	/**
	 * An internal error has been detected, but the source is unknown.
	 */
	public static final long TSS_E_FAIL = TSS_E_BASE + 0x002L;

	/**
	 * One or more parameter is bad.
	 */
	public static final long TSS_E_BAD_PARAMETER = TSS_E_BASE + 0x003L;

	/**
	 * An internal SW error has been detected.
	 */
	public static final long TSS_E_INTERNAL_ERROR = TSS_E_BASE + 0x004L;

	/**
	 * Ran out of memory.
	 */
	public static final long TSS_E_OUTOFMEMORY = TSS_E_BASE + 0x005L;

	/**
	 * Not implemented.
	 */
	public static final long TSS_E_NOTIMPL = TSS_E_BASE + 0x006L;

	/**
	 * Key is already registered
	 */
	public static final long TSS_E_KEY_ALREADY_REGISTERED = TSS_E_BASE + 0x008L;

	/**
	 * An unexpected TPM error has occurred.
	 */
	public static final long TSS_E_TPM_UNEXPECTED = TSS_E_BASE + 0x010L;

	/**
	 * A communications error with the TPM has been detected.
	 */
	public static final long TSS_E_COMM_FAILURE = TSS_E_BASE + 0x011L;

	/**
	 * The operation has timed out.
	 */
	public static final long TSS_E_TIMEOUT = TSS_E_BASE + 0x012L;

	/**
	 * The TPM does not support the requested feature.
	 */
	public static final long TSS_E_TPM_UNSUPPORTED_FEATURE = TSS_E_BASE + 0x014L;

	/**
	 * The action was canceled by request.
	 */
	public static final long TSS_E_CANCELED = TSS_E_BASE + 0x016L;

	/**
	 * The key cannot be found in the persistent storage database.
	 */
	public static final long TSS_E_PS_KEY_NOTFOUND = TSS_E_BASE + 0x020L;

	/**
	 * The key already exists in the persistent storage database.
	 */
	public static final long TSS_E_PS_KEY_EXISTS = TSS_E_BASE + 0x021L;

	/**
	 * The key data set not valid in the persistent storage database.
	 */
	public static final long TSS_E_PS_BAD_KEY_STATE = TSS_E_BASE + 0x022L;

	/*************************************************************************************************
	 * error codes returned by specific TSS Service Provider Interface methods offset TSS_TSPI_OFFSET
	 */

	/**
	 * Object type not valid for this operation.
	 */
	public static final long TSS_E_INVALID_OBJECT_TYPE = TSS_E_BASE + 0x101L;

	/**
	 * Core Service connection doesn't exist.
	 */
	public static final long TSS_E_NO_CONNECTION = TSS_E_BASE + 0x102L;

	/**
	 * Core Service connection failed.
	 */
	public static final long TSS_E_CONNECTION_FAILED = TSS_E_BASE + 0x103L;

	/**
	 * Communication with Core Service failed.
	 */
	public static final long TSS_E_CONNECTION_BROKEN = TSS_E_BASE + 0x104L;

	/**
	 * Invalid hash algorithm.
	 */
	public static final long TSS_E_HASH_INVALID_ALG = TSS_E_BASE + 0x105L;

	/**
	 * Hash length is inconsistent with hash algorithm.
	 */
	public static final long TSS_E_HASH_INVALID_LENGTH = TSS_E_BASE + 0x106L;

	/**
	 * Hash object has no internal hash value.
	 */
	public static final long TSS_E_HASH_NO_DATA = TSS_E_BASE + 0x107L;

	/**
	 * Flag value for attrib-functions inconsistent.
	 */
	public static final long TSS_E_INVALID_ATTRIB_FLAG = TSS_E_BASE + 0x109L;

	/**
	 * Subflag value for attrib-functions inconsistent.
	 */
	public static final long TSS_E_INVALID_ATTRIB_SUBFLAG = TSS_E_BASE + 0x10AL;

	/**
	 * Data for attrib-functions invalid.
	 */
	public static final long TSS_E_INVALID_ATTRIB_DATA = TSS_E_BASE + 0x10BL;

	/**
	 * Wrong flag information for object creation. The alternate spelling is supported to be
	 * compatible with a typo in the 1.1b header files.
	 */
	public static final long TSS_E_INVALID_OBJECT_INIT_FLAG = TSS_E_BASE + 0x10CL;

	public static final long TSS_E_INVALID_OBJECT_INITFLAG = TSS_E_INVALID_OBJECT_INIT_FLAG;

	/**
	 * No PCR register are selected or set.
	 */
	public static final long TSS_E_NO_PCRS_SET = TSS_E_BASE + 0x10DL;

	/**
	 * The addressed key is currently not loaded.
	 */
	public static final long TSS_E_KEY_NOT_LOADED = TSS_E_BASE + 0x10EL;

	/**
	 * No key information is currently available.
	 */
	public static final long TSS_E_KEY_NOT_SET = TSS_E_BASE + 0x10FL;

	/**
	 * Internal validation of data failed.
	 */
	public static final long TSS_E_VALIDATION_FAILED = TSS_E_BASE + 0x110L;

	/**
	 * Authorization is required.
	 */
	public static final long TSS_E_TSP_AUTHREQUIRED = TSS_E_BASE + 0x111L;

	/**
	 * Multiple authorization is required.
	 */
	public static final long TSS_E_TSP_AUTH2REQUIRED = TSS_E_BASE + 0x112L;

	/**
	 * Authorization failed.
	 */
	public static final long TSS_E_TSP_AUTHFAIL = TSS_E_BASE + 0x113L;

	/**
	 * Multiple authorization failed.
	 */
	public static final long TSS_E_TSP_AUTH2FAIL = TSS_E_BASE + 0x114L;

	/**
	 * There's no migration policy object set for the addressed key.
	 */
	public static final long TSS_E_KEY_NO_MIGRATION_POLICY = TSS_E_BASE + 0x115L;

	/**
	 * No secret information is currently available for the addressed policy object.
	 */
	public static final long TSS_E_POLICY_NO_SECRET = TSS_E_BASE + 0x116L;

	/**
	 * The operation failed due to an invalid object status.
	 */
	public static final long TSS_E_INVALID_OBJ_ACCESS = TSS_E_BASE + 0x117L;

	/**
	 * Invalid encryption scheme.
	 */
	public static final long TSS_E_INVALID_ENCSCHEME = TSS_E_BASE + 0x118L;

	/**
	 * Invalid signature scheme.
	 */
	public static final long TSS_E_INVALID_SIGSCHEME = TSS_E_BASE + 0x119L;

	/**
	 * Invalid length for encrypted data object.
	 */
	public static final long TSS_E_ENC_INVALID_LENGTH = TSS_E_BASE + 0x120L;

	/**
	 * Encrypted data object contains no data.
	 */
	public static final long TSS_E_ENC_NO_DATA = TSS_E_BASE + 0x121L;

	/**
	 * Invalid type for encrypted data object.
	 */
	public static final long TSS_E_ENC_INVALID_TYPE = TSS_E_BASE + 0x122L;

	/**
	 * Invalid usage of key.
	 */
	public static final long TSS_E_INVALID_KEYUSAGE = TSS_E_BASE + 0x123L;

	/**
	 * Internal validation of data failed.
	 */
	public static final long TSS_E_VERIFICATION_FAILED = TSS_E_BASE + 0x124L;

	/**
	 * Hash algorithm identifier not set.
	 */
	public static final long TSS_E_HASH_NO_IDENTIFIER = TSS_E_BASE + 0x125L;

	/**
	 * An invalid handle
	 */
	public static final long TSS_E_INVALID_HANDLE = TSS_E_BASE + 0x126L;

	/**
	 * A silent context requires user input
	 */
	public static final long TSS_E_SILENT_CONTEXT = TSS_E_BASE + 0x127L;

	/**
	 * TSP is instructed to verify the EK checksum and it does not verify.
	 */
	public static final long TSS_E_EK_CHECKSUM = TSS_E_BASE + 0x128L;

	/**
	 * The Policy object does not have a delegation blob set.
	 */
	public static final long TSS_E_DELEGATION_NOTSET = TSS_E_BASE + 0x129L;

	/**
	 * The specified delegation family was not found
	 */
	public static final long TSS_E_DELFAMILY_NOTFOUND = TSS_E_BASE + 0x130L;

	/**
	 * The specified delegation family table row is already in use and the command flags does not
	 * allow the TSS to overwrite the existing entry.
	 */
	public static final long TSS_E_DELFAMILY_ROWEXISTS = TSS_E_BASE + 0x131L;

	/**
	 * The specified delegation family table row is already in use and the command flags does not
	 * allow the TSS to overwrite the existing entry.
	 */
	public static final long TSS_E_VERSION_MISMATCH = TSS_E_BASE + 0x132L;

	/**
	 * Decryption of the encrypted pseudonym has failed, due to either a wrong secret key or a wrong
	 * decryption condition.
	 */
	public static final long TSS_E_DAA_AR_DECRYPTION_ERROR = TSS_E_BASE + 0x133L;

	/**
	 * The TPM could not be authenticated by the DAA Issuer.
	 */
	public static final long TSS_E_DAA_AUTHENTICATION_ERROR = TSS_E_BASE + 0x134L;

	/**
	 * DAA Challenge response error.
	 */
	public static final long TSS_E_DAA_CHALLENGE_RESPONSE_ERROR = TSS_E_BASE + 0x135L;

	/**
	 * Verification of the credential TSS_DAA_CRED_ISSUER issued by the DAA Issuer has failed.
	 */
	public static final long TSS_E_DAA_CREDENTIAL_PROOF_ERROR = TSS_E_BASE + 0x136L;

	/**
	 * Verification of the platform's credential request TSS_DAA_CREDENTIAL_REQUEST has failed.
	 */
	public static final long TSS_E_DAA_CREDENTIAL_REQUEST_PROOF_ERROR = TSS_E_BASE + 0x137L;

	/**
	 * DAA Issuer's authentication key chain could not be verified or is not correct.
	 */
	public static final long TSS_E_DAA_ISSUER_KEY_ERROR = TSS_E_BASE + 0x138L;

	/**
	 * While verifying the pseudonym of the TPM, the private key of the TPM was found on the rogue
	 * list.
	 */
	public static final long TSS_E_DAA_PSEUDONYM_ERROR = TSS_E_BASE + 0x139L;

	/**
	 * Pointer to memory wrong.
	 */
	public static final long TSS_E_INVALID_RESOURCE = TSS_E_BASE + 0x13AL;

	/**
	 * The NV area referenced already exists
	 */
	public static final long TSS_E_NV_AREA_EXIST = TSS_E_BASE + 0x13BL;

	/**
	 * The NV area referenced doesn't exist
	 */
	public static final long TSS_E_NV_AREA_NOT_EXIST = TSS_E_BASE + 0x13CL;

	/**
	 * The transport session authorization failed
	 */
	public static final long TSS_E_TSP_TRANS_AUTHFAIL = TSS_E_BASE + 0x13DL;

	/**
	 * Authorization for transport is required
	 */
	public static final long TSS_E_TSP_TRANS_AUTHREQUIRED = TSS_E_BASE + 0x13EL;

	/**
	 * A command was executed outside of an exclusive transport session.
	 */
	public static final long TSS_E_TSP_TRANS_NOTEXCLUSIVE = TSS_E_BASE + 0x13FL;

	/**
	 * Generic transport protection error.
	 */
	public static final long TSS_E_TSP_TRANS_FAIL = TSS_E_BASE + 0x140L;

	/**
	 * A command could not be executed through a logged transport session because the command used a
	 * key and the key's public key is not known to the TSP.
	 */
	public static final long TSS_E_TSP_TRANS_NO_PUBKEY = TSS_E_BASE + 0x141L;

	/**
	 * The TPM active counter has not been set yet.^M
	 */
	public static final long TSS_E_NO_ACTIVE_COUNTER = TSS_E_BASE + 0x142L;


	/*************************************************************************************************
	 * This method returns an error message including the error code, the error type and the error
	 * message.
	 * 
	 * @param errCode The error code to be translated into a text message.
	 */
	public static String errToString(final long errCode)
	{
		StringBuffer retVal = new StringBuffer();

		retVal.append("TSP error:");
		retVal.append(Utils.getNL());
		retVal.append("  error code: ");
		retVal.append(Utils.longToHex(errCode));
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
			case (int) TSS_SUCCESS:
				retVal = "Successful completion of the operation.";
				break;
			case (int) TSS_E_FAIL:
				retVal = "An internal error has been detected, but the source is unknown.";
				break;
			case (int) TSS_E_BAD_PARAMETER:
				retVal = "One or more parameter is bad.";
				break;
			case (int) TSS_E_INTERNAL_ERROR:
				retVal = "An internal SW error has been detected.";
				break;
			case (int) TSS_E_OUTOFMEMORY:
				retVal = "Ran out of memory.";
				break;
			case (int) TSS_E_NOTIMPL:
				retVal = "Not implemented.";
				break;
			case (int) TSS_E_KEY_ALREADY_REGISTERED:
				retVal = "Key is already registered";
				break;
			case (int) TSS_E_TPM_UNEXPECTED:
				retVal = "An unexpected TPM error has occurred.";
				break;
			case (int) TSS_E_COMM_FAILURE:
				retVal = "A communications error with the TPM has been detected.";
				break;
			case (int) TSS_E_TIMEOUT:
				retVal = "The operation has timed out.";
				break;
			case (int) TSS_E_TPM_UNSUPPORTED_FEATURE:
				retVal = "The TPM does not support the requested feature.";
				break;
			case (int) TSS_E_CANCELED:
				retVal = "The action was canceled by request.";
				break;
			case (int) TSS_E_PS_KEY_NOTFOUND:
				retVal = "The key cannot be found in the persistent storage database.";
				break;
			case (int) TSS_E_PS_KEY_EXISTS:
				retVal = "The key already exists in the persistent storage database.";
				break;
			case (int) TSS_E_PS_BAD_KEY_STATE:
				retVal = "The key data set not valid in the persistent storage database.";
				break;
			case (int) TSS_E_INVALID_OBJECT_TYPE:
				retVal = "Object type not valid for this operation.";
				break;
			case (int) TSS_E_NO_CONNECTION:
				retVal = "Core Service connection doesn't exist.";
				break;
			case (int) TSS_E_CONNECTION_FAILED:
				retVal = "Core Service connection failed.";
				break;
			case (int) TSS_E_CONNECTION_BROKEN:
				retVal = "Communication with Core Service failed.";
				break;
			case (int) TSS_E_HASH_INVALID_ALG:
				retVal = "Invalid hash algorithm.";
				break;
			case (int) TSS_E_HASH_INVALID_LENGTH:
				retVal = "Hash length is inconsistent with hash algorithm.";
				break;
			case (int) TSS_E_HASH_NO_DATA:
				retVal = "Hash object has no internal hash value.";
				break;
			case (int) TSS_E_INVALID_ATTRIB_FLAG:
				retVal = "Flag value for attrib-functions inconsistent.";
				break;
			case (int) TSS_E_INVALID_ATTRIB_SUBFLAG:
				retVal = "Subflag value for attrib-functions inconsistent.";
				break;
			case (int) TSS_E_INVALID_ATTRIB_DATA:
				retVal = "Data for attrib-functions invalid.";
				break;
			case (int) TSS_E_INVALID_OBJECT_INIT_FLAG:
				retVal = "Wrong flag information for object creation. The alternate spelling is supported to "
						+ "be compatible with a typo in the 1.1b header files.";
				break;
			case (int) TSS_E_NO_PCRS_SET:
				retVal = "No PCR register are selected or set.";
				break;
			case (int) TSS_E_KEY_NOT_LOADED:
				retVal = "The addressed key is currently not loaded.";
				break;
			case (int) TSS_E_KEY_NOT_SET:
				retVal = "No key information is currently available.";
				break;
			case (int) TSS_E_VALIDATION_FAILED:
				retVal = "Internal validation of data failed.";
				break;
			case (int) TSS_E_TSP_AUTHREQUIRED:
				retVal = "Authorization is required.";
				break;
			case (int) TSS_E_TSP_AUTH2REQUIRED:
				retVal = "Multiple authorization is required.";
				break;
			case (int) TSS_E_TSP_AUTHFAIL:
				retVal = "Authorization failed.";
				break;
			case (int) TSS_E_TSP_AUTH2FAIL:
				retVal = "Multiple authorization failed.";
				break;
			case (int) TSS_E_KEY_NO_MIGRATION_POLICY:
				retVal = "There's no migration policy object set for the addressed key.";
				break;
			case (int) TSS_E_POLICY_NO_SECRET:
				retVal = "No secret information is currently available for the addressed policy object.";
				break;
			case (int) TSS_E_INVALID_OBJ_ACCESS:
				retVal = "The operation failed due to an invalid object status.";
				break;
			case (int) TSS_E_INVALID_ENCSCHEME:
				retVal = "Invalid encryption scheme";
				break;
			case (int) TSS_E_INVALID_SIGSCHEME:
				retVal = "Invalid signature scheme";
				break;
			case (int) TSS_E_ENC_INVALID_LENGTH:
				retVal = "Invalid signature scheme";
				break;
			case (int) TSS_E_ENC_NO_DATA:
				retVal = "Encrypted data object contains no data";
				break;
			case (int) TSS_E_ENC_INVALID_TYPE:
				retVal = "Invalid type for encrypted data object";
				break;
			case (int) TSS_E_INVALID_KEYUSAGE:
				retVal = "Invalid usage of key";
				break;
			case (int) TSS_E_VERIFICATION_FAILED:
				retVal = "Internal validation of data failed";
				break;
			case (int) TSS_E_HASH_NO_IDENTIFIER:
				retVal = "Hash algorithm identifier not set.";
				break;
			case (int) TSS_E_INVALID_HANDLE:
				retVal = "An invalid handle";
				break;
			case (int) TSS_E_SILENT_CONTEXT:
				retVal = "A silent context requires user input";
				break;
			case (int) TSS_E_EK_CHECKSUM:
				retVal = "TSP is instructed to verify the EK checksum and it does not verify.";
				break;
			case (int) TSS_E_DELEGATION_NOTSET:
				retVal = "The Policy object does not have a delegation blob set.";
				break;
			case (int) TSS_E_DELFAMILY_NOTFOUND:
				retVal = "The specified delegation family was not found";
				break;
			case (int) TSS_E_DELFAMILY_ROWEXISTS:
				retVal = "The specified delegation family table row is already in use and the command flags does "
						+ "not allow the TSS to overwrite the existing entry.";
				break;
			case (int) TSS_E_VERSION_MISMATCH:
				retVal = "The specified delegation family table row is already in use and the command flags does "
						+ "not allow the TSS to overwrite the existing entry.";
				break;
			case (int) TSS_E_DAA_AR_DECRYPTION_ERROR:
				retVal = "Decryption of the encrypted pseudonym has failed, due to either a wrong secret key or a "
						+ "wrong decryption condition.";
				break;
			case (int) TSS_E_DAA_AUTHENTICATION_ERROR:
				retVal = "The TPM could not be authenticated by the DAA Issuer.";
				break;
			case (int) TSS_E_DAA_CHALLENGE_RESPONSE_ERROR:
				retVal = "DAA Challenge response error.";
				break;
			case (int) TSS_E_DAA_CREDENTIAL_PROOF_ERROR:
				retVal = "Verification of the credential TSS_DAA_CRED_ISSUER issued by the DAA Issuer has failed.";
				break;
			case (int) TSS_E_DAA_CREDENTIAL_REQUEST_PROOF_ERROR:
				retVal = "Verification of the platform's credential request TSS_DAA_CREDENTIAL_REQUEST has failed.";
				break;
			case (int) TSS_E_DAA_ISSUER_KEY_ERROR:
				retVal = "DAA Issuer's authentication key chain could not be verified or is not correct.";
				break;
			case (int) TSS_E_DAA_PSEUDONYM_ERROR:
				retVal = "While verifying the pseudonym of the TPM, the private key of the TPM was found on the "
						+ "rogue list.";
				break;
			case (int) TSS_E_INVALID_RESOURCE:
				retVal = "Pointer to memory wrong.";
				break;
			case (int) TSS_E_NV_AREA_EXIST:
				retVal = "The NV area referenced already exists";
				break;
			case (int) TSS_E_NV_AREA_NOT_EXIST:
				retVal = "The NV area referenced doesn't exist";
				break;
			case (int) TSS_E_TSP_TRANS_AUTHFAIL:
				retVal = "The transport session authorization failed";
				break;
			case (int) TSS_E_TSP_TRANS_AUTHREQUIRED:
				retVal = "Authorization for transport is required";
				break;
			case (int) TSS_E_TSP_TRANS_NOTEXCLUSIVE:
				retVal = "A command was executed outside of an exclusive transport session.";
				break;
			case (int) TSS_E_TSP_TRANS_FAIL:
				retVal = "Generic transport protection error.";
				break;
			case (int) TSS_E_TSP_TRANS_NO_PUBKEY:
				retVal = "A command could not be executed through a logged transport session because the command used a key and the key's public key is not known to the TSP.";
				break;
			case (int) TSS_E_NO_ACTIVE_COUNTER:
				retVal = "The TPM active counter has not been set yet.";
				break;
				}

		return retVal;
	}

}
