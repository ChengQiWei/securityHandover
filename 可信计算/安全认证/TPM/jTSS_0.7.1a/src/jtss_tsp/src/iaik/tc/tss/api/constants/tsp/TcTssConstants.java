/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.api.constants.tsp;


import iaik.tc.tss.api.constants.tpm.TcTpmConstants;
import iaik.tc.tss.api.structs.common.TcBlobData;

/**
 * This class provides all the constants defined by the TCG for the TSS software stack.
 */
public class TcTssConstants {

	// ////////////////////////////////////////////////////////////////////////
	// Additional Defines (not in TSS Spec)
	// ////////////////////////////////////////////////////////////////////////

	/** Handle specifying NULL object. */
	public static final long NULL_HOBJECT = 0x0;

	/** Handle specifying NULL key. */
	public static final long NULL_HKEY = NULL_HOBJECT;

	// ////////////////////////////////////////////////////////////////////////
	// definition of the object types that can be created via CreateObject
	// ////////////////////////////////////////////////////////////////////////

	/** Policy object. */
	public static final long TSS_OBJECT_TYPE_POLICY = 0x01;

	/** RSA key object. */
	public static final long TSS_OBJECT_TYPE_RSAKEY = 0x02;

	/** Encrypted data object. */
	public static final long TSS_OBJECT_TYPE_ENCDATA = 0x03;

	/** PCR composite object. */
	public static final long TSS_OBJECT_TYPE_PCRS = 0x04;

	/** Hash object. */
	public static final long TSS_OBJECT_TYPE_HASH = 0x05;

	// ////////////////////////////////////////////////////////////////////////
	// CreateObject: Flags
	// ////////////////////////////////////////////////////////////////////////

	// for RSAKEY object:

	// Authorization:
	// Never |0 0|
	// Always |0 1|

	/** Key needs no authorization (DEFAULT). */
	public static final long TSS_KEY_NO_AUTHORIZATION = 0x00000000;

	/** Key needs authorization. */
	public static final long TSS_KEY_AUTHORIZATION = 0x00000001;

	// Volatility
	// Non Volatile |0|
	// Volatile |1|

	/** Key is non-volatile. MAY be unloaded at startup. */
	public static final long TSS_KEY_NON_VOLATILE = 0x00000000;

	/** Key is volatile. MUST be unloaded at startup. */
	public static final long TSS_KEY_VOLATILE = 0x00000004;

	// Migration:
	// Non Migratable |0|
	// Migratable |1|

	/** Key is not migratable (DEFAULT). */
	public static final long TSS_KEY_NOT_MIGRATABLE = 0x00000000;

	/** Key is migratable. */
	public static final long TSS_KEY_MIGRATABLE = 0x00000008;

	// Default = Legacy; |0 0 0 0|
	// Signing |0 0 0 1|
	// Storage |0 0 1 0|
	// Identity |0 0 1 0|
	// AuthChange |0 1 0 0|
	// Bind |0 1 0 1|
	// Legacy |0 1 1 0|

	/** Default key (legacy key) */
	public static final long TSS_KEY_TYPE_DEFAULT = 0x00000000;

	/** Key for signing operations. */
	public static final long TSS_KEY_TYPE_SIGNING = 0x00000010;

	/** Key for wrapping keys. */
	public static final long TSS_KEY_TYPE_STORAGE = 0x00000020;

	/** Key for an identity. */
	public static final long TSS_KEY_TYPE_IDENTITY = 0x00000030;

	/** An ephemeral key used to change authorization value. */
	public static final long TSS_KEY_TYPE_AUTHCHANGE = 0x00000040;

	/** Binding Key for TPM binding operations. */
	public static final long TSS_KEY_TYPE_BIND = 0x00000050;

	/** Key that can perform signing and binding. */
	public static final long TSS_KEY_TYPE_LEGACY = 0x00000060;

	/** Key that can act as a CMK MA */
	public static final long TSS_KEY_TYPE_MIGRATE = 0x00000070;

	// Size:
	// 512 |0 0 0 1|
	// 1024 |0 0 1 0|
	// 2048 |0 0 1 1|
	// 4096 |0 1 0 0|
	// 8192 |0 1 0 1|
	// 16286 |0 1 1 0|

	/** Key size 512 bits. */
	public static final long TSS_KEY_SIZE_512 = 0x00000100;

	/** Key size 1024 bits. */
	public static final long TSS_KEY_SIZE_1024 = 0x00000200;

	/** Key size 2048 bits. */
	public static final long TSS_KEY_SIZE_2048 = 0x00000300;

	/** Key size 4096 bits. */
	public static final long TSS_KEY_SIZE_4096 = 0x00000400;

	/** Key size 8192 bits. */
	public static final long TSS_KEY_SIZE_8192 = 0x00000500;

	/** Key size 16384 bits. */
	public static final long TSS_KEY_SIZE_16384 = 0x00000600;

	// fixed KeyTypes = templates;
	// Reserved: |0 0 0 0 0 0 0 0 0 0 0 0 0 0|
	// Empty Key |0 0 0 0 0 0|
	// Storage root key |0 0 0 0 0 1|

	/** no TCG key template (empty TSP key object) */
	public static final long TSS_KEY_EMPTY_KEY = 0x00000000;

	/** use a TCG SRK template (TSP key object for SRK) */
	public static final long TSS_KEY_TSP_SRK = 0x04000000;

	// Flags for ENCDATA:
	// Seal |0 0 1|
	// Bind |0 1 0|
	// Legacy |0 1 1|

	/** Data object is used for seal operation. */
	public static final long TSS_ENCDATA_SEAL = 0x00000001;

	/** Data object is used for bind operation. */
	public static final long TSS_ENCDATA_BIND = 0x00000002;

	/** Data for legacy bind operation. */
	public static final long TSS_ENCDATA_LEGACY = 0x00000003;

	// Flags for POLICY:
	// Usage |0 1|
	// Migration |1 0|

	/** Policy object used for (usage) authorization. */
	public static final long TSS_POLICY_USAGE = 0x00000001;

	/** Policy object used for migration. */
	public static final long TSS_POLICY_MIGRATION = 0x00000002;

	// Flags for HASH:
	// Algorithm:
	// DEFAULT
	// |0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0|
	// SHA1
	// |0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1|
	// OTHER
	// |1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1|

	/** Default hash algorithm. */
	public static final long TSS_HASH_DEFAULT = 0x00000000;

	/** Hash object with algorithm SHA1. */
	public static final long TSS_HASH_SHA1 = 0x00000001;

	/** Hash object with other algorithm. */
	public static final long TSS_HASH_OTHER = 0xFFFFFFFF;

	// Object Context:
	// TSS_TSPATTRIB_CONTEXT_SILENT_MODE |0 0 1|
	// TSS_TSPATTRIB_CONTEXT_MACHINE_NAME |0 1 0|

	/**
	 * Get/set the silent mode of a context object. <br>
	 * Valid values for this attribFlag are:
	 * <ul>
	 * <li>{@link TcTssConstants#TSS_TSPATTRIB_CONTEXT_SILENT}</li>
	 * <li>{@link TcTssConstants#TSS_TSPATTRIB_CONTEXT_NOT_SILENT}</li>
	 * </ul>
	 * Note: The subFlag has to be set to 0.
	 */
	public static final long TSS_TSPATTRIB_CONTEXT_SILENT_MODE = 0x00000001;

	/**
	 * Get the machine name of the TSS given as a zero terminated UNICODE string the context object is
	 * connected with.
	 */
	public static final long TSS_TSPATTRIB_CONTEXT_MACHINE_NAME = 0x00000002;

	// Object Policy Attributes:
	// TSS_TSPATTRIB_POLICY_CALLBACK_HMAC |0 0 1|
	// TSS_TSPATTRIB_POLICY_CALLBACK_XOR_ENC |0 1 0|
	// TSS_TSPATTRIB_POLICY_CALLBACK_TAKEOWNERSHIP |0 1 1|
	// TSS_TSPATTRIB_POLICY_CALLBACK_CHANGEAUTHASYM |1 0 0|
	// TSS_TSPATTRIB_POLICY_SECRET_LIFETIME |1 0 1|
	// TSS_TSPATTRIB_POLICY_POPUPSTRING |1 1 0|

	/** Get/Set the address of the callback function to be used. */
	public static final long TSS_TSPATTRIB_POLICY_CALLBACK_HMAC = 0x00000080;

	/** Get/Set the address of the callback function to be used. */
	public static final long TSS_TSPATTRIB_POLICY_CALLBACK_XOR_ENC = 0x00000100;

	/** Get/Set the the address of the callback function to be used. */
	public static final long TSS_TSPATTRIB_POLICY_CALLBACK_TAKEOWNERSHIP = 0x00000180;

	/** Get/Set the the address of the callback function to be used. */
	public static final long TSS_TSPATTRIB_POLICY_CALLBACK_CHANGEAUTHASYM = 0x00000200;

	public static final long TSS_TSPATTRIB_POLICY_CALLBACK_SEALX_MASK = 0x00000380;

	/**
	 * Get/Set the lifetime of a secret. <br>
	 * Valid subFlags for this attribFlag are:
	 * <ul>
	 * <li>{@link TcTssConstants#TSS_TSPATTRIB_POLICYSECRET_LIFETIME_ALWAYS}</li>
	 * <li>{@link TcTssConstants#TSS_TSPATTRIB_POLICYSECRET_LIFETIME_COUNTER}</li>
	 * <li>{@link TcTssConstants#TSS_TSPATTRIB_POLICYSECRET_LIFETIME_TIMER}</li>
	 * </ul>
	 */
	public static final long TSS_TSPATTRIB_POLICY_SECRET_LIFETIME = 0x00000280;

	/**
	 * A NULL terminated UNICODE string which is displayed in the TSP policy popup dialog. This string
	 * object is to be created using the {@link TcBlobData#newString(String)}
	 * method.
	 */
	public static final long TSS_TSPATTRIB_POLICY_POPUPSTRING = 0x00000300;

	// Definition of policy mode flags that can be used with the method
	// Tspi_Policy_SetSecret= ;
	//	
	// TSS_SECRET_MODE_NONE |0 0 0 1|
	// TSS_SECRET_MODE_SHA1 |0 0 1 0|
	// TSS_SECRET_MODE_PLAIN |0 0 1 1|
	// TSS_SECRET_MODE_POPUP |0 1 0 0|
	// TSS_SECRET_MODE_CALLBACK |0 1 0 1|

	/** No authorization will be processed */
	public static final long TSS_SECRET_MODE_NONE = 0x00000800;

	/** Secret string will not be touched by TSP. */
	public static final long TSS_SECRET_MODE_SHA1 = 0x00001000;

	/** Secret string will be hashed using SHA1 */
	public static final long TSS_SECRET_MODE_PLAIN = 0x00001800;

	/**
	 * TSS will ask for a secret (presenting a dialog box to the user). The string that is displayed
	 * in the popup dialog can be sustomized via the
	 * {@link TcTssConstants#TSS_TSPATTRIB_POLICY_POPUPSTRING} attribute.
	 */
	public static final long TSS_SECRET_MODE_POPUP = 0x00002000;

	/** Application has to provide a callback function */
	public static final long TSS_SECRET_MODE_CALLBACK = 0x00002800;

	// ////////////////////////////////////////////////////////////////////////
	// SetAttribField and GetAttribField: SubFlags
	// ////////////////////////////////////////////////////////////////////////

	// SubFlags for Flag TSS_TSPATTRIB_POLICY_SECRET_LIFETIME
	// TSS_TSPATTRIB_POLICYSECRET_LIFETIME_ALWAYS |0 0 0 1|
	// TSS_TSPATTRIB_POLICYSECRET_LIFETIME_COUNTER |0 0 1 0|
	// TSS_TSPATTRIB_POLICYSECRET_LIFETIME_TIMER |0 0 1 1|

	/** Secret will not be invalidated. */
	public static final long TSS_SECRET_LIFETIME_ALWAYS = 0x00000001;

	/** Secret may be used n-times. */
	public static final long TSS_SECRET_LIFETIME_COUNTER = 0x00000002;

	/** Secret will be valid for n seconds. */
	public static final long TSS_SECRET_LIFETIME_TIMER = 0x00000003;

	/** Secret will not be invalidated. Attrib value: true or false. */
	public static final long TSS_TSPATTRIB_POLICYSECRET_LIFETIME_ALWAYS = TSS_SECRET_LIFETIME_ALWAYS;

	/** Secret may be used n-times. Attrib value: Counter value. */
	public static final long TSS_TSPATTRIB_POLICYSECRET_LIFETIME_COUNTER = TSS_SECRET_LIFETIME_COUNTER;

	/** Secret will be valid for n seconds. Attrib value: Time value in seconds. */
	public static final long TSS_TSPATTRIB_POLICYSECRET_LIFETIME_TIMER = TSS_SECRET_LIFETIME_TIMER;

	// values for Flag TSS_TSPATTRIB_CONTEXT_SILENT_MODE

	/** TSP dialogs are shown (Default). */
	public static final long TSS_TSPATTRIB_CONTEXT_NOT_SILENT = 0x00000000;

	/** TSP dialogs are not shown. */
	public static final long TSS_TSPATTRIB_CONTEXT_SILENT = 0x00000001;

	// Object EncData:

	/**
	 * Get/Set a data blob for sealing or binding. <br>
	 * Valid subFlags are:
	 * <ul>
	 * <li>{@link TcTssConstants#TSS_TSPATTRIB_ENCDATABLOB_BLOB}</li>
	 * </ul>
	 */
	public static final long TSS_TSPATTRIB_ENCDATA_BLOB = 0x00000008;

	/**
	 * Get PCR information the data is sealed to. <br>
	 * Valid subFlags are:
	 * <ul>
	 * <li>{@link TcTssConstants#TSS_TSPATTRIB_ENCDATAPCR_DIGEST_ATCREATION}</li>
	 * <li>{@link TcTssConstants#TSS_TSPATTRIB_ENCDATAPCR_DIGEST_RELEASE}</li>
	 * <li>{@link TcTssConstants#TSS_TSPATTRIB_ENCDATAPCR_SELECTION}</li>
	 * </ul>
	 */
	public static final long TSS_TSPATTRIB_ENCDATA_PCR = 0x00000010;

	// Object Key:
	// TSS_TSPATTRIB_KEY_BLOB |0 0 0 1|
	// TSS_TSPATTRIB_KEY_PARAM |0 0 1 0|
	// TSS_TSPATTRIB_KEY_GUID |0 0 1 1|
	// TSS_TSPATTRIB_KEY_PCR |0 1 0 0|
	// TSS_TSPATTRIB_RSAKEY_INFO |0 1 0 1|
	// TSS_TSPATTRIB_KEY_REGISTER |0 1 1 0|

	/**
	 * Get/Set a key blob. <br>
	 * Valid subFlags are:
	 * <ul>
	 * <li>{@link TcTssConstants#TSS_TSPATTRIB_KEYBLOB_BLOB}</li>
	 * <li>{@link TcTssConstants#TSS_TSPATTRIB_KEYBLOB_PUBLIC_KEY}</li>
	 * <li>{@link TcTssConstants#TSS_TSPATTRIB_KEYBLOB_PRIVATE_KEY}</li>
	 * </ul>
	 */
	public static final long TSS_TSPATTRIB_KEY_BLOB = 0x00000040;

	/**
	 * Get key information. <br>
	 * Valid subFlags are:
	 * <ul>
	 * <li>{@link TcTssConstants#TSS_TSPATTRIB_KEYINFO_USAGE}</li>
	 * <li>{@link TcTssConstants#TSS_TSPATTRIB_KEYINFO_MIGRATABLE}</li>
	 * <li>{@link TcTssConstants#TSS_TSPATTRIB_KEYINFO_REDIRECTED}</li>
	 * <li>{@link TcTssConstants#TSS_TSPATTRIB_KEYINFO_VOLATILE}</li>
	 * <li>{@link TcTssConstants#TSS_TSPATTRIB_KEYINFO_AUTHDATAUSAGE}</li>
	 * <li>{@link TcTssConstants#TSS_TSPATTRIB_KEYINFO_ALGORITHM}</li>
	 * <li>{@link TcTssConstants#TSS_TSPATTRIB_KEYINFO_ENCSCHEME}</li>
	 * <li>{@link TcTssConstants#TSS_TSPATTRIB_KEYINFO_SIGSCHEME}</li>
	 * <li>{@link TcTssConstants#TSS_TSPATTRIB_KEYINFO_SIZE}</li>
	 * <li>{@link TcTssConstants#TSS_TSPATTRIB_KEYINFO_KEYFLAGS}</li>
	 * <li>{@link TcTssConstants#TSS_TSPATTRIB_KEYINFO_AUTHUSAGE}</li>
	 * <li>{@link TcTssConstants#TSS_TSPATTRIB_KEYINFO_VERSION}</li>
	 * </ul>
	 */
	public static final long TSS_TSPATTRIB_KEY_INFO = 0x00000080;

	/**
	 * Get TSS_UUID structure containing the UUID the key is assigned to.
	 */
	public static final long TSS_TSPATTRIB_KEY_UUID = 0x000000C0;

	/**
	 * Get PCR information the key is sealed to. <br>
	 * Valid subFlags are:
	 * <ul>
	 * <li>{@link TcTssConstants#TSS_TSPATTRIB_KEYPCR_DIGEST_ATCREATION}</li>
	 * <li>{@link TcTssConstants#TSS_TSPATTRIB_KEYPCR_DIGEST_ATRELEASE}</li>
	 * <li>{@link TcTssConstants#TSS_TSPATTRIB_KEYPCR_SELECTION}</li>
	 * </ul>
	 */
	public static final long TSS_TSPATTRIB_KEY_PCR = 0x00000100;

	/**
	 * Get exponent/modulus info from a RSA key. <br>
	 * Valid subFlags are:
	 * <ul>
	 * <li>{@link TcTssConstants#TSS_TSPATTRIB_KEYINFO_RSA_PRIMES}</li>
	 * <li>{@link TcTssConstants#TSS_TSPATTRIB_KEYINFO_RSA_KEYSIZE}</li>
	 * <li>{@link TcTssConstants#TSS_TSPATTRIB_KEYINFO_RSA_EXPONENT}</li>
	 * <li>{@link TcTssConstants#TSS_TSPATTRIB_KEYINFO_RSA_MODULUS}</li>
	 * </ul>
	 */
	public static final long TSS_TSPATTRIB_RSAKEY_INFO = 0x00000140;

	/**
	 * Set/Get the persistent storage the key is registered in. <br>
	 * Valid attribs are:
	 * <ul>
	 * <li>{@link TcTssConstants#TSS_TSPATTRIB_KEYREGISTER_NO}</li>
	 * <li>{@link TcTssConstants#TSS_TSPATTRIB_KEYREGISTER_SYSTEM}</li>
	 * <li>{@link TcTssConstants#TSS_TSPATTRIB_KEYREGISTER_USER}</li>
	 * </ul>
	 */
	public static final long TSS_TSPATTRIB_KEY_REGISTER = 0x00000180;

	// Object Hash:

	/**
	 * Sets the length and data for the hash algorithm identifier. (Hash object created with type is
	 * HASH_ALG_OTHER). [subFlag: 0]
	 */
	public static final long TSS_TSPATTRIB_HASH_IDENTIFIER = 0x00001000;

	// SubFlags for Flag TSS_TSPATTRIB_ENCDATA_BLOB
	// TSS_TSPATTRIB_ENCDATABLOB_BLOB |0 0 1|
	// TSS_TSPATTRIB_ENCDATAPCR_DIGEST_ATCREATION |0 1 0|

	/**
	 * Data blob that represents the encrypted data depending on its type (seal or bind).
	 */
	public static final long TSS_TSPATTRIB_ENCDATABLOB_BLOB = 0x00000001;

	/**
	 * Get composite digest value of the PCR values, at the time when the sealing was performed.
	 */
	public static final long TSS_TSPATTRIB_ENCDATAPCR_DIGEST_ATCREATION = 0x00000002;

	/** Composite digest value of the PCR values, at the time when the unsealing should be performed. */
	public static final long TSS_TSPATTRIB_ENCDATAPCR_DIGEST_RELEASE = 0x00000003;

	/** A bit map that indicates if a PCR is active or not. */
	public static final long TSS_TSPATTRIB_ENCDATAPCR_SELECTION = 0x00000004;

	// SubFlags for Flag TSS_TSPATTRIB_KEY_BLOB
	// TSS_TSPATTRIB_KEYBLOB_BLOB |0 0 0 1|
	// TSS_TSPATTRIB_KEYBLOB_PUBLIC_KEY |0 0 1 0|
	// TSS_TSPATTRIB_KEYBLOB_PRIVATE_KEY |0 1 0 1|

	/** Key information as a key blob. */
	public static final long TSS_TSPATTRIB_KEYBLOB_BLOB = 0x00000008;

	/** Public key information as public key blob. */
	public static final long TSS_TSPATTRIB_KEYBLOB_PUBLIC_KEY = 0x00000010;

	/** Encrypted private key information as private key blob. */
	public static final long TSS_TSPATTRIB_KEYBLOB_PRIVATE_KEY = 0x00000028;

	// SubFlags for Flag TSS_TSPATTRIB_KEY_INFO
	// TSS_TSPATTRIB_KEYINFO_SIZE |0 0 0 0 1|
	// TSS_TSPATTRIB_KEYINFO_USAGE |0 0 0 1 0|
	// TSS_TSPATTRIB_KEYINFO_KEYFLAGS |0 0 0 1 1|
	// TSS_TSPATTRIB_KEYINFO_AUTHUSAGE |0 0 1 0 0|
	// TSS_TSPATTRIB_KEYINFO_ALGORITHM |0 0 1 0 1|
	// TSS_TSPATTRIB_KEYINFO_SIGSCHEME |0 0 1 1 0|
	// TSS_TSPATTRIB_KEYINFO_ENCSCHEME |0 0 1 1 1|
	// TSS_TSPATTRIB_KEYINFO_MIGRATABLE |0 1 0 0 0|
	// TSS_TSPATTRIB_KEYINFO_REDIRECTED |0 1 0 0 1|
	// TSS_TSPATTRIB_KEYINFO_VOLATILE |0 1 0 1 0|
	// TSS_TSPATTRIB_KEYINFO_AUTHDATAUSAGE |0 1 0 1 1|
	// TSS_TSPATTRIB_KEYINFO_VERSION |0 1 0 100|

	/** Key size in bits. */
	public static final long TSS_TSPATTRIB_KEYINFO_SIZE = 0x00000080;

	/**
	 * Key usage info. <br>
	 * Valid attribs are:
	 * <ul>
	 * <li>{@link TcTssConstants#TSS_KEYUSAGE_BIND}</li>
	 * <li>{@link TcTssConstants#TSS_KEYUSAGE_AUTHCHANGE}</li>
	 * <li>{@link TcTssConstants#TSS_KEYUSAGE_IDENTITY}</li>
	 * <li>{@link TcTssConstants#TSS_KEYUSAGE_STORAGE}</li>
	 * <li>{@link TcTssConstants#TSS_KEYUSAGE_LEGACY}</li>
	 * <li>{@link TcTssConstants#TSS_KEYUSAGE_SIGN}</li>
	 * </ul>
	 */
	public static final long TSS_TSPATTRIB_KEYINFO_USAGE = 0x00000100;

	/** Key flags. */
	public static final long TSS_TSPATTRIB_KEYINFO_KEYFLAGS = 0x00000180;

	/** Key auth usage info. */
	public static final long TSS_TSPATTRIB_KEYINFO_AUTHUSAGE = 0x00000200;

	/**
	 * Key algorithm ID. <br>
	 * Valid attributes are:
	 * <ul>
	 * <li>{@link TcTssConstants#TSS_ALG_3DES}</li>
	 * <li>{@link TcTssConstants#TSS_ALG_AES}</li>
	 * <li>{@link TcTssConstants#TSS_ALG_DES}</li>
	 * <li>{@link TcTssConstants#TSS_ALG_HMAC}</li>
	 * <li>{@link TcTssConstants#TSS_ALG_RSA}</li>
	 * <li>{@link TcTssConstants#TSS_ALG_SHA}</li>
	 * </ul>
	 */
	public static final long TSS_TSPATTRIB_KEYINFO_ALGORITHM = 0x00000280;

	/**
	 * Key sig scheme. <br>
	 * Valid attributes are:
	 * <ul>
	 * <li>{@link TcTssConstants#TSS_SS_NONE}</li>
	 * <li>{@link TcTssConstants#TSS_SS_RSASSAPKCS1V15_DER}</li>
	 * <li>{@link TcTssConstants#TSS_SS_RSASSAPKCS1V15_SHA1}</li>
	 * </ul>
	 */
	public static final long TSS_TSPATTRIB_KEYINFO_SIGSCHEME = 0x00000300;

	/**
	 * Encryption scheme. <br>
	 * Valid attributes are:
	 * <ul>
	 * <li>{@link TcTssConstants#TSS_ES_NONE}</li>
	 * <li>{@link TcTssConstants#TSS_ES_RSAESOAEP_SHA1_MGF1}</li>
	 * <li>{@link TcTssConstants#TSS_ES_RSAESPKCSV15}</li>
	 * </ul>
	 */
	public static final long TSS_TSPATTRIB_KEYINFO_ENCSCHEME = 0x00000380;

	/** If true then key is migratable. (attrib is a boolean value) */
	public static final long TSS_TSPATTRIB_KEYINFO_MIGRATABLE = 0x00000400;

	/** Key is redirected. (attributes is a boolean value) */
	public static final long TSS_TSPATTRIB_KEYINFO_REDIRECTED = 0x00000480;

	/** If true key is volatile. (attrib is a boolean value) */
	public static final long TSS_TSPATTRIB_KEYINFO_VOLATILE = 0x00000500;

	/** If true authorization is required. (attrib is a boolean value) */
	public static final long TSS_TSPATTRIB_KEYINFO_AUTHDATAUSAGE = 0x00000580;

	/** Version info as TSS version struct. */
	public static final long TSS_TSPATTRIB_KEYINFO_VERSION = 0x00000600;

	// SubFlags for Flag TSS_TSPATTRIB_RSAKEY_INFO
	// TSS_TSPATTRIB_KEYINFO_RSA_EXPONENT |0 0 1|
	// TSS_TSPATTRIB_KEYINFO_RSA_MODULUS |0 1 0|
	// TSS_TSPATTRIB_KEYINFO_RSA_KEYSIZE |0 1 1|
	// TSS_TSPATTRIB_KEYINFO_RSA_PRIMES |1 0 0|

	/** Exponent of the key. */
	public static final long TSS_TSPATTRIB_KEYINFO_RSA_EXPONENT = 0x00001000;

	/** Modulus of the key. */
	public static final long TSS_TSPATTRIB_KEYINFO_RSA_MODULUS = 0x00002000;

	/** Size of the key. */
	public static final long TSS_TSPATTRIB_KEYINFO_RSA_KEYSIZE = 0x00003000;

	/**
	 * The number of prime factors used by the RSA key.
	 */
	public static final long TSS_TSPATTRIB_KEYINFO_RSA_PRIMES = 0x00004000;

	// SubFlags for Flag TSS_TSPATTRIB_KEY_PCR
	// TSS_TSPATTRIB_KEYPCR_DIGEST_ATCREATION |0 0 1|
	// TSS_TSPATTRIB_KEYPCR_DIGEST_ATRELEASE |0 1 0|
	// TSS_TSPATTRIB_KEYPCR_SELECTION |0 1 1|

	/**
	 * Get composite digest value of the PCR values, at the time when the sealing was performed.
	 */
	public static final long TSS_TSPATTRIB_KEYPCR_DIGEST_ATCREATION = 0x00008000;

	/**
	 * This is the digest of the PCR value to verify when revealing sealed data.
	 */
	public static final long TSS_TSPATTRIB_KEYPCR_DIGEST_ATRELEASE = 0x00010000;

	/**
	 * This is the selction of PCRs to which the key is bound.
	 */
	public static final long TSS_TSPATTRIB_KEYPCR_SELECTION = 0x00018000;

	// SubFlags for TSS_TSPATTRIB_KEY_REGISTER
	// TSS_TSPATTRIB_KEYREGISTER_USER |0 0 1|
	// TSS_TSPATTRIB_KEYREGISTER_SYSTEM |0 1 0|
	// TSS_TSPATTRIB_KEYREGISTER_NO |0 1 1|

	/** Key is registered automatically in the persistent storage of TSP. */
	public static final long TSS_TSPATTRIB_KEYREGISTER_USER = 0x02000000;

	/** Key is registered automatically in the persistent storage of TSP. */
	public static final long TSS_TSPATTRIB_KEYREGISTER_SYSTEM = 0x04000000;

	/** Key is not registered in PS. */
	public static final long TSS_TSPATTRIB_KEYREGISTER_NO = 0x06000000;

	// Algorithm ID Definitions
	// This table defines the algo id's values intentional moved away from corresponding TPM values to
	// avoid possible misuse

	/** RSA algorithm handle. */
	public static final long TSS_ALG_RSA = 0x20;

	/** DES algorithm handle. */
	public static final long TSS_ALG_DES = 0x21;

	/** 3DES algorithm handle. */
	public static final long TSS_ALG_3DES = 0x22;

	/** SHA1 algorithm handle. */
	public static final long TSS_ALG_SHA = 0x23;

	/** HMAC algorithm handle. */
	public static final long TSS_ALG_HMAC = 0x24;

	// persistent storage registration definitions

	/** Key is registered persistently in the user storage database. */
	public static final long TSS_PS_TYPE_USER = 1;

	/** Key is registered persistently in the system storage database. */
	public static final long TSS_PS_TYPE_SYSTEM = 2;

	// migration scheme definitions
	// Values intentional moved away from corresponding TPM values to avoid
	// possible misuse

	/**
	 * A public key that can be used for migrating a key utilizing Tspi_Key_CreateMigrationBlob
	 * followed by Tspi_Key_ConvertMigrationBlob.
	 */
	public static final long TSS_MS_MIGRATE = 0x20;

	/**
	 * A public key that can be used for migrating a key by just rewrapping this key utilizing
	 * Tspi_Key_CreateMigrationBlob.
	 */
	public static final long TSS_MS_REWRAP = 0x21;

	/** A public key that can be used for the maintenance commands. */
	public static final long TSS_MS_MAINT = 0x22;

	// TCPA key authorization
	// Values intentional moved away from corresponding TPM values to avoid
	// possible misuse

	/** Key always requires authorization */
	public static final long TSS_KEYAUTH_AUTH_NEVER = 0x10;

	/** Key always requires authorization */
	public static final long TSS_KEYAUTH_AUTH_ALWAYS = 0x11;

	// key usage definitions
	// Values intentional moved away from corresponding TPM values to avoid
	// possible misuse

	/**
	 * The key can be used for binding and unbinding operations only.
	 */
	public static final long TSS_KEYUSAGE_BIND = 0x00;

	/**
	 * The key is used for operations that require a TPM identity, only.
	 */
	public static final long TSS_KEYUSAGE_IDENTITY = 0x01;

	/**
	 * The key is used for operations that require a TPM identity, only.
	 */
	public static final long TSS_KEYUSAGE_LEGACY = 0x02;

	/**
	 * The [private] key is used for signing operations, only. This means that it MUST be a leaf of
	 * the Protected Storage key hierarchy.
	 */
	public static final long TSS_KEYUSAGE_SIGN = 0x03;

	/**
	 * The key is used to wrap and unwrap other keys in the Protected Storage hierarchy, only.
	 */
	public static final long TSS_KEYUSAGE_STORAGE = 0x04;

	/** The key is used to change authorization. */
	public static final long TSS_KEYUSAGE_AUTHCHANGE = 0x07;

	// key encrypten and signature scheme definitions

	/** No encryption scheme is set. */
	public static final long TSS_ES_NONE = 0x10;

	/**
	 * The encryption is performed using the scheme RSA_ES_PKCSV15 defined in [PKCS #1v2.0: 8.1].
	 */
	public static final long TSS_ES_RSAESPKCSV15 = 0x11;

	/**
	 * The encryption and decryption is performed using the scheme RSA_ES_OAEP defined in [PKCS
	 * #1v2.0: 8.1] using SHA1 as the hash algorithm for the encoding operation.
	 */
	public static final long TSS_ES_RSAESOAEP_SHA1_MGF1 = 0x12;

	/** No signature scheme. */
	public static final long TSS_SS_NONE = 0x10;

	/**
	 * The signature is be performed using the scheme RSASSA-PKCS1-v1.5 defined in [PKCS #1v2.0: 8.1]
	 * using SHA1 as the hash algorithm for the encoding operation.
	 */
	public static final long TSS_SS_RSASSAPKCS1V15_SHA1 = 0x11;

	/**
	 * The signature is performed using the scheme RSASSA-PKCS1-v1.5 defined in [PKCS #1v2.0: 8.1].
	 * The caller must properly format the area to sign using the DER rules. The provided area maximum
	 * size is k-11 octets
	 */
	public static final long TSS_SS_RSASSAPKCS1V15_DER = 0x12;

	// Flags for TPM status information = Get- and SetStatus;
	
	public static final long TSS_SS_RSASSAPKCS1V15_INFO = 0x13;

	/**
	 * Permanently disable the TPM owner authorized clearing of TPM ownership. The method ClearOwner( )
	 * with ForcedClear = FALSE is not available any longer.
	 */
	public static final long TSS_TPMSTATUS_DISABLEOWNERCLEAR = 0x00000001;

	/** Prevent temporarily (until next power on) a forced clear of the TPM ownership. */
	public static final long TSS_TPMSTATUS_DISABLEFORCECLEAR = 0x00000002;

	/** Query whether TPM is disabled or enabled. */
	public static final long TSS_TPMSTATUS_DISABLED = 0x00000003;

	/** Query whether the TPM is deactivated or activated. */
	public static final long TSS_TPMSTATUS_DEACTIVATED = 0x00000004;

	/** Disable the TPM. Owner authorization is required. */
	public static final long TSS_TPMSTATUS_OWNERSETDISABLE = 0x00000005;

	/** Set the ability to take TPM ownwership utilizing the method TPM_TakeOwnership(). */
	public static final long TSS_TPMSTATUS_SETOWNERINSTALL = 0x00000006;

	/**
	 * Permanently disable the ability to read the endorsement public key without requiring TPM owner
	 * authorizition. The method GetPubEndorsementKey() with OwnerAuthorized = FALSE is not available
	 * any longer.
	 */
	public static final long TSS_TPMSTATUS_DISABLEPUBEKREAD = 0x00000007;

	/**
	 * Query whether the TPM owner may create a maintenance archive utilizing the method
	 * CreateMaintenanceArchive() or not.
	 */
	public static final long TSS_TPMSTATUS_ALLOWMAINTENANCE = 0x00000008;

	/**
	 * Query whether both physicalPresenceHWEnable and physicalPresenceCMDEnable flags are locked and
	 * cannot be changed for the life of the TPM.
	 */
	public static final long TSS_TPMSTATUS_PHYSPRES_LIFETIMELOCK = 0x00000009;

	/**
	 * Query whether the TPM hardware signal <physical presence> is enabled to provide proof of
	 * physical presence.
	 */
	public static final long TSS_TPMSTATUS_PHYSPRES_HWENABLE = 0x0000000A;

	/**
	 * Query whether the TPM command TSC_PhysicalPresence is enabled to provide proof of physical
	 * presence.
	 */
	public static final long TSS_TPMSTATUS_PHYSPRES_CMDENABLE = 0x0000000B;

	/**
	 * Query whether changes to the physicalPresence flag are permitted.
	 */
	public static final long TSS_TPMSTATUS_PHYSPRES_LOCK = 0x0000000C;

	/**
	 * Query whether a TPM owner is present indicated by the TPM command TSC_PhysicalPresence.
	 */
	public static final long TSS_TPMSTATUS_PHYSPRESENCE = 0x0000000D;

	/** Disable the TPM. Proof of physical access is required. */
	public static final long TSS_TPMSTATUS_PHYSICALDISABLE = 0x0000000E;

	/**
	 * Query whether the endorsement key pair was created using the methode
	 * Tspi_TPM_CreateEndorsementKey() or it was created using a manufacturers process.
	 */
	public static final long TSS_TPMSTATUS_CEKP_USED = 0x0000000F;

	/** Deactivate the TPM. Proof of physical access is required. */
	public static final long TSS_TPMSTATUS_PHYSICALSETDEACTIVATED = 0x00000010;

	/**
	 * Temporarily deactivate (until next power on) the TPM.
	 */
	public static final long TSS_TPMSTATUS_SETTEMPDEACTIVATED = 0x00000011;

	/**
	 * Indicates that the TPM is between the TPM_Init state and the execution of the TPM_Startup
	 * command.
	 */
	public static final long TSS_TPMSTATUS_POSTINITIALISE = 0x00000012;

	/**
	 * Sets the TPM to force a full sefttest before allowing commands to be performed.
	 */
	public static final long TSS_TPMSTATUS_TPMPOST = 0x00000013;

	/**
	 * Resets the effects of multiple authorization failures.
	 */
	public static final long TSS_TPMSTATUS_RESETLOCK = 0x0000001D;

	/**
	 * Locks the state of the TSS_TPMSTATUS_TPMPOST flag for the lifetime of the TPM.
	 */
	public static final long TSS_TPMSTATUS_TPMPOSTLOCK = 0x00000014;

	// TPM capabilities

	/** Queries whether an ordinal is supported. (subCap: ordinal number) */
	public static final long TSS_TPMCAP_ORD = 0x10;

	/** Queries whether an algorithm is supported. (subCap: TcTssConstants.TSS_ALG_XXX) */
	public static final long TSS_TPMCAP_ALG = 0x11;

	/** Queries the state of a flag. (subCap: ignored) */
	public static final long TSS_TPMCAP_FLAG = 0x12;

	/**
	 * Determines a physical property of the TPM. <br>
	 * Valid subCaps are:
	 * <ul>
	 * <li>{@link TcTssConstants#TSS_TPMCAP_PROP_DIR}</li>
	 * <li>{@link TcTssConstants#TSS_TPMCAP_PROP_MANUFACTURER}</li>
	 * <li>{@link TcTssConstants#TSS_TPMCAP_PROP_PCR}</li>
	 * <li>{@link TcTssConstants#TSS_TPMCAP_PROP_SLOTS}</li>
	 * </ul>
	 */
	public static final long TSS_TPMCAP_PROPERTY = 0x13;

	/** Queries the current TPM version. (subCaps: ignored) */
	public static final long TSS_TPMCAP_VERSION = 0x14;

	// Sub-Capability Flags TPM-Capabilities

	/** The number of PCR registers supported by the TPM. */
	public static final long TSS_TPMCAP_PROP_PCR = 0x10;

	/** The number of DIR registers supported by the TPM. */
	public static final long TSS_TPMCAP_PROP_DIR = 0x11;

	/** The manufacturer of the TPM. */
	public static final long TSS_TPMCAP_PROP_MANUFACTURER = 0x12;

	/**
	 * The maximum number of 2048 bit RSA keys that the TPM is capable of loading. This MAY vary with
	 * time and circumstances.
	 */
	public static final long TSS_TPMCAP_PROP_SLOTS = 0x13;

	// TSS Core Service Capabilities

	/** Queries whether an algorithm is supported. (subCap: TcTssConstants.TSS_ALG_XXX) */
	public static final long TSS_TCSCAP_ALG = 0x00000001;

	/** Queries the current TCS version. (subCap: none) */
	public static final long TSS_TCSCAP_VERSION = 0x00000002;

	/**
	 * Queries the support of key and authorization caching. <br>
	 * Valid subCaps are:
	 * <ul>
	 * <li>{@link TcTssConstants#TSS_TCSCAP_PROP_KEYCACHE}</li>
	 * <li>{@link TcTssConstants#TSS_TCSCAP_PROP_AUTHCACHE}</li>
	 * </ul>
	 */
	public static final long TSS_TCSCAP_CACHING = 0x00000003;

	/** Queries the support of a persistent storage. (subCap: none) */
	public static final long TSS_TCSCAP_PERSSTORAGE = 0x00000004;

	/**
	 * Queries the manufacturer information. <br>
	 * Valid subCaps are:
	 * <ul>
	 * <li>{@link TcTssConstants#TSS_TCSCAP_PROP_MANUFACTURER_STR}</li>
	 * <li>{@link TcTssConstants#TSS_TCSCAP_PROP_MANUFACTURER_ID}</li>
	 * </ul>
	 */
	public static final long TSS_TCSCAP_MANUFACTURER = 0x00000005;

	// Sub-Capability Flags TSS-CoreService-Capabilities

	/**
	 * TRUE indicates that the TCS supports key caching, FALSE indicates that the TCS does not support
	 * key caching.
	 */
	public static final long TSS_TCSCAP_PROP_KEYCACHE = 0x00000100;

	/**
	 * TRUE indicates that the TCS supports authorization session caching, FALSE indicates that the
	 * TCS does not support authorization session caching.
	 */
	public static final long TSS_TCSCAP_PROP_AUTHCACHE = 0x00000101;

	/**
	 * Returns an Unicode string of the TCS manufacturer. The contents of this string is determined by
	 * the manufacturer and is subject to change in subsequent releases of the TCS.
	 */
	public static final long TSS_TCSCAP_PROP_MANUFACTURER_STR = 0x00000102;

	/** Returns the manufacurer or implementer of the TCS. */
	public static final long TSS_TCSCAP_PROP_MANUFACTURER_ID = 0x00000103;

	// TSS Service Provider Capabilities

	/** Queries whether an algorithm is supported. */
	public static final long TSS_TSPCAP_ALG = 0x00000010;

	/** Queries whether an algorithm is supported. (subCap: none) */
	public static final long TSS_TSPCAP_VERSION = 0x00000011;

	/** Queries the support of a persistant storage. (subCap: none) */
	public static final long TSS_TSPCAP_PERSSTORAGE = 0x00000012;

	// Event type definitions

	/**
	 * The event is in response to loading a firmware or software component for which a VE certificate
	 * was available. rgbEvent points to the VE certificate that shipped with the platform firmware or
	 * software (or discovered by other means). PcrValue is the digest of the firmware, software or
	 * other code loaded. Certificates are much too large to put into the log in the Pre-OS
	 * environment. Validation of Certificates is unlikely in the Pre-OS environment. The event points
	 * to a TSS_EVENT_CERT structure.
	 */
	public static final long TSS_EV_CODE_CERT = 0x00000001;

	/**
	 * The event is in response to loading a firmware or other software component, but no VE
	 * certificate was found. ulEventLenght is 0 and rgbEvent is unused. However, PcrValue is the
	 * digest of the firmware discovered. Absence of a VE certificate does not indicate lack of trust;
	 * it merely indicates that a VE certificate was not available at this point in boot. Upper-level
	 * software may be able to obtain such certificates.
	 */
	public static final long TSS_EV_CODE_NOCERT = 0x00000002;

	/**
	 * The event describes the platform configuration. The supporting information is a platform or
	 * firmware-defined XML data structure that indicates security-relevant hardware configuration
	 * information. The event logged to the PCR is the SHA-1 digest of the XML data structure, and the
	 * firmware guarantees that the configuration stated in the data structure is in effect when the
	 * firmware relinquishes control to the next module in boot. Size is the size in bytes of the XML
	 * data structure, and rgbEvent points to the data structure itself. The information may include
	 * size of physical memory, number of processors, chipset configuration, buses discovered and
	 * processor/bus frequencies. Firmware vendors are free to define the XML reporting structure and
	 * select those parameters that are important for their platforms.
	 */
	public static final long TSS_EV_XML_CONFIG = 0x00000003;

	/**
	 * The action was not performed. The corresponding DIGEST structure must be 0x1 (a single binary
	 * digit in the LSB of the DIGEST structure), and this value is logged to the PCR. A supporting
	 * data structure may be supplied containing information that describes why the event did not
	 * occur. If such supporting information is supplied, it should be well-formed XML. However, this
	 * supporting information is not required.
	 */
	public static final long TSS_EV_NO_ACTION = 0x00000004;

	/**
	 * A list of actions was complete. This event must be used if more than one event can be logged to
	 * the TPM and upper-level software needs to be informed that logging was completed.
	 */
	public static final long TSS_EV_SEPARATOR = 0x00000005;

	/**
	 * A logged event. This is a zero terminated UNICODE string with the content defined by the
	 * Platform Specific specifications.
	 */
	public static final long TSS_EV_ACTION = 0x00000006;

	/** Implementation specification defined data. */
	public static final long TSS_EV_PLATFORM_SPECIFIC = 0x00000007;

	// TSS random number limits

	/** Random number limit. (subCap: none) */
	public static final long TSS_TSPCAP_RANDOMLIMIT = 0x00001000;

	/* Imported from the TSS 1.2 header files for use in 1.2 style callbacks */

	/** Get/Set the the address of the callback function to be used. */
	public static long TSS_TSPATTRIB_TPM_CALLBACK_COLLATEIDENTITY = 0x00000001;

	/** Get/Set the the address of the callback function to be used. */
	public static long TSS_TSPATTRIB_TPM_CALLBACK_ACTIVATEIDENTITY = 0x00000002;

	public static long TSS_TSPATTRIB_TPM_ORDINAL_AUDIT_STATUS = 0x00000003;

	public static long TSS_TSPATTRIB_TPM_CREDENTIAL = 0x00001000;

	// Subflags for TSS_TSPATTRIB_TPM_ORDINAL_AUDIT_STATUS
	public static long TPM_CAP_PROP_TPM_CLEAR_ORDINAL_AUDIT = 0x00000000;

	public static long TPM_CAP_PROP_TPM_SET_ORDINAL_AUDIT = 0x00000001;

	// Subflags for TSS_TSPATTRIB_TPM_CREDENTIAL
	public static long TSS_TPMATTRIB_EKCERT = 0x00000001;

	public static long TSS_TPMATTRIB_TPM_CC = 0x00000002;

	public static long TSS_TPMATTRIB_PLATFORMCERT = 0x00000003;

	public static long TSS_TPMATTRIB_PLATFORM_CC = 0x00000004;

	/**
	 * This is simply a helper define for those applications where the well known secret is defined as
	 * all zeros.
	 */
	public static byte[] TSS_WELL_KNOWN_SECRET = new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0 };

	// backports from TSS 1.2 spec:

	/**
	 * Flag indicating the hash operation handling of the password. Valid subFlags
	 * for this attribFlag are:
	 * <ul>
	 * <li>{@link TcTssConstants#TSS_TSPATTRIB_SECRET_HASH_MODE_POPUP}</li>
	 * </ul>
	 */
	public static long TSS_TSPATTRIB_SECRET_HASH_MODE = 0x00000006;

	/**
	 * Valid attribute values of {@link TcTssConstants#TSS_TSPATTRIB_SECRET_HASH_MODE_POPUP} are:
	 * <ul>
	 * <li>{@link TcTssConstants#TSS_TSPATTRIB_HASH_MODE_NOT_NULL}</li>
	 * <li>{@link TcTssConstants#TSS_TSPATTRIB_HASH_MODE_NULL}</li>
	 * </ul>
	 */
	public static long TSS_TSPATTRIB_SECRET_HASH_MODE_POPUP = 0x00000001;

	/**
	 * Null termination is excluded when hashing.
	 */
	public static long TSS_TSPATTRIB_HASH_MODE_NOT_NULL = 0x00000000;

	/**
	 * Null Termination is included when hashing.
	 */
	public static long TSS_TSPATTRIB_HASH_MODE_NULL = 0x00000001;

	// Constants added in the TSS Specification 1.2

	public static final long TSS_ALG_AES128 = 0x25;

	public static final long TSS_ALG_AES192 = 0x26;

	public static final long TSS_ALG_AES256 = 0x27;

	public static final long TSS_ALG_DEFAULT = 0xfe;

	public static final long TSS_ALG_DEFAULT_SIZE = 0xff;

	/** AES algorithm handle. */
	public static final long TSS_ALG_AES = TSS_ALG_AES128;

	public static final long TSS_ALG_MGF1 = 0x29;

	public static final long TSS_ALG_XOR = 0x28;

	public static final long TSS_BLOB_STRUCT_VERSION = 0x01;

	public static final long TSS_BLOB_TYPE_BOUNDDATA = 0x05;

	public static final long TSS_BLOB_TYPE_CERTIFY_INFO = 0x0A;

	public static final long TSS_BLOB_TYPE_CERTIFY_INFO_2 = 0x0C;

	public static final long TSS_BLOB_TYPE_CMK_BYTE_STREAM = 0x0E;

	public static final long TSS_BLOB_TYPE_CMK_MIG_KEY = 0x0D;

	public static final long TSS_BLOB_TYPE_KEY = 0x01;

	public static final long TSS_BLOB_TYPE_KEY_1_2 = 0x0B;

	public static final long TSS_BLOB_TYPE_MIGKEY = 0x03;

	public static final long TSS_BLOB_TYPE_MIGTICKET = 0x06;

	public static final long TSS_BLOB_TYPE_PRIVATEKEY = 0x07;

	public static final long TSS_BLOB_TYPE_PRIVATEKEY_MOD1 = 0x08;

	public static final long TSS_BLOB_TYPE_PUBKEY = 0x02;

	public static final long TSS_BLOB_TYPE_RANDOM_XOR = 0x09;

	public static final long TSS_BLOB_TYPE_SEALEDDATA = 0x04;

	public static final long TSS_CMK_DELEGATE_BIND = 1 << 29;

	public static final long TSS_CMK_DELEGATE_LEGACY = 1 << 28;

	public static final long TSS_CMK_DELEGATE_MIGRATE = 1 << 27;

	public static final long TSS_CMK_DELEGATE_SIGNING = 1 << 31;

	public static final long TSS_CMK_DELEGATE_STORAGE = 1 << 30;

	public static final long TSS_CONNECTION_VERSION_1_1 = 0x00000001;

	public static final long TSS_CONNECTION_VERSION_1_2 = 0x00000002;

	/* Length of the e's = exponents, part of certificate, 386 bits; */
	public static final long TSS_DAA_LENGTH_E = 46;

	/* Length of the interval the e's are chosen from = 120 bits; */
	public static final long TSS_DAA_LENGTH_E_PRIME = 15;

	/* Length of the f_i's = information encoded into the certificate, 104 bits; */
	public static final long TSS_DAA_LENGTH_F = 13;

	/* Length of the modulus 'Gamma' = 1632 bits; */
	public static final long TSS_DAA_LENGTH_GAMMA = 204;

	/* Length of the output of the hash function SHA-1 used for the Fiat-Shamir heuristic= 160 bits; */
	public static final long TSS_DAA_LENGTH_HASH = TcTpmConstants.TPM_SHA1_160_HASH_LEN;

	/* Length of the output of MGF1 in conjunction with the modulus Gamma = 1712 bits; */
	public static final long TSS_DAA_LENGTH_MFG1_GAMMA = 214;

	/* Length of the output of MGF1 used for anonymity revocation = 200 bits; */
	public static final long TSS_DAA_LENGTH_MGF1_AR = 25;

	/* Length of the RSA Modulus = 2048 bits; */
	public static final long TSS_DAA_LENGTH_N = 256;

	/*
	 * Length of the order 'rho' of the sub group of Z*_Gamma that is used for roggue tagging = 208
	 * bits;
	 */
	public static final long TSS_DAA_LENGTH_RHO = 26;

	/* Length of the split large exponent for easier computations on the TPM = 1024 bits; */
	public static final long TSS_DAA_LENGTH_S = 128;

	/* Length of the security parameter controlling the statistical zero-knowledge propert = 80 bits; */
	public static final long TSS_DAA_LENGTH_SAFETY = 10;

	/* Length of the v's = random value, part of certificate, 2536 bits; */
	public static final long TSS_DAA_LENGTH_V = 317;

	public static final long TSS_DELEGATE_CACHEOWNERDELEGATION_OVERWRITEEXISTING = 1;

	public static final long TSS_DELEGATE_INCREMENTVERIFICATIONCOUNT = 1;

	public static final long TSS_DELEGATIONTYPE_KEY = 0x00000003;

	public static final long TSS_DELEGATIONTYPE_NONE = 0x00000001;

	public static final long TSS_DELEGATIONTYPE_OWNER = 0x00000002;

	public static final long TSS_ES_SYM_CBC_PKCS5PAD = 0x15;

	public static final long TSS_ES_SYM_CNT = 0x13;

	public static final long TSS_ES_SYM_OFB = 0x14;

	public static final long TSS_FLAG_DAA_PSEUDONYM_ENCRYPTED = 0x00000001;

	public static final long TSS_FLAG_DAA_PSEUDONYM_PLAIN = 0x00000000;

	public static final long TSS_FLAG_DAA_SIGN_IDENTITY_KEY = 0x00000000;

	public static final long TSS_FLAG_DAA_SIGN_MESSAGE_HASH = 0x00000001;

	public static final long TSS_KEYAUTH_AUTH_PRIV_USE_ONLY = 0x12;

	public static final long TSS_KEY_AUTHORIZATION_PRIV_USE_ONLY = 0x00000002; // key needs auth

	public static final long TSS_KEY_CERTIFIED_MIGRATABLE = 0x00001000;

	public static final long TSS_KEYFLAG_CERTIFIED_MIGRATABLE = 0x00000008;

	public static final long TSS_KEYFLAG_MIGRATABLE = 0x00000002;

	public static final long TSS_KEYFLAG_REDIRECTION = 0x00000001;

	public static final long TSS_KEYFLAG_VOLATILEKEY = 0x00000004;

	public static final long TSS_KEY_NOT_CERTIFIED_MIGRATABLE = 0x00000000;

	public static final long TSS_KEY_SIZE_BITMASK = 0x00000F00; // mask to extract key size

	public static final long TSS_KEY_SIZE_DEFAULT = 0x00000000; // indicate tpm-specific size

	public static final long TSS_KEY_SIZEVAL_1024BIT = 0x0400;

	public static final long TSS_KEY_SIZEVAL_16384BIT = 0x4000;

	public static final long TSS_KEY_SIZEVAL_2048BIT = 0x0800;

	public static final long TSS_KEY_SIZEVAL_4096BIT = 0x1000;

	public static final long TSS_KEY_SIZEVAL_512BIT = 0x0200;

	public static final long TSS_KEY_SIZEVAL_8192BIT = 0x2000;

	public static final long TSS_KEY_STRUCT_BITMASK = 0x0001C000;

	public static final long TSS_KEY_STRUCT_DEFAULT = 0x00000000;

	public static final long TSS_KEY_STRUCT_KEY12 = 0x00008000;

	public static final long TSS_KEY_STRUCT_KEY = 0x00004000;

	public static final long TSS_KEY_TEMPLATE_BITMASK = 0xFC000000; // bitmask to extract key

	public static final long TSS_KEY_TYPE_BITMASK = 0x000000F0; // mask to extract key type

	public static final long TSS_KEYUSAGE_MIGRATE = 0x06;

	public static final long TSS_MIGATTRIB_AUTHORITY_APPROVAL_HMAC = 0x00000302;

	public static final long TSS_MIGATTRIB_AUTHORITY_DATA = 0x00000030;

	public static final long TSS_MIGATTRIB_AUTHORITY_DIGEST = 0x00000301;

	public static final long TSS_MIGATTRIB_AUTHORITY_MSALIST = 0x00000303;

	public static final long TSS_MIGATTRIB_MIG_AUTH_AUTHORITY_DIGEST = 0x00000401;

	public static final long TSS_MIGATTRIB_MIG_AUTH_DATA = 0x00000040;

	public static final long TSS_MIGATTRIB_MIG_AUTH_DESTINATION_DIGEST = 0x00000402;

	public static final long TSS_MIGATTRIB_MIG_AUTHORITY_PUBKEY_BLOB = 0x00000104;

	public static final long TSS_MIGATTRIB_MIG_AUTH_SOURCE_DIGEST = 0x00000403;

	public static final long TSS_MIGATTRIB_MIG_DESTINATION_PUBKEY_BLOB = 0x00000105;

	public static final long TSS_MIGATTRIB_MIG_MSALIST_PUBKEY_BLOB = 0x00000103;

	public static final long TSS_MIGATTRIB_MIGRATIONBLOB = 0x00000010;

	public static final long TSS_MIGATTRIB_MIGRATION_REWRAPPED_BLOB = 0x00000102;

	public static final long TSS_MIGATTRIB_MIGRATIONTICKET = 0x00000020;

	public static final long TSS_MIGATTRIB_MIGRATION_XOR_BLOB = 0x00000101;

	public static final long TSS_MIGATTRIB_MIG_SOURCE_PUBKEY_BLOB = 0x00000106;

	public static final long TSS_MIGATTRIB_PAYLOAD_TYPE = 0x00000060;

	public static final long TSS_MIGATTRIB_PT_MIGRATE_EXTERNAL = 0x00000602;

	public static final long TSS_MIGATTRIB_PT_MIGRATE_RESTRICTED = 0x00000601;

	public static final long TSS_MIGATTRIB_TICKET_DATA = 0x00000050;

	public static final long TSS_MIGATTRIB_TICKET_RESTRICT_TICKET = 0x00000504;

	public static final long TSS_MIGATTRIB_TICKET_SIG_DIGEST = 0x00000501;

	public static final long TSS_MIGATTRIB_TICKET_SIG_TICKET = 0x00000503;

	public static final long TSS_MIGATTRIB_TICKET_SIG_VALUE = 0x00000502;

	public static final long TSS_MS_RESTRICT_APPROVE_DOUBLE = 0x24;

	public static final long TSS_MS_RESTRICT_MIGRATE = 0x23;

	public static final long TSS_MS_RESTRICT_MIGRATE_EXTERNAL = 0x25;

	public static final long TSS_NV_DEFINED = 0x10000000; // "Defined permanently" flag

	public static final long TSS_NV_INDEX_SESSIONS = 0x00011101;

	public static final long TSS_NV_MASK_DEFINED = 0x10000000; // mask to extract 'D'

	public static final long TSS_NV_MASK_INDEX = 0x0000ffff; // mask to extract index byte

	public static final long TSS_NV_MASK_PLATFORM = 0x40000000; // mask to extract 'P'

	public static final long TSS_NV_MASK_PURVIEW = 0x00ff0000; // mask to extract purview byte

	public static final long TSS_NV_MASK_RESERVED = 0x0f000000; // mask to extract reserved bits

	public static final long TSS_NV_MASK_TPM = 0x80000000; // mask to extract 'T'

	public static final long TSS_NV_MASK_USER = 0x20000000; // mask to extract 'U'

	public static final long TSS_NV_PLATFORM = 0x40000000; // Platform mfr reserved bit

	public static final long TSS_NV_TPM = 0x80000000; // TPM mfr reserved bit

	public static final long TSS_NV_USER = 0x20000000; // User reserved bit

	public static final long TSS_OBJECT_TYPE_DELFAMILY = 0x06; // Delegation Family object

	public static final long TSS_OBJECT_TYPE_MIGDATA = 0x08; // CMK Migration data object

	public static final long TSS_OBJECT_TYPE_DAA_CERTIFICATE = 0x09; // DAA credential^M

	public static final long TSS_OBJECT_TYPE_DAA_ISSUER_KEY = 0x0a; // DAA cred. issuer keypair^M

	public static final long TSS_OBJECT_TYPE_DAA_ARA_KEY = 0x0b; // DAA anonymity revocation^M

	public static final long TSS_OBJECT_TYPE_NV = 0x07; // NV object

	public static final long TSS_PCRS_DIRECTION_CREATION = 1;

	public static final long TSS_PCRS_DIRECTION_RELEASE = 2;

	public static final long TSS_PCRS_STRUCT_DEFAULT = 0x00000000; // depends on context

	public static final long TSS_PCRS_STRUCT_INFO = 0x00000001; // TPM_PCR_INFO

	public static final long TSS_PCRS_STRUCT_INFO_LONG = 0x00000002; // TPM_PCR_INFO_LONG

	public static final long TSS_PCRS_STRUCT_INFO_SHORT = 0x00000003; // TPM_PCR_INFO_SHORT

	public static final long TSS_POLICY_OPERATOR = 0x00000003; // migration policy object

	public static final long TSS_TCSCAP_PLATFORM_CLASS = 0x00000006;

	public static final long TSS_TCSCAP_PLATFORM_TYPE = 0x00001101;

	public static final long TSS_TCSCAP_PLATFORM_VERSION = 0x00001100;

	public static final long TSS_TCSCAP_TRANS_EXCLUSIVE = 0x00002100;

	public static final long TSS_TCSCAP_TRANSPORT = 0x00000007;

	public static final long TSS_TCSCAP_PLATFORM_INFO = 0x00000008;

	public static final long TSS_TCSCAP_PROP_HOST_PLATFORM = 0x00003001;

	public static final long TSS_TCSCAP_PROP_ALL_PLATFORMS = 0x00003002;

	public static final long TSS_TPMCAP_AUTH_ENCRYPT = 0x1c;

	public static final long TSS_TPMCAP_HANDLE = 0x1a;

	public static final long TSS_TPMCAP_MFR = 0x18;

	public static final long TSS_TPMCAP_NV_INDEX = 0x17;

	public static final long TSS_TPMCAP_NV_LIST = 0x16;

	public static final long TSS_TPMCAP_PROP_ACTIVECOUNTER = 0x26;

	public static final long TSS_TPMCAP_PROP_AUTHSESSIONS = 0x19;

	public static final long TSS_TPMCAP_PROP_CMKRESTRICTION = 0x2b;

	public static final long TSS_TPMCAP_PROP_CONTEXTS = 0x1f;

	public static final long TSS_TPMCAP_PROP_COUNTERS = 0x24;

	public static final long TSS_TPMCAP_PROP_DAA_INTERRUPT = 0x23;

	public static final long TSS_TPMCAP_PROP_DAASESSIONS = 0x21;

	public static final long TSS_TPMCAP_PROP_DELEGATEROWS = 0x15;

	public static final long TSS_TPMCAP_PROP_DURATION = 0x2c;

	public static final long TSS_TPMCAP_PROP_FAMILYROWS = 0x14;

	public static final long TSS_TPMCAP_PROP_INPUTBUFFERSIZE = 0x2e;

	public static final long TSS_TPMCAP_PROP_LOCALITIES_AVAIL = 0x32;

	public static final long TSS_TPMCAP_PROP_MAXAUTHSESSIONS = 0x1a;

	public static final long TSS_TPMCAP_PROP_MAXCONTEXTCOUNTDIST = 0x2a;

	public static final long TSS_TPMCAP_PROP_MAXCONTEXTS = 0x20;

	public static final long TSS_TPMCAP_PROP_MAXCOUNTERS = 0x25;

	public static final long TSS_TPMCAP_PROP_MAXDAASESSIONS = 0x22;

	public static final long TSS_TPMCAP_PROP_MAXKEYS = 0x18;

	public static final long TSS_TPMCAP_PROP_MAXNVAVAILABLE = 0x2d;

	public static final long TSS_TPMCAP_PROP_MAXSESSIONS = 0x1e;

	public static final long TSS_TPMCAP_PROP_MAXTRANSESSIONS = 0x1c;

	public static final long TSS_TPMCAP_PROP_OWNER = 0x16;

	public static final long TSS_TPMCAP_PROP_REVISION = 0x2f;

	public static final long TSS_TPMCAP_PROP_SESSIONS = 0x1d;

	public static final long TSS_TPMCAP_PROP_STARTUPEFFECTS = 0x29;

	public static final long TSS_TPMCAP_PROP_TISTIMEOUTS = 0x28;

	public static final long TSS_TPMCAP_PROP_TRANSESSIONS = 0x1b;

	public static final long TSS_TPMCAP_SET_PERM_FLAGS = 0x1d; // cf. TPM_SET_PERM_FLAGS

	public static final long TSS_TPMCAP_SET_VENDOR = 0x1e; // cf. TPM_SET_VENDOR

	/** Queries the selection size that can be used with 1.1 and 1.2 structures. */
	/*
	 * NOTE: This define is missing in the TSS spec. The value for this define therefore is a custom
	 * (non-spec) value.
	 */
	public static final long TSS_TPMCAP_SELECT_SIZE = 0x1f;

	
	public static final long TSS_TPMCAP_SYM_MODE = 0x19;

	public static final long TSS_TPMCAP_TRANS_ES = 0x1b;

	public static final long TSS_TPMCAP_VERSION_VAL = 0x15;

	public static final long TSS_TPMSTATUS_DISABLEPUBSRKREAD = 0x00000016; // persistent flag

	public static final long TSS_TPMSTATUS_ENABLE_REVOKEEK = 0x0000001A; // persistent flag

	public static final long TSS_TPMSTATUS_FIPS = 0x00000019; // persistent flag

	public static final long TSS_TPMSTATUS_MAINTENANCEUSED = 0x00000017; // persistent flag

	public static final long TSS_TPMSTATUS_NV_LOCK = 0x0000001B; // persistent flag

	public static final long TSS_TPMSTATUS_OPERATOR_INSTALLED = 0x00000018; // persistent flag

	public static final long TSS_TPMSTATUS_TPM_ESTABLISHED = 0x0000001C; // persistent flag

	public static final long TSS_TSPATTRIB_ALG_IDENTIFIER = 0x00002000; // ASN.1 alg identifier

	public static final long TSS_TSPATTRIB_CONTEXT_CONNECTION_VERSION = 0x00000005;

	public static final long TSS_TSPATTRIB_CONTEXTTRANS_CONTROL = 0x00000008;

	public static final long TSS_TSPATTRIB_CONTEXTTRANS_MODE = 0x00000010;

	public static final long TSS_TSPATTRIB_CONTEXT_TRANSPORT = 0x00000004;

	public static final long TSS_TSPATTRIB_CONTEXT_VERSION_AUTO = 0x00000001;

	public static final long TSS_TSPATTRIB_CONTEXT_VERSION_MODE = 0x00000003;

	public static final long TSS_TSPATTRIB_CONTEXT_VERSION_V1_1 = 0x00000002;

	public static final long TSS_TSPATTRIB_CONTEXT_VERSION_V1_2 = 0x00000003;

	public static final long TSS_TSPATTRIB_DAA = 0x00000001;

	public static final long TSS_TSPATTRIB_DAA_CALLBACK_SIGN = 0x00000003;

	public static final long TSS_TSPATTRIB_DAA_CALLBACK_VERIFYSIGNATURE = 0x00000004;

	public static final long TSS_TSPATTRIB_DAACOMMIT_NUMBER = 0x00000001; // UINT32

	public static final long TSS_TSPATTRIB_DAACOMMIT_SELECTION = 0x00000002;

	public static final long TSS_TSPATTRIB_DAACOMMIT_COMMITMENTS = 0x00000003;

	public static final long TSS_TSPATTRIB_DAA_SIGN = 0x00000002;

	public static final long TSS_TSPATTRIB_DELFAMILY_INFO = 0x00000002;

	public static final long TSS_TSPATTRIB_DELFAMILYINFO_FAMILYID = 0x00000005;

	public static final long TSS_TSPATTRIB_DELFAMILYINFO_LABEL = 0x00000003;

	public static final long TSS_TSPATTRIB_DELFAMILYINFO_VERCOUNT = 0x00000004;

	public static final long TSS_TSPATTRIB_DELFAMILY_STATE = 0x00000001;

	public static final long TSS_TSPATTRIB_DELFAMILYSTATE_ENABLED = 0x00000002;

	public static final long TSS_TSPATTRIB_DELFAMILYSTATE_LOCKED = 0x00000001;

	public static final long TSS_TSPATTRIB_DISABLE_TRANSPORT = 0x00000000;

	public static final long TSS_TSPATTRIB_ENABLE_TRANSPORT = 0x00000001;

	public static final long TSS_TSPATTRIB_ENCDATAPCR_DIGEST_ATRELEASE = 0x00000003;

	public static final long TSS_TSPATTRIB_ENCDATA_PCR_LONG = 0x00000018;

	public static final long TSS_TSPATTRIB_ENCDATAPCRLONG_CREATION_SELECTION = 0x00000007;

	public static final long TSS_TSPATTRIB_ENCDATAPCRLONG_DIGEST_ATCREATION = 0x00000009;

	public static final long TSS_TSPATTRIB_ENCDATAPCRLONG_DIGEST_ATRELEASE = 0x0000000A;

	public static final long TSS_TSPATTRIB_ENCDATAPCRLONG_LOCALITY_ATCREATION = 0x00000005;

	public static final long TSS_TSPATTRIB_ENCDATAPCRLONG_LOCALITY_ATRELEASE = 0x00000006;

	public static final long TSS_TSPATTRIB_ENCDATAPCRLONG_RELEASE_SELECTION = 0x00000008;

	public static final long TSS_TSPATTRIB_ENCDATA_SEAL = 0x00000020;

	public static final long TSS_TSPATTRIB_ENCDATASEAL_NO_PROTECT = 0x00000000;

	public static final long TSS_TSPATTRIB_ENCDATASEAL_PROTECT = 0x00000001;

	public static final long TSS_TSPATTRIB_ENCDATASEAL_PROTECT_MODE = 0x00000001;

	public static final long TSS_TSPATTRIB_KEY_CMKINFO = 0x00000400; // CMK info

	public static final long TSS_TSPATTRIB_KEY_CONTROLBIT = 0x00000200; // key control flags

	public static final long TSS_TSPATTRIB_KEYINFO_CMK = 0x00000680; // if true then key

	public static final long TSS_TSPATTRIB_KEYINFO_CMK_MA_APPROVAL = 0x00000010;

	public static final long TSS_TSPATTRIB_KEYINFO_CMK_MA_DIGEST = 0x00000020;

	public static final long TSS_TSPATTRIB_KEYINFO_KEYSTRUCT = 0x00000700; // type of key struct

	public static final long TSS_TSPATTRIB_KEY_PCR_LONG = 0x000001c0; // PCR_INFO_LONG for the key

	public static final long TSS_TSPATTRIB_KEYPCRLONG_CREATION_SELECTION = 0x000C0000; /* DATA */

	public static final long TSS_TSPATTRIB_KEYPCRLONG_DIGEST_ATCREATION = 0x00140000; /* DATA */

	public static final long TSS_TSPATTRIB_KEYPCRLONG_DIGEST_ATRELEASE = 0x00180000; /* DATA */

	public static final long TSS_TSPATTRIB_KEYPCRLONG_LOCALITY_ATCREATION = 0x00040000; /* UINT32 */

	public static final long TSS_TSPATTRIB_KEYPCRLONG_LOCALITY_ATRELEASE = 0x00080000; /* UINT32 */

	public static final long TSS_TSPATTRIB_KEYPCRLONG_RELEASE_SELECTION = 0x00100000; /* DATA */

	public static final long TSS_TSPATTRIB_NV_DATASIZE = 0x00000004;

	public static final long TSS_TSPATTRIB_NV_INDEX = 0x00000001;

	public static final long TSS_TSPATTRIB_NV_PCR = 0x00000005;

	public static final long TSS_TSPATTRIB_NVPCR_READDIGESTATRELEASE = 0x02000000;

	public static final long TSS_TSPATTRIB_NVPCR_READLOCALITYATRELEASE = 0x03000000;

	public static final long TSS_TSPATTRIB_NVPCR_READPCRSELECTION = 0x01000000;

	public static final long TSS_TSPATTRIB_NVPCR_WRITEDIGESTATRELEASE = 0x05000000;

	public static final long TSS_TSPATTRIB_NVPCR_WRITELOCALITYATRELEASE = 0x06000000;

	public static final long TSS_TSPATTRIB_NVPCR_WRITEPCRSELECTION = 0x04000000;

	public static final long TSS_TSPATTRIB_NV_PERMISSIONS = 0x00000002;

	public static final long TSS_TSPATTRIB_NV_STATE = 0x00000003;

	public static final long TSS_TSPATTRIB_NVSTATE_READSTCLEAR = 0x00100000;

	public static final long TSS_TSPATTRIB_NVSTATE_WRITEDEFINE = 0x00300000;

	public static final long TSS_TSPATTRIB_NVSTATE_WRITESTCLEAR = 0x00200000;

	public static final long TSS_TSPATTRIB_PCRS_INFO = 0x00000001; // info

	public static final long TSS_TSPATTRIB_PCRSINFO_PCRSTRUCT = 0x00000001; // type of pcr struct

	public static final long TSS_TSPATTRIB_POLDEL_FAMILYID = 0x00000006;

	public static final long TSS_TSPATTRIB_POLDEL_INDEX = 0x00000002;

	public static final long TSS_TSPATTRIB_POLDEL_KEYBLOB = 0x00000009;

	public static final long TSS_TSPATTRIB_POLDEL_LABEL = 0x00000005;

	public static final long TSS_TSPATTRIB_POLDEL_OWNERBLOB = 0x00000008;

	public static final long TSS_TSPATTRIB_POLDELPCR_DIGESTATRELEASE = 0x00000002;

	public static final long TSS_TSPATTRIB_POLDELPCR_LOCALITY = 0x00000001;

	public static final long TSS_TSPATTRIB_POLDELPCR_SELECTION = 0x00000003;

	public static final long TSS_TSPATTRIB_POLDEL_PER1 = 0x00000003;

	public static final long TSS_TSPATTRIB_POLDEL_PER2 = 0x00000004;

	public static final long TSS_TSPATTRIB_POLDEL_TYPE = 0x00000001;

	public static final long TSS_TSPATTRIB_POLDEL_VERCOUNT = 0x00000007;

	public static final long TSS_TSPATTRIB_POLICY_DELEGATION_INFO = 0x00000001;

	public static final long TSS_TSPATTRIB_POLICY_DELEGATION_PCR = 0x00000002;

	public static final long TSS_TSPATTRIB_TRANSPORT_AUTHENTIC_CHANNEL = 0x00000002;

	public static final long TSS_TSPATTRIB_TRANSPORT_DEFAULT_ENCRYPTION = 0x00000001;

	public static final long TSS_TSPATTRIB_TRANSPORT_EXCLUSIVE = 0x00000004;

	public static final long TSS_TSPATTRIB_TRANSPORT_NO_DEFAULT_ENCRYPTION = 0x00000000;

	public static final long TSS_TSPATTRIB_TRANSPORT_STATIC_AUTH = 0x00000008;

	public static final long TSS_TSPCAP_COLLATE_ALG = 0x00000014;

	public static final long TSS_TSPCAP_RETURNVALUE_INFO = 0x00000015;

	public static final long TSS_TSPCAP_MANUFACTURER = 0x00000013;

	public static final long TSS_TSPCAP_PROP_MANUFACTURER_ID = 0x00000103;

	public static final long TSS_TSPCAP_PROP_MANUFACTURER_STR = 0x00000102;

	public static final long TSS_TSPCAP_PROP_RETURNVALUE_INFO = 0x00000201;

	public static final long TSS_RT_KEY = 0x00000010;

	public static final long TSS_RT_AUTH = 0x00000020;

	public static final long TSS_RT_TRANS = 0x00000030;

	public static final long TSS_RT_COUNTER = 0x00000040;
	
	
}
