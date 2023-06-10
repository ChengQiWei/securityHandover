/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.api.constants.tpm;


/**
 * This class contains constants and flags that are used when communicating with a TPM.
 */
public class TcTpmConstants {

	// Making constructor unavailable.
	protected TcTpmConstants()
	{
	}

	public static final short TPM_PT_ASYM = 0x01;

	public static final short TPM_PT_BIND = 0x02;

	public static final short TPM_PT_MIGRATE = 0x03;

	public static final short TPM_PT_MAINT = 0x04;

	public static final short TPM_PT_SEAL = 0x05;

	public static final short TPM_PT_MIGRATE_RESTRICTED = 0x06;

	public static final short TPM_PT_MIGRATE_EXTERNAL = 0x07;

	public static final short TPM_PT_CMK_MIGRATE = 0x08;

	public static final short TPM_ET_XOR = 0x00;

	public static final short TPM_ET_AES = 0x06;

	public static final short TPM_AUTH_NEVER = 0x00;

	public static final short TPM_AUTH_ALWAYS = 0x01;

	public static final short TPM_AUTH_PRIV_USE_ONLY = 0x11;

	public static final int TPM_TAG_CONTEXTBLOB = 0x0001;

	public static final int TPM_TAG_CONTEXT_SENSITIVE = 0x0002;

	public static final int TPM_TAG_CONTEXTPOINTER = 0x0003;

	public static final int TPM_TAG_CONTEXTLIST = 0x0004;

	public static final int TPM_TAG_SIGNINFO = 0x0005;

	public static final int TPM_TAG_PCR_INFO_LONG = 0x0006;

	public static final int TPM_TAG_PERSISTENT_FLAGS = 0x0007;

	public static final int TPM_TAG_VOLATILE_FLAGS = 0x0008;

	public static final int TPM_TAG_PERSISTENT_DATA = 0x0009;

	public static final int TPM_TAG_VOLATILE_DATA = 0x000a;

	public static final int TPM_TAG_SV_DATA = 0x000b;

	public static final int TPM_TAG_EK_BLOB = 0x000c;

	public static final int TPM_TAG_EK_BLOB_AUTH = 0x000d;

	public static final int TPM_TAG_COUNTER_VALUE = 0x000e;

	public static final int TPM_TAG_TRANSPORT_INTERNAL = 0x000f;

	public static final int TPM_TAG_TRANSPORT_LOG_IN = 0x0010;

	public static final int TPM_TAG_TRANSPORT_LOG_OUT = 0x0011;

	public static final int TPM_TAG_AUDIT_EVENT_IN = 0x0012;

	public static final int TPM_TAG_AUDIT_EVENT_OUT = 0x0013;

	public static final int TPM_TAG_CURRENT_TICKS = 0x0014;

	public static final int TPM_TAG_KEY = 0x0015;

	public static final int TPM_TAG_STORED_DATA12 = 0x0016;

	public static final int TPM_TAG_NV_ATTRIBUTES = 0x0017;

	public static final int TPM_TAG_NV_DATA_PUBLIC = 0x0018;

	public static final int TPM_TAG_NV_DATA_SENSITIVE = 0x0019;

	public static final int TPM_TAG_DELEGATIONS = 0x001a;

	public static final int TPM_TAG_DELEGATE_PUBLIC = 0x001b;

	public static final int TPM_TAG_DELEGATE_TABLE_ROW = 0x001c;

	public static final int TPM_TAG_TRANSPORT_AUTH = 0x001d;

	public static final int TPM_TAG_TRANSPORT_PUBLIC = 0x001e;

	public static final int TPM_TAG_PERMANENT_FLAGS = 0x001f;

	public static final int TPM_TAG_STCLEAR_FLAGS = 0x0020;

	public static final int TPM_TAG_STANY_FLAGS = 0x0021;

	public static final int TPM_TAG_PERMANENT_DATA = 0x0022;

	public static final int TPM_TAG_STCLEAR_DATA = 0x0023;

	public static final int TPM_TAG_STANY_DATA = 0x0024;

	public static final int TPM_TAG_FAMILY_TABLE_ENTRY = 0x0025;

	public static final int TPM_TAG_DELEGATE_SENSITIVE = 0x0026;

	public static final int TPM_TAG_DELG_KEY_BLOB = 0x0027;

	public static final int TPM_TAG_KEY12 = 0x0028;

	public static final int TPM_TAG_CERTIFY_INFO2 = 0x0029;

	public static final int TPM_TAG_DELEGATE_OWNER_BLOB = 0x002a;

	public static final int TPM_TAG_EK_BLOB_ACTIVATE = 0x002b;

	public static final int TPM_TAG_DAA_BLOB = 0x002c;

	public static final int TPM_TAG_DAA_CONTEXT = 0x002d;

	public static final int TPM_TAG_DAA_ENFORCE = 0x002e;

	public static final int TPM_TAG_DAA_ISSUER = 0x002f;

	public static final int TPM_TAG_CAP_VERSION_INFO = 0x0030;

	public static final int TPM_TAG_DAA_SENSITIVE = 0x0031;

	public static final int TPM_TAG_DAA_TPM = 0x0032;

	public static final int TPM_TAG_CMK_MIGAUTH = 0x0033;

	public static final int TPM_TAG_CMK_SIGTICKET = 0x0034;

	public static final int TPM_TAG_CMK_MA_APPROVAL = 0x0035;

	public static final int TPM_TAG_QUOTE_INFO2 = 0x0036;

	public static final int TPM_ET_KEYHANDLE = 0x0001;

	public static final int TPM_ET_OWNER = 0x0002;

	public static final int TPM_ET_DATA = 0x0003;

	public static final int TPM_ET_SRK = 0x0004;

	public static final int TPM_ET_KEY = 0x0005;

	public static final int TPM_ET_REVOKE = 0x0006;

	public static final int TPM_ET_DEL_OWNER_BLOB = 0x0007;

	public static final int TPM_ET_DEL_ROW = 0x0008;

	public static final int TPM_ET_DEL_KEY_BLOB = 0x0009;

	public static final int TPM_ET_COUNTER = 0x000a;

	public static final int TPM_ET_NV = 0x000b;

	public static final int TPM_ET_RESERVED_HANDLE = 0x0040;

	public static final int TPM_ST_CLEAR = 0x0001;

	public static final int TPM_ST_STATE = 0x0002;

	public static final int TPM_ST_DEACTIVATED = 0x0003;

	public static final int TPM_PID_OIAP = 0x0001;

	public static final int TPM_PID_OSAP = 0x0002;

	public static final int TPM_PID_ADIP = 0x0003;

	public static final int TPM_PID_ADCP = 0x0004;

	public static final int TPM_PID_OWNER = 0x0005;

	public static final int TPM_PID_DSAP = 0x0006;

	public static final int TPM_PID_TRANSPORT = 0x0007;

	public static final int TPM_PHYSICAL_PRESENCE_LOCK = 0x0004;

	public static final int TPM_PHYSICAL_PRESENCE_PRESENT = 0x0008;

	public static final int TPM_PHYSICAL_PRESENCE_NOTPRESENT = 0x0010;

	public static final int TPM_PHYSICAL_PRESENCE_CMD_ENABLE = 0x0020;

	public static final int TPM_PHYSICAL_PRESENCE_HW_ENABLE = 0x0040;

	public static final int TPM_PHYSICAL_PRESENCE_LIFETIME_LOCK = 0x0080;

	public static final int TPM_PHYSICAL_PRESENCE_CMD_DISABLE = 0x0100;

	public static final int TPM_PHYSICAL_PRESENCE_HW_DISABLE = 0x0200;

	public static final int TPM_MS_MIGRATE = 0x0001;

	public static final int TPM_MS_REWRAP = 0x0002;

	public static final int TPM_MS_MAINT = 0x0003;

	public static final int TPM_MS_RESTRICT_MIGRATE = 0x0004;

	public static final int TPM_MS_RESTRICT_APPROVE_DOUBLE = 0x0005;

	public static final int TPM_MS_RESTRICT_MIGRATE_EXTERNAL = 0x0006;

	public static final int TPM_EK_TYPE_ACTIVATE = 0x0001;

	public static final int TPM_EK_TYPE_AUTH = 0x0002;

	public static final int TPM_PS_PC_11 = 0x0001;

	public static final int TPM_PS_PC_12 = 0x0002;

	public static final int TPM_PS_PDA_12 = 0x0003;

	public static final int TPM_PS_Server_12 = 0x0004;

	public static final int TPM_PS_Mobile_12 = 0x0005;

	public static final int TPM_KEY_SIGNING = 0x0010;

	public static final int TPM_KEY_STORAGE = 0x0011;

	public static final int TPM_KEY_IDENTITY = 0x0012;

	public static final int TPM_KEY_AUTHCHANGE = 0x0013;

	public static final int TPM_KEY_BIND = 0x0014;

	public static final int TPM_KEY_LEGACY = 0x0015;

	public static final int TPM_KEY_MIGRATE = 0x0016;

	public static final int TPM_SS_NONE = 0x0001;

	public static final int TPM_SS_RSASSAPKCS1v15_SHA1 = 0x0002;

	public static final int TPM_SS_RSASSAPKCS1v15_DER = 0x0003;

	public static final int TPM_SS_RSASSAPKCS1v15_INFO = 0x0004;

	public static final int TPM_ES_NONE = 0x0001;

	public static final int TPM_ES_RSAESPKCSv15 = 0x0002;

	public static final int TPM_ES_RSAESOAEP_SHA1_MGF1 = 0x0003;

	public static final int TPM_ES_SYM_CNT = 0x0004;

	public static final int TPM_ES_SYM_OFB = 0x0005;

	public static final int TPM_ES_SYM_CBC_PKCS5PAD = 0x00ff;

	public static final int TPM_TAG_RQU_COMMAND = 0x00c1;

	public static final int TPM_TAG_RQU_AUTH1_COMMAND = 0x00c2;

	public static final int TPM_TAG_RQU_AUTH2_COMMAND = 0x00c3;

	public static final int TPM_TAG_RSP_COMMAND = 0x00c4;

	public static final int TPM_TAG_RSP_AUTH1_COMMAND = 0x00c5;

	public static final int TPM_TAG_RSP_AUTH2_COMMAND = 0x00c6;

	public static final long TPM_RT_KEY = 0x00000001;

	public static final long TPM_RT_AUTH = 0x00000002;

	public static final long TPM_RT_HASH = 0x00000003;

	public static final long TPM_RT_TRANS = 0x00000004;

	public static final long TPM_RT_CONTEXT = 0x00000005;

	public static final long TPM_RT_COUNTER = 0x00000006;

	public static final long TPM_RT_DELEGATE = 0x00000007;

	public static final long TPM_RT_DAA_TPM = 0x00000008;

	public static final long TPM_RT_DAA_V0 = 0x00000009;

	public static final long TPM_RT_DAA_V1 = 0x0000000a;

	public static final long TPM_KH_SRK = 0x40000000;

	public static final long TPM_KH_OWNER = 0x40000001;

	public static final long TPM_KH_REVOKE = 0x40000002;

	public static final long TPM_KH_TRANSPORT = 0x40000003;

	public static final long TPM_KH_OPERATOR = 0x40000004;

	public static final long TPM_KH_ADMIN = 0x40000005;

	public static final long TPM_KH_EK = 0x40000006;

	public static final long TPM_ALG_RSA = 0x00000001;

	public static final long TPM_ALG_DES = 0x00000002;

	public static final long TPM_ALG_3DES = 0x00000003;

	public static final long TPM_ALG_SHA = 0x00000004;

	public static final long TPM_ALG_HMAC = 0x00000005;

	public static final long TPM_ALG_AES = 0x00000006;

	public static final long TPM_ALG_MGF1 = 0x00000007;

	public static final long TPM_ALG_AES192 = 0x00000008;

	public static final long TPM_ALG_AES256 = 0x00000009;

	public static final long TPM_ALG_XOR = 0x0000000a;

	public static final long TPM_REDIRECTION = 0x00000001;

	public static final long TPM_MIGRATABLE = 0x00000002;

	public static final long TPM_VOLATILE = 0x00000004;

	public static final long TPM_PCRIGNOREDONREAD = 0x00000008;

	public static final long TPM_MIGRATEAUTHORITY = 0x00000010;

	public static final long TPM_CMK_DELEGATE_SIGNING = 1 << 31;

	public static final long TPM_CMK_DELEGATE_STORAGE = 1 << 30;

	public static final long TPM_CMK_DELEGATE_BIND = 1 << 29;

	public static final long TPM_CMK_DELEGATE_LEGACY = 1 << 28;

	public static final long TPM_CMK_DELEGATE_MIGRATE = 1 << 27;

	public static final long TPM_PF_DISABLE                      = 1 <<  0;

	public static final long TPM_PF_OWNERSHIP                    = 1 <<  1;

	public static final long TPM_PF_DEACTIVATED                  = 1 <<  2;

	public static final long TPM_PF_READPUBEK                    = 1 <<  3;

	public static final long TPM_PF_DISABLEOWNERCLEAR            = 1 <<  4;

	public static final long TPM_PF_ALLOWMAINTENANCE             = 1 <<  5;

	public static final long TPM_PF_PHYSICALPRESENCELIFETIMELOCK = 1 <<  6;

	public static final long TPM_PF_PHYSICALPRESENCEHWENABLE     = 1 <<  7;

	public static final long TPM_PF_PHYSICALPRESENCECMDENABLE    = 1 <<  8;

	public static final long TPM_PF_CEKPUSED                     = 1 <<  9;

	public static final long TPM_PF_TPMPOST                      = 1 << 10;

	public static final long TPM_PF_TPMPOSTLOCK                  = 1 << 11;

	public static final long TPM_PF_FIPS                         = 1 << 12;

	public static final long TPM_PF_OPERATOR                     = 1 << 13;

	public static final long TPM_PF_ENABLEREVOKEEK               = 1 << 14;

	public static final long TPM_PF_NV_LOCKED                    = 1 << 15;

	public static final long TPM_PF_READSRKPUB                   = 1 << 16;

	public static final long TPM_PF_RESETESTABLISHMENTBIT        = 1 << 17;

	public static final long TPM_PF_MAINTENANCEDONE              = 1 << 18;

	public static final long TPM_SF_DEACTIVATED          = 1 << 0;

	public static final long TPM_SF_DISABLEFORCECLEAR    = 1 << 1;

	public static final long TPM_SF_PHYSICALPRESENCE     = 1 << 2;

	public static final long TPM_SF_PHYSICALPRESENCELOCK = 1 << 3;

	public static final long TPM_SF_GLOBALLOCK           = 1 << 4;

	public static final long TPM_AF_POSTINITIALIZE = 0x00000001;

	public static final long TPM_AF_LOCALITYMODIFIER = 0x00000002;

	public static final long TPM_AF_TRANSPORTEXCLUSIVE = 0x00000003;

	public static final long TPM_AF_TOSPRESENT = 0x00000004;

	public static final long TPM_LOC_FOUR = 1 << 4;

	public static final long TPM_LOC_THREE = 1 << 3;

	public static final long TPM_LOC_TWO = 1 << 2;

	public static final long TPM_LOC_ONE = 1 << 1;

	public static final long TPM_LOC_ZERO = 1 << 0;

	public static final long TPM_LOC_ALL = TPM_LOC_ZERO | TPM_LOC_ONE   |
	                                       TPM_LOC_TWO  | TPM_LOC_THREE |
	                                       TPM_LOC_FOUR ;

	public static final long TPM_KEY_CONTROL_OWNER_EVICT = 0x00000001;

	public static final long TPM_TRANSPORT_ENCRYPT = 0x00000001;

	public static final long TPM_TRANSPORT_LOG = 0x00000002;

	public static final long TPM_TRANSPORT_EXCLUSIVE = 0x00000004;

	/** This NV index constant has the <b>D-bit</b> set!<br>
	 *  It is used to lock a TPM!<br>
	 *  Usage for a <b>TPM_NV_DefineSpace</b> command call might permanently damage a TPM! */
	public static final long TPM_NV_INDEX_LOCK = 0xffffffffL;

	public static final long TPM_NV_INDEX0 = 0x00000000;

	/** This NV index constant has the <b>D-bit</b> set!<br>
	 *  Usage for a <b>TPM_NV_DefineSpace</b> command call might permanently damage a TPM! */
	public static final long TPM_NV_INDEX_DIR = 0x10000001;

	/** This NV index constant has the <b>D-bit</b> set!<br>
	 *  Usage for a <b>TPM_NV_DefineSpace</b> command call might permanently damage a TPM! */
	public static final long TPM_NV_INDEX_EKCert = 0x1000f000;

	/** This NV index constant has the <b>D-bit</b> set!<br>
	 *  Usage for a <b>TPM_NV_DefineSpace</b> command call might permanently damage a TPM! */
	public static final long TPM_NV_INDEX_TPM_CC = 0x1000f001;

	/** This NV index constant has the <b>D-bit</b> set!<br>
	 *  Usage for a <b>TPM_NV_DefineSpace</b> command call might permanently damage a TPM! */
	public static final long TPM_NV_INDEX_PlatformCert = 0x1000f002;

	/** This NV index constant has the <b>D-bit</b> set!<br>
	 *  Usage for a <b>TPM_NV_DefineSpace</b> command call might permanently damage a TPM! */
	public static final long TPM_NV_INDEX_Platform_CC = 0x1000f003;

	public static final long TPM_NV_INDEX_TRIAL = 0x0000f004;

	/** This constant represents the base of an index range. Don't use as an index! */
	public static final long TPM_NV_INDEX_TSS_BASE = 0x10011100;

	/** This constant represents the base of an index range. Don't use as an index! */
	public static final long TPM_NV_INDEX_PC_BASE = 0x10011200;

	/** This constant represents the base of an index range. Don't use as an index! */
	public static final long TPM_NV_INDEX_SERVER_BASE = 0x10011300;

	/** This constant represents the base of an index range. Don't use as an index! */
	public static final long TPM_NV_INDEX_MOBILE_BASE = 0x10011400;

	/** This constant represents the base of an index range. Don't use as an index! */
	public static final long TPM_NV_INDEX_PERIPHERAL_BASE = 0x10011500;

	/** This constant represents the base of an index range. Don't use as an index! */
	public static final long TPM_NV_INDEX_GROUP_RESV_BASE = 0x10010000;

	public static final long TPM_NV_PER_READ_STCLEAR = 1 << 31;

	public static final long TPM_NV_PER_AUTHREAD = 1 << 18;

	public static final long TPM_NV_PER_OWNERREAD = 1 << 17;

	public static final long TPM_NV_PER_PPREAD = 1 << 16;

	public static final long TPM_NV_PER_GLOBALLOCK = 1 << 15;

	public static final long TPM_NV_PER_WRITE_STCLEAR = 1 << 14;

	public static final long TPM_NV_PER_WRITEDEFINE = 1 << 13;

	public static final long TPM_NV_PER_WRITEALL = 1 << 12;

	public static final long TPM_NV_PER_AUTHWRITE = 1 << 2;

	public static final long TPM_NV_PER_OWNERWRITE = 1 << 1;

	public static final long TPM_NV_PER_PPWRITE = 1 << 0;

	public static final long TPM_DELEGATE_SetOrdinalAuditStatus = 1 << 30;

	public static final long TPM_DELEGATE_DirWriteAuth = 1 << 29;

	public static final long TPM_DELEGATE_CMK_ApproveMA = 1 << 28;

	public static final long TPM_DELEGATE_CMK_CreateTicket = 1 << 26;

	public static final long TPM_DELEGATE_Delegate_LoadOwnerDelegation = 1 << 24;

	public static final long TPM_DELEGATE_DAA_Join = 1 << 23;

	public static final long TPM_DELEGATE_AuthorizeMigrationKey = 1 << 22;

	public static final long TPM_DELEGATE_CreateMaintenanceArchive = 1 << 21;

	public static final long TPM_DELEGATE_LoadMaintenanceArchive = 1 << 20;

	public static final long TPM_DELEGATE_KillMaintenanceFeature = 1 << 19;

	public static final long TPM_DELEGATE_OwnerReadInteralPub = 1 << 18;

	public static final long TPM_DELEGATE_ResetLockValue = 1 << 17;

	public static final long TPM_DELEGATE_OwnerClear = 1 << 16;

	public static final long TPM_DELEGATE_DisableOwnerClear = 1 << 15;

	public static final long TPM_DELEGATE_OwnerSetDisable = 1 << 13;

	public static final long TPM_DELEGATE_SetCapability = 1 << 12;

	public static final long TPM_DELEGATE_MakeIdentity = 1 << 11;

	public static final long TPM_DELEGATE_ActivateIdentity = 1 << 10;

	public static final long TPM_DELEGATE_OwnerReadPubek = 1 << 9;

	public static final long TPM_DELEGATE_DisablePubekRead = 1 << 8;

	public static final long TPM_DELEGATE_SetRedirection = 1 << 7;

	public static final long TPM_DELEGATE_FieldUpgrade = 1 << 6;

	public static final long TPM_DELEGATE_Delegate_UpdateVerification = 1 << 5;

	public static final long TPM_DELEGATE_CreateCounter = 1 << 4;

	public static final long TPM_DELEGATE_ReleaseCounterOwner = 1 << 3;

	public static final long TPM_DELEGATE_DelegateManage = 1 << 2;

	public static final long TPM_DELEGATE_Delegate_CreateOwnerDelegation = 1 << 1;

	public static final long TPM_DELEGATE_DAA_Sign = 1 << 0;

	public static final long TPM_KEY_DELEGATE_CMK_ConvertMigration = 1 << 28;

	public static final long TPM_KEY_DELEGATE_TickStampBlob = 1 << 27;

	public static final long TPM_KEY_DELEGATE_ChangeAuthAsymStart = 1 << 26;

	public static final long TPM_KEY_DELEGATE_ChangeAuthAsymFinish = 1 << 25;

	public static final long TPM_KEY_DELEGATE_CMK_CreateKey = 1 << 24;

	public static final long TPM_KEY_DELEGATE_MigrateKey = 1 << 23;

	public static final long TPM_KEY_DELEGATE_LoadKey2 = 1 << 22;

	public static final long TPM_KEY_DELEGATE_EstablishTransport = 1 << 21;

	public static final long TPM_KEY_DELEGATE_ReleaseTransportSigned = 1 << 20;

	public static final long TPM_KEY_DELEGATE_Quote2 = 1 << 19;

	public static final long TPM_KEY_DELEGATE_Sealx = 1 << 18;

	public static final long TPM_KEY_DELEGATE_MakeIdentity = 1 << 17;

	public static final long TPM_KEY_DELEGATE_ActivateIdentity = 1 << 16;

	public static final long TPM_KEY_DELEGATE_GetAuditDigestSigned = 1 << 15;

	public static final long TPM_KEY_DELEGATE_Sign = 1 << 14;

	public static final long TPM_KEY_DELEGATE_CertifyKey2 = 1 << 13;

	public static final long TPM_KEY_DELEGATE_CertifyKey = 1 << 12;

	public static final long TPM_KEY_DELEGATE_CreateWrapKey = 1 << 11;

	public static final long TPM_KEY_DELEGATE_CMK_CreateBlob = 1 << 10;

	public static final long TPM_KEY_DELEGATE_CreateMigrationBlob = 1 << 9;

	public static final long TPM_KEY_DELEGATE_ConvertMigrationBlob = 1 << 8;

	public static final long TPM_KEY_DELEGATE_CreateKeyDelegation = 1 << 7;

	public static final long TPM_KEY_DELEGATE_ChangeAuth = 1 << 6;

	public static final long TPM_KEY_DELEGATE_GetPubKey = 1 << 5;

	public static final long TPM_KEY_DELEGATE_UnBind = 1 << 4;

	public static final long TPM_KEY_DELEGATE_Quote = 1 << 3;

	public static final long TPM_KEY_DELEGATE_Unseal = 1 << 2;

	public static final long TPM_KEY_DELEGATE_Seal = 1 << 1;

	public static final long TPM_KEY_DELEGATE_LoadKey = 1 << 0;

	public static final long TPM_FAMILY_CREATE = 0x00000001;

	public static final long TPM_FAMILY_ENABLE = 0x00000002;

	public static final long TPM_FAMILY_ADMIN = 0x00000003;

	public static final long TPM_FAMILY_INVALIDATE = 0x00000004;

	public static final long TPM_FAMFLAG_DELEGATE_ADMIN_LOCK = 1 << 1;

	public static final long TPM_FAMFLAG_ENABLE = 1 << 0;

	public static final long TPM_DEL_OWNER_BITS = 0x00000001;

	public static final long TPM_DEL_KEY_BITS = 0x00000002;

	public static final long TPM_CAP_ORD = 0x00000001;

	public static final long TPM_CAP_ALG = 0x00000002;

	public static final long TPM_CAP_PID = 0x00000003;

	public static final long TPM_CAP_FLAG = 0x00000004;

	public static final long TPM_CAP_PROPERTY = 0x00000005;

	public static final long TPM_CAP_VERSION = 0x00000006;

	public static final long TPM_CAP_KEY_HANDLE = 0x00000007;

	public static final long TPM_CAP_CHECK_LOADED = 0x00000008;

	public static final long TPM_CAP_SYM_MODE = 0x00000009;

	public static final long TPM_CAP_KEY_STATUS = 0x0000000C;

	public static final long TPM_CAP_NV_LIST = 0x0000000D;

	public static final long TPM_CAP_MFR = 0x00000010;

	public static final long TPM_CAP_NV_INDEX = 0x00000011;

	public static final long TPM_CAP_TRANS_ALG = 0x00000012;

	public static final long TPM_CAP_HANDLE = 0x00000014;

	public static final long TPM_CAP_TRANS_ES = 0x00000015;

	public static final long TPM_CAP_AUTH_ENCRYPT = 0x00000017;

	public static final long TPM_CAP_SELECT_SIZE = 0x00000018;

	public static final long TPM_CAP_VERSION_VAL = 0x0000001A;

	public static final long TPM_CAP_FLAG_PERMANENT = 0x00000108;

	public static final long TPM_CAP_FLAG_VOLATILE = 0x00000109;

	public static final long TPM_CAP_PROP_PCR = 0x00000101;

	public static final long TPM_CAP_PROP_DIR = 0x00000102;

	public static final long TPM_CAP_PROP_MANUFACTURER = 0x00000103;

	public static final long TPM_CAP_PROP_KEYS = 0x00000104;

	public static final long TPM_CAP_PROP_MIN_COUNTER = 0x00000107;

	public static final long TPM_CAP_PROP_AUTHSESS = 0x0000010A;

	public static final long TPM_CAP_PROP_TRANSSESS = 0x0000010B;

	public static final long TPM_CAP_PROP_COUNTERS = 0x0000010C;

	public static final long TPM_CAP_PROP_MAX_AUTHSESS = 0x0000010D;

	public static final long TPM_CAP_PROP_MAX_TRANSSESS = 0x0000010E;

	public static final long TPM_CAP_PROP_MAX_COUNTERS = 0x0000010F;

	public static final long TPM_CAP_PROP_MAX_KEYS = 0x00000110;

	public static final long TPM_CAP_PROP_OWNER = 0x00000111;

	public static final long TPM_CAP_PROP_CONTEXT = 0x00000112;

	public static final long TPM_CAP_PROP_MAX_CONTEXT = 0x00000113;

	public static final long TPM_CAP_PROP_FAMILYROWS = 0x00000114;

	public static final long TPM_CAP_PROP_TIS_TIMEOUT = 0x00000115;

	public static final long TPM_CAP_PROP_STARTUP_EFFECT = 0x00000116;

	public static final long TPM_CAP_PROP_DELEGATE_ROW = 0x00000117;

	public static final long TPM_CAP_PROP_DAA_MAX = 0x00000119;

	public static final long TPM_CAP_PROP_DAA_SESS = 0x0000011A;

	public static final long TPM_CAP_PROP_CONTEXT_DIST = 0x0000011B;

	public static final long TPM_CAP_PROP_DAA_INTERRUPT = 0x0000011C;

	public static final long TPM_CAP_PROP_SESSIONS = 0x0000011D;

	public static final long TPM_CAP_PROP_MAX_SESSIONS = 0x0000011E;

	public static final long TPM_CAP_PROP_CMK_RESTRICTION = 0x0000011F;

	public static final long TPM_CAP_PROP_DURATION = 0x00000120;

	public static final long TPM_CAP_PROP_ACTIVE_COUNTER = 0x00000122;

	public static final long TPM_CAP_PROP_MAX_NV_AVAILABLE = 0x00000123;

	public static final long TPM_CAP_PROP_INPUT_BUFFER = 0x00000124;

	public static final long TPM_SET_PERM_FLAGS = 0x00000001;

	public static final long TPM_SET_PERM_DATA = 0x00000002;

	public static final long TPM_SET_STCLEAR_FLAGS = 0x00000003;

	public static final long TPM_SET_STCLEAR_DATA = 0x00000004;

	public static final long TPM_SET_STANY_FLAGS = 0x00000005;

	public static final long TPM_SET_STANY_DATA = 0x00000006;

	public static final long TPM_SET_VENDOR = 0x00000007;

	public static final long TPM_Vendor_Specific32 = 0x00000400;

	public static final long TPM_Vendor_Specific8 = 0x80;

	public static final long TPM_KEYHND_SRK = TPM_KH_SRK;

	public static final long TPM_KEYHND_OWNER = TPM_KH_OWNER;

	public static final long TPM_ALG_AES128 = TPM_ALG_AES;

	public static final long TPM_SHA1_160_HASH_LEN = 0x14;

	public static final long TPM_SHA1BASED_NONCE_LEN = TPM_SHA1_160_HASH_LEN;

	public static final long TPM_FAMILY_TABLE_ENTRY_MIN = 8;

	public static final long TPM_NUM_DELEGATE_TABLE_ENTRY_MIN = 2;

	public static final long TPM_CAP_PROP_SLOTS = TPM_CAP_PROP_KEYS;

	public static final long TPM_DAA_SIZE_r0 = 43;

	public static final long TPM_DAA_SIZE_r1 = 43;

	public static final long TPM_DAA_SIZE_r2 = 128;

	public static final long TPM_DAA_SIZE_r3 = 168;

	public static final long TPM_DAA_SIZE_r4 = 219;

	public static final long TPM_DAA_SIZE_NT = 20;

	public static final long TPM_DAA_SIZE_v0 = 128;

	public static final long TPM_DAA_SIZE_v1 = 192;

	public static final long TPM_DAA_SIZE_NE = 256;

	public static final long TPM_DAA_SIZE_w = 256;

	public static final long TPM_DAA_SIZE_issuerModulus = 256;

	public static final long TPM_DAA_power0 = 104;

	public static final long TPM_DAA_power1 = 1024;

	public static final long TPM_REDIR_GPIO = 0x00000001;

	public static final long TPM_SYM_MODE_ECB = 0x00000001;

	public static final long TPM_SYM_MODE_CBC = 0x00000002;

	public static final long TPM_SYM_MODE_CFB = 0x00000003;

}
