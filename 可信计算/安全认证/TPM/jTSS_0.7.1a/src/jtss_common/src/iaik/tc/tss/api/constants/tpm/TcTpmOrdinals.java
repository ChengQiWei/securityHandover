/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */


package iaik.tc.tss.api.constants.tpm;


/**
 * This class contains the TPM command ordinals. 
 */
public class TcTpmOrdinals {

	// Making constructor unavailable.
	private TcTpmOrdinals() {
	}

	public static final long TPM_PROTECTED_COMMAND = 0x00000000;

	public static final long TPM_UNPROTECTED_COMMAND = 0x80000000;

	public static final long TPM_CONNECTION_COMMAND = 0x40000000;

	public static final long TPM_VENDOR_COMMAND = 0x20000000;

	public static final int TPM_MAIN = 0x0000;

	public static final int TPM_PC = 0x0001;

	public static final int TPM_PDA = 0x0002;

	public static final int TPM_CELL_PHONE = 0x0003;

	public static final int TPM_SERVER = 0x0004;

	public static final long TPM_PROTECTED_ORDINAL = TPM_MAIN
			| TPM_PROTECTED_COMMAND;

	public static final long TPM_UNPROTECTED_ORDINAL = TPM_MAIN
			| TPM_UNPROTECTED_COMMAND;

	public static final long TPM_CONNECTION_ORDINAL = TPM_MAIN
			| TPM_CONNECTION_COMMAND;

	public static final long TPM_ORD_OIAP = 0x0000000A;

	public static final long TPM_ORD_OSAP = 0x0000000B;

	public static final long TPM_ORD_ChangeAuth = 0x0000000C;

	public static final long TPM_ORD_TakeOwnership = 0x0000000D;

	public static final long TPM_ORD_ChangeAuthAsymStart = 0x0000000E;

	public static final long TPM_ORD_ChangeAuthAsymFinish = 0x0000000F;

	public static final long TPM_ORD_ChangeAuthOwner = 0x00000010;

	public static final long TPM_ORD_DSAP = 0x00000011;

	public static final long TPM_ORD_CMK_CreateTicket = 0x00000012;

	public static final long TPM_ORD_CMK_CreateKey = 0x00000013;

	public static final long TPM_ORD_Extend = 0x00000014;

	public static final long TPM_ORD_PcrRead = 0x00000015;

	public static final long TPM_ORD_Quote = 0x00000016;

	public static final long TPM_ORD_Seal = 0x00000017;

	public static final long TPM_ORD_Unseal = 0x00000018;

	public static final long TPM_ORD_DirWriteAuth = 0x00000019;

	public static final long TPM_ORD_DirRead = 0x0000001A;

	public static final long TPM_ORD_CMK_CreateBlob = 0x0000001B;

	public static final long TPM_ORD_CMK_SetRestrictions = 0x0000001C;

	public static final long TPM_ORD_CMK_ApproveMA = 0x0000001D;

	public static final long TPM_ORD_UnBind = 0x0000001E;

	public static final long TPM_ORD_CreateWrapKey = 0x0000001F;

	public static final long TPM_ORD_LoadKey = 0x00000020;

	public static final long TPM_ORD_GetPubKey = 0x00000021;

	public static final long TPM_ORD_EvictKey = 0x00000022;

	public static final long TPM_ORD_KeyControlOwner = 0x00000023;

	public static final long TPM_ORD_CMK_ConvertMigration = 0x00000024;

	public static final long TPM_ORD_MigrateKey = 0x00000025;

	public static final long TPM_ORD_CreateMigrationBlob = 0x00000028;

	public static final long TPM_ORD_DAA_Join = 0x00000029;

	public static final long TPM_ORD_ConvertMigrationBlob = 0x0000002A;

	public static final long TPM_ORD_AuthorizeMigrationKey = 0x0000002B;

	public static final long TPM_ORD_CreateMaintenanceArchive = 0x0000002C;

	public static final long TPM_ORD_LoadMaintenanceArchive = 0x0000002D;

	public static final long TPM_ORD_KillMaintenanceFeature = 0x0000002E;

	public static final long TPM_ORD_LoadManuMaintPub = 0x0000002F;

	public static final long TPM_ORD_ReadManuMaintPub = 0x00000030;

	public static final long TPM_ORD_DAA_Sign = 0x00000031;

	public static final long TPM_ORD_CertifyKey = 0x00000032;

	public static final long TPM_ORD_CertifyKey2 = 0x00000033;

	public static final long TPM_ORD_Sign = 0x0000003C;

	public static final long TPM_ORD_Sealx = 0x0000003D;

	public static final long TPM_ORD_Quote2 = 0x0000003E;

	public static final long TPM_ORD_SetCapability = 0x0000003F;
	
	public static final long TPM_ORD_ResetLockValue = 0x00000040;

	public static final long TPM_ORD_LoadKey2 = 0x00000041;

	public static final long TPM_ORD_GetRandom = 0x00000046;

	public static final long TPM_ORD_StirRandom = 0x00000047;

	public static final long TPM_ORD_SelfTestFull = 0x00000050;

	public static final long TPM_ORD_CertifySelfTest = 0x00000052;

	public static final long TPM_ORD_ContinueSelfTest = 0x00000053;

	public static final long TPM_ORD_GetTestResult = 0x00000054;

	public static final long TPM_ORD_Reset = 0x0000005A;

	public static final long TPM_ORD_OwnerClear = 0x0000005B;

	public static final long TPM_ORD_DisableOwnerClear = 0x0000005C;

	public static final long TPM_ORD_ForceClear = 0x0000005D;

	public static final long TPM_ORD_DisableForceClear = 0x0000005E;

	public static final long TPM_ORD_GetCapabilitySigned = 0x00000064;

	public static final long TPM_ORD_GetCapability = 0x00000065;

	public static final long TPM_ORD_GetCapabilityOwner = 0x00000066;

	public static final long TPM_ORD_OwnerSetDisable = 0x0000006E;

	public static final long TPM_ORD_PhysicalEnable = 0x0000006F;

	public static final long TPM_ORD_PhysicalDisable = 0x00000070;

	public static final long TPM_ORD_SetOwnerInstall = 0x00000071;

	public static final long TPM_ORD_PhysicalSetDeactivated = 0x00000072;

	public static final long TPM_ORD_SetTempDeactivated = 0x00000073;

	public static final long TPM_ORD_SetOperatorAuth = 0x00000074;

	public static final long TPM_ORD_SetOwnerPointer = 0x00000075;

	public static final long TPM_ORD_CreateEndorsementKeyPair = 0x00000078;

	public static final long TPM_ORD_MakeIdentity = 0x00000079;

	public static final long TPM_ORD_ActivateIdentity = 0x0000007A;

	public static final long TPM_ORD_ReadPubek = 0x0000007C;

	public static final long TPM_ORD_OwnerReadPubek = 0x0000007D;

	public static final long TPM_ORD_DisablePubekRead = 0x0000007E;

	public static final long TPM_ORD_CreateRevocableEK = 0x0000007F;

	public static final long TPM_ORD_RevokeTrust = 0x00000080;

	public static final long TPM_ORD_OwnerReadInternalPub = 0x00000081;

	public static final long TPM_ORD_GetAuditEvent = 0x00000082;

	public static final long TPM_ORD_GetAuditEventSigned = 0x00000083;

	public static final long TPM_ORD_GetAuditDigest = 0x00000085;

	public static final long TPM_ORD_GetAuditDigestSigned = 0x00000086;

	public static final long TPM_ORD_GetOrdinalAuditStatus = 0x0000008C;

	public static final long TPM_ORD_SetOrdinalAuditStatus = 0x0000008D;

	public static final long TPM_ORD_Terminate_Handle = 0x00000096;

	public static final long TPM_ORD_Init = 0x00000097;

	public static final long TPM_ORD_SaveState = 0x00000098;

	public static final long TPM_ORD_Startup = 0x00000099;

	public static final long TPM_ORD_SetRedirection = 0x0000009A;

	public static final long TPM_ORD_SHA1Start = 0x000000A0;

	public static final long TPM_ORD_SHA1Update = 0x000000A1;

	public static final long TPM_ORD_SHA1Complete = 0x000000A2;

	public static final long TPM_ORD_SHA1CompleteExtend = 0x000000A3;

	public static final long TPM_ORD_FieldUpgrade = 0x000000AA;

	public static final long TPM_ORD_SaveKeyContext = 0x000000B4;

	public static final long TPM_ORD_LoadKeyContext = 0x000000B5;

	public static final long TPM_ORD_SaveAuthContext = 0x000000B6;

	public static final long TPM_ORD_LoadAuthContext = 0x000000B7;

	public static final long TPM_ORD_SaveContext = 0x000000B8;

	public static final long TPM_ORD_LoadContext = 0x000000B9;

	public static final long TPM_ORD_FlushSpecific = 0x000000BA;

	public static final long TPM_ORD_PCR_Reset = 0x000000C8;

	public static final long TPM_ORD_NV_DefineSpace = 0x000000CC;

	public static final long TPM_ORD_NV_WriteValue = 0x000000CD;

	public static final long TPM_ORD_NV_WriteValueAuth = 0x000000CE;

	public static final long TPM_ORD_NV_ReadValue = 0x000000CF;

	public static final long TPM_ORD_NV_ReadValueAuth = 0x000000D0;

	public static final long TPM_ORD_Delegate_UpdateVerification = 0x000000D1;

	public static final long TPM_ORD_Delegate_Manage = 0x000000D2;

	public static final long TPM_ORD_Delegate_CreateKeyDelegation = 0x000000D4;

	public static final long TPM_ORD_Delegate_CreateOwnerDelegation = 0x000000D5;

	public static final long TPM_ORD_Delegate_VerifyDelegation = 0x000000D6;

	public static final long TPM_ORD_Delegate_LoadOwnerDelegation = 0x000000D8;

	public static final long TPM_ORD_Delegate_ReadTable = 0x000000DB;

	public static final long TPM_ORD_CreateCounter = 0x000000DC;

	public static final long TPM_ORD_IncrementCounter = 0x000000DD;

	public static final long TPM_ORD_ReadCounter = 0x000000DE;

	public static final long TPM_ORD_ReleaseCounter = 0x000000DF;

	public static final long TPM_ORD_ReleaseCounterOwner = 0x000000E0;

	public static final long TPM_ORD_EstablishTransport = 0x000000E6;

	public static final long TPM_ORD_ExecuteTransport = 0x000000E7;

	public static final long TPM_ORD_ReleaseTransportSigned = 0x000000E8;

	public static final long TPM_ORD_GetTicks = 0x000000F1;

	public static final long TPM_ORD_TickStampBlob = 0x000000F2;

	public static final long TSC_ORD_PhysicalPresence = 0x4000000A;

	public static final long TSC_ORD_ResetEstablishmentBit = 0x4000000B;
	
	// Infineon specific ordinals
	
	public static final long TPM_ORD_IFX_ReadCert11 = 0x20000002;
}
