/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.test.tsp.java.tpm;

import iaik.tc.tss.api.constants.tpm.TcTpmOrdinals;
import iaik.tc.tss.api.exceptions.common.TcTssException;
import iaik.tc.tss.impl.java.tsp.TcTpm;
import iaik.tc.tss.test.tsp.java.TestCommon;
import iaik.tc.utils.logging.Log;

public class TestOrdinals extends TestCommon {

	public void testOrdinals()
	{
		try {
			Log.debug("TPM_ORD_ActivateIdentity                    " + ((TcTpm)context_.getTpmObject()).isOrdinalSupported(TcTpmOrdinals.TPM_ORD_ActivateIdentity));
			Log.debug("TPM_ORD_AuthorizeMigrationKey               " + ((TcTpm)context_.getTpmObject()).isOrdinalSupported(TcTpmOrdinals.TPM_ORD_AuthorizeMigrationKey));
			Log.debug("TPM_ORD_CertifyKey                          " + ((TcTpm)context_.getTpmObject()).isOrdinalSupported(TcTpmOrdinals.TPM_ORD_CertifyKey));
			Log.debug("TPM_ORD_CertifyKey2 [n]                     " + ((TcTpm)context_.getTpmObject()).isOrdinalSupported(TcTpmOrdinals.TPM_ORD_CertifyKey2));
			Log.debug("TPM_ORD_CertifySelfTest [x]                 " + ((TcTpm)context_.getTpmObject()).isOrdinalSupported(TcTpmOrdinals.TPM_ORD_CertifySelfTest));
			Log.debug("TPM_ORD_ChangeAuth                          " + ((TcTpm)context_.getTpmObject()).isOrdinalSupported(TcTpmOrdinals.TPM_ORD_ChangeAuth));
			Log.debug("TPM_ORD_ChangeAuthAsymFinish [d]            " + ((TcTpm)context_.getTpmObject()).isOrdinalSupported(TcTpmOrdinals.TPM_ORD_ChangeAuthAsymFinish));
			Log.debug("TPM_ORD_ChangeAuthAsymStart [d]             " + ((TcTpm)context_.getTpmObject()).isOrdinalSupported(TcTpmOrdinals.TPM_ORD_ChangeAuthAsymStart));
			Log.debug("TPM_ORD_ChangeAuthOwner                     " + ((TcTpm)context_.getTpmObject()).isOrdinalSupported(TcTpmOrdinals.TPM_ORD_ChangeAuthOwner));
			Log.debug("TPM_ORD_CMK_ApproveMA [o,n]                 " + ((TcTpm)context_.getTpmObject()).isOrdinalSupported(TcTpmOrdinals.TPM_ORD_CMK_ApproveMA));
			Log.debug("TPM_ORD_CMK_ConvertMigration [o,n]          " + ((TcTpm)context_.getTpmObject()).isOrdinalSupported(TcTpmOrdinals.TPM_ORD_CMK_ConvertMigration));
			Log.debug("TPM_ORD_CMK_CreateBlob [o,n]                " + ((TcTpm)context_.getTpmObject()).isOrdinalSupported(TcTpmOrdinals.TPM_ORD_CMK_CreateBlob));
			Log.debug("TPM_ORD_CMK_CreateKey [o,n]                 " + ((TcTpm)context_.getTpmObject()).isOrdinalSupported(TcTpmOrdinals.TPM_ORD_CMK_CreateKey));
			Log.debug("TPM_ORD_CMK_CreateTicket [o,n]              " + ((TcTpm)context_.getTpmObject()).isOrdinalSupported(TcTpmOrdinals.TPM_ORD_CMK_CreateTicket));
			Log.debug("TPM_ORD_CMK_SetRestrictions [o,n]           " + ((TcTpm)context_.getTpmObject()).isOrdinalSupported(TcTpmOrdinals.TPM_ORD_CMK_SetRestrictions));
			Log.debug("TPM_ORD_ContinueSelfTest                    " + ((TcTpm)context_.getTpmObject()).isOrdinalSupported(TcTpmOrdinals.TPM_ORD_ContinueSelfTest));
			Log.debug("TPM_ORD_ConvertMigrationBlob                " + ((TcTpm)context_.getTpmObject()).isOrdinalSupported(TcTpmOrdinals.TPM_ORD_ConvertMigrationBlob));
			Log.debug("TPM_ORD_CreateCounter [n]                   " + ((TcTpm)context_.getTpmObject()).isOrdinalSupported(TcTpmOrdinals.TPM_ORD_CreateCounter));
			Log.debug("TPM_ORD_CreateEndorsementKeyPair            " + ((TcTpm)context_.getTpmObject()).isOrdinalSupported(TcTpmOrdinals.TPM_ORD_CreateEndorsementKeyPair));
			Log.debug("TPM_ORD_CreateMaintenanceArchive [o]        " + ((TcTpm)context_.getTpmObject()).isOrdinalSupported(TcTpmOrdinals.TPM_ORD_CreateMaintenanceArchive));
			Log.debug("TPM_ORD_CreateMigrationBlob                 " + ((TcTpm)context_.getTpmObject()).isOrdinalSupported(TcTpmOrdinals.TPM_ORD_CreateMigrationBlob));
			Log.debug("TPM_ORD_CreateRevocableEK [o,n]             " + ((TcTpm)context_.getTpmObject()).isOrdinalSupported(TcTpmOrdinals.TPM_ORD_CreateRevocableEK));
			Log.debug("TPM_ORD_CreateWrapKey                       " + ((TcTpm)context_.getTpmObject()).isOrdinalSupported(TcTpmOrdinals.TPM_ORD_CreateWrapKey));
			Log.debug("TPM_ORD_DAA_Join [o,n]                      " + ((TcTpm)context_.getTpmObject()).isOrdinalSupported(TcTpmOrdinals.TPM_ORD_DAA_Join));
			Log.debug("TPM_ORD_DAA_Sign [o,n]                      " + ((TcTpm)context_.getTpmObject()).isOrdinalSupported(TcTpmOrdinals.TPM_ORD_DAA_Sign));
			Log.debug("TPM_ORD_Delegate_CreateKeyDelegation [n]    " + ((TcTpm)context_.getTpmObject()).isOrdinalSupported(TcTpmOrdinals.TPM_ORD_Delegate_CreateKeyDelegation));
			Log.debug("TPM_ORD_Delegate_CreateOwnerDelegation [n]  " + ((TcTpm)context_.getTpmObject()).isOrdinalSupported(TcTpmOrdinals.TPM_ORD_Delegate_CreateOwnerDelegation));
			Log.debug("TPM_ORD_Delegate_LoadOwnerDelegation [n]    " + ((TcTpm)context_.getTpmObject()).isOrdinalSupported(TcTpmOrdinals.TPM_ORD_Delegate_LoadOwnerDelegation));
			Log.debug("TPM_ORD_Delegate_Manage [n]                 " + ((TcTpm)context_.getTpmObject()).isOrdinalSupported(TcTpmOrdinals.TPM_ORD_Delegate_Manage));
			Log.debug("TPM_ORD_Delegate_ReadTable [n]              " + ((TcTpm)context_.getTpmObject()).isOrdinalSupported(TcTpmOrdinals.TPM_ORD_Delegate_ReadTable));
			Log.debug("TPM_ORD_Delegate_UpdateVerification [n]     " + ((TcTpm)context_.getTpmObject()).isOrdinalSupported(TcTpmOrdinals.TPM_ORD_Delegate_UpdateVerification));
			Log.debug("TPM_ORD_Delegate_VerifyDelegation [n]       " + ((TcTpm)context_.getTpmObject()).isOrdinalSupported(TcTpmOrdinals.TPM_ORD_Delegate_VerifyDelegation));
			Log.debug("TPM_ORD_DirRead [d]                         " + ((TcTpm)context_.getTpmObject()).isOrdinalSupported(TcTpmOrdinals.TPM_ORD_DirRead));
			Log.debug("TPM_ORD_DirWriteAuth [d]                    " + ((TcTpm)context_.getTpmObject()).isOrdinalSupported(TcTpmOrdinals.TPM_ORD_DirWriteAuth));
			Log.debug("TPM_ORD_DisableForceClear                   " + ((TcTpm)context_.getTpmObject()).isOrdinalSupported(TcTpmOrdinals.TPM_ORD_DisableForceClear));
			Log.debug("TPM_ORD_DisableOwnerClear                   " + ((TcTpm)context_.getTpmObject()).isOrdinalSupported(TcTpmOrdinals.TPM_ORD_DisableOwnerClear));
			Log.debug("TPM_ORD_DisablePubekRead [d]                " + ((TcTpm)context_.getTpmObject()).isOrdinalSupported(TcTpmOrdinals.TPM_ORD_DisablePubekRead));
			Log.debug("TPM_ORD_DSAP [n]                            " + ((TcTpm)context_.getTpmObject()).isOrdinalSupported(TcTpmOrdinals.TPM_ORD_DSAP));
			Log.debug("TPM_ORD_EstablishTransport [n]              " + ((TcTpm)context_.getTpmObject()).isOrdinalSupported(TcTpmOrdinals.TPM_ORD_EstablishTransport));
			Log.debug("TPM_ORD_EvictKey [d]                        " + ((TcTpm)context_.getTpmObject()).isOrdinalSupported(TcTpmOrdinals.TPM_ORD_EvictKey));
			Log.debug("TPM_ORD_ExecuteTransport [n]                " + ((TcTpm)context_.getTpmObject()).isOrdinalSupported(TcTpmOrdinals.TPM_ORD_ExecuteTransport));
			Log.debug("TPM_ORD_Extend                              " + ((TcTpm)context_.getTpmObject()).isOrdinalSupported(TcTpmOrdinals.TPM_ORD_Extend));
			Log.debug("TPM_ORD_FieldUpgrade [o]                    " + ((TcTpm)context_.getTpmObject()).isOrdinalSupported(TcTpmOrdinals.TPM_ORD_FieldUpgrade));
			Log.debug("TPM_ORD_FlushSpecific [n]                   " + ((TcTpm)context_.getTpmObject()).isOrdinalSupported(TcTpmOrdinals.TPM_ORD_FlushSpecific));
			Log.debug("TPM_ORD_ForceClear                          " + ((TcTpm)context_.getTpmObject()).isOrdinalSupported(TcTpmOrdinals.TPM_ORD_ForceClear));
			Log.debug("TPM_ORD_GetAuditDigest [o,n]                " + ((TcTpm)context_.getTpmObject()).isOrdinalSupported(TcTpmOrdinals.TPM_ORD_GetAuditDigest));
			Log.debug("TPM_ORD_GetAuditDigestSigned [o,n]          " + ((TcTpm)context_.getTpmObject()).isOrdinalSupported(TcTpmOrdinals.TPM_ORD_GetAuditDigestSigned));
			Log.debug("TPM_ORD_GetAuditEvent [o,n]                 " + ((TcTpm)context_.getTpmObject()).isOrdinalSupported(TcTpmOrdinals.TPM_ORD_GetAuditEvent));
			Log.debug("TPM_ORD_GetAuditEventSigned [o,n]           " + ((TcTpm)context_.getTpmObject()).isOrdinalSupported(TcTpmOrdinals.TPM_ORD_GetAuditEventSigned));
			Log.debug("TPM_ORD_GetCapability [c]                   " + ((TcTpm)context_.getTpmObject()).isOrdinalSupported(TcTpmOrdinals.TPM_ORD_GetCapability));
			Log.debug("TPM_ORD_GetCapabilityOwner [d]              " + ((TcTpm)context_.getTpmObject()).isOrdinalSupported(TcTpmOrdinals.TPM_ORD_GetCapabilityOwner));
			Log.debug("TPM_ORD_GetCapabilitySigned [x]             " + ((TcTpm)context_.getTpmObject()).isOrdinalSupported(TcTpmOrdinals.TPM_ORD_GetCapabilitySigned));
			Log.debug("TPM_ORD_GetOrdinalAuditStatus [x]           " + ((TcTpm)context_.getTpmObject()).isOrdinalSupported(TcTpmOrdinals.TPM_ORD_GetOrdinalAuditStatus));
			Log.debug("TPM_ORD_GetPubKey                           " + ((TcTpm)context_.getTpmObject()).isOrdinalSupported(TcTpmOrdinals.TPM_ORD_GetPubKey));
			Log.debug("TPM_ORD_GetRandom                           " + ((TcTpm)context_.getTpmObject()).isOrdinalSupported(TcTpmOrdinals.TPM_ORD_GetRandom));
			Log.debug("TPM_ORD_GetTestResult                       " + ((TcTpm)context_.getTpmObject()).isOrdinalSupported(TcTpmOrdinals.TPM_ORD_GetTestResult));
			Log.debug("TPM_ORD_GetTicks [n]                        " + ((TcTpm)context_.getTpmObject()).isOrdinalSupported(TcTpmOrdinals.TPM_ORD_GetTicks));
			Log.debug("TPM_ORD_IncrementCounter [n]                " + ((TcTpm)context_.getTpmObject()).isOrdinalSupported(TcTpmOrdinals.TPM_ORD_IncrementCounter));
			Log.debug("TPM_ORD_Init                                " + ((TcTpm)context_.getTpmObject()).isOrdinalSupported(TcTpmOrdinals.TPM_ORD_Init));
			Log.debug("TPM_ORD_KeyControlOwner [n]                 " + ((TcTpm)context_.getTpmObject()).isOrdinalSupported(TcTpmOrdinals.TPM_ORD_KeyControlOwner));
			Log.debug("TPM_ORD_KillMaintenanceFeature [o]          " + ((TcTpm)context_.getTpmObject()).isOrdinalSupported(TcTpmOrdinals.TPM_ORD_KillMaintenanceFeature));
			Log.debug("TPM_ORD_LoadAuthContext [o,d]               " + ((TcTpm)context_.getTpmObject()).isOrdinalSupported(TcTpmOrdinals.TPM_ORD_LoadAuthContext));
			Log.debug("TPM_ORD_LoadContext [n]                     " + ((TcTpm)context_.getTpmObject()).isOrdinalSupported(TcTpmOrdinals.TPM_ORD_LoadContext));
			Log.debug("TPM_ORD_LoadKey [d]                         " + ((TcTpm)context_.getTpmObject()).isOrdinalSupported(TcTpmOrdinals.TPM_ORD_LoadKey));
			Log.debug("TPM_ORD_LoadKey2 [n]                        " + ((TcTpm)context_.getTpmObject()).isOrdinalSupported(TcTpmOrdinals.TPM_ORD_LoadKey2));
			Log.debug("TPM_ORD_LoadKeyContext [o,d]                " + ((TcTpm)context_.getTpmObject()).isOrdinalSupported(TcTpmOrdinals.TPM_ORD_LoadKeyContext));
			Log.debug("TPM_ORD_LoadMaintenanceArchive [o]          " + ((TcTpm)context_.getTpmObject()).isOrdinalSupported(TcTpmOrdinals.TPM_ORD_LoadMaintenanceArchive));
			Log.debug("TPM_ORD_LoadManuMaintPub [o]                " + ((TcTpm)context_.getTpmObject()).isOrdinalSupported(TcTpmOrdinals.TPM_ORD_LoadManuMaintPub));
			Log.debug("TPM_ORD_MakeIdentity                        " + ((TcTpm)context_.getTpmObject()).isOrdinalSupported(TcTpmOrdinals.TPM_ORD_MakeIdentity));
			Log.debug("TPM_ORD_MigrateKey [n]                      " + ((TcTpm)context_.getTpmObject()).isOrdinalSupported(TcTpmOrdinals.TPM_ORD_MigrateKey));
			Log.debug("TPM_ORD_NV_DefineSpace [n]                  " + ((TcTpm)context_.getTpmObject()).isOrdinalSupported(TcTpmOrdinals.TPM_ORD_NV_DefineSpace));
			Log.debug("TPM_ORD_NV_ReadValue [n]                    " + ((TcTpm)context_.getTpmObject()).isOrdinalSupported(TcTpmOrdinals.TPM_ORD_NV_ReadValue));
			Log.debug("TPM_ORD_NV_ReadValueAuth [n]                " + ((TcTpm)context_.getTpmObject()).isOrdinalSupported(TcTpmOrdinals.TPM_ORD_NV_ReadValueAuth));
			Log.debug("TPM_ORD_NV_WriteValue [n]                   " + ((TcTpm)context_.getTpmObject()).isOrdinalSupported(TcTpmOrdinals.TPM_ORD_NV_WriteValue));
			Log.debug("TPM_ORD_NV_WriteValueAuth [n]               " + ((TcTpm)context_.getTpmObject()).isOrdinalSupported(TcTpmOrdinals.TPM_ORD_NV_WriteValueAuth));
			Log.debug("TPM_ORD_OIAP                                " + ((TcTpm)context_.getTpmObject()).isOrdinalSupported(TcTpmOrdinals.TPM_ORD_OIAP));
			Log.debug("TPM_ORD_OSAP                                " + ((TcTpm)context_.getTpmObject()).isOrdinalSupported(TcTpmOrdinals.TPM_ORD_OSAP));
			Log.debug("TPM_ORD_OwnerClear                          " + ((TcTpm)context_.getTpmObject()).isOrdinalSupported(TcTpmOrdinals.TPM_ORD_OwnerClear));
			Log.debug("TPM_ORD_OwnerReadInternalPub [c]            " + ((TcTpm)context_.getTpmObject()).isOrdinalSupported(TcTpmOrdinals.TPM_ORD_OwnerReadInternalPub));
			Log.debug("TPM_ORD_OwnerReadPubek [d]                  " + ((TcTpm)context_.getTpmObject()).isOrdinalSupported(TcTpmOrdinals.TPM_ORD_OwnerReadPubek));
			Log.debug("TPM_ORD_OwnerSetDisable                     " + ((TcTpm)context_.getTpmObject()).isOrdinalSupported(TcTpmOrdinals.TPM_ORD_OwnerSetDisable));
			Log.debug("TPM_ORD_PcrRead                             " + ((TcTpm)context_.getTpmObject()).isOrdinalSupported(TcTpmOrdinals.TPM_ORD_PcrRead));
			Log.debug("TPM_ORD_PCR_Reset [n]                       " + ((TcTpm)context_.getTpmObject()).isOrdinalSupported(TcTpmOrdinals.TPM_ORD_PCR_Reset));
			Log.debug("TPM_ORD_PhysicalDisable                     " + ((TcTpm)context_.getTpmObject()).isOrdinalSupported(TcTpmOrdinals.TPM_ORD_PhysicalDisable));
			Log.debug("TPM_ORD_PhysicalEnable                      " + ((TcTpm)context_.getTpmObject()).isOrdinalSupported(TcTpmOrdinals.TPM_ORD_PhysicalEnable));
			Log.debug("TPM_ORD_PhysicalSetDeactivated              " + ((TcTpm)context_.getTpmObject()).isOrdinalSupported(TcTpmOrdinals.TPM_ORD_PhysicalSetDeactivated));
			Log.debug("TPM_ORD_Quote                               " + ((TcTpm)context_.getTpmObject()).isOrdinalSupported(TcTpmOrdinals.TPM_ORD_Quote));
			Log.debug("TPM_ORD_Quote2 [o,n]                        " + ((TcTpm)context_.getTpmObject()).isOrdinalSupported(TcTpmOrdinals.TPM_ORD_Quote2));
			Log.debug("TPM_ORD_ReadCounter [n]                     " + ((TcTpm)context_.getTpmObject()).isOrdinalSupported(TcTpmOrdinals.TPM_ORD_ReadCounter));
			Log.debug("TPM_ORD_ReadManuMaintPub [o]                " + ((TcTpm)context_.getTpmObject()).isOrdinalSupported(TcTpmOrdinals.TPM_ORD_ReadManuMaintPub));
			Log.debug("TPM_ORD_ReadPubek                           " + ((TcTpm)context_.getTpmObject()).isOrdinalSupported(TcTpmOrdinals.TPM_ORD_ReadPubek));
			Log.debug("TPM_ORD_ReleaseCounter [n]                  " + ((TcTpm)context_.getTpmObject()).isOrdinalSupported(TcTpmOrdinals.TPM_ORD_ReleaseCounter));
			Log.debug("TPM_ORD_ReleaseCounterOwner [n]             " + ((TcTpm)context_.getTpmObject()).isOrdinalSupported(TcTpmOrdinals.TPM_ORD_ReleaseCounterOwner));
			Log.debug("TPM_ORD_ReleaseTransportSigned [n]          " + ((TcTpm)context_.getTpmObject()).isOrdinalSupported(TcTpmOrdinals.TPM_ORD_ReleaseTransportSigned));
			Log.debug("TPM_ORD_Reset [c]                           " + ((TcTpm)context_.getTpmObject()).isOrdinalSupported(TcTpmOrdinals.TPM_ORD_Reset));
			Log.debug("TPM_ORD_ResetLockValue [n]                  " + ((TcTpm)context_.getTpmObject()).isOrdinalSupported(TcTpmOrdinals.TPM_ORD_ResetLockValue));
			Log.debug("TPM_ORD_RevokeTrust [o,n]                   " + ((TcTpm)context_.getTpmObject()).isOrdinalSupported(TcTpmOrdinals.TPM_ORD_RevokeTrust));
			Log.debug("TPM_ORD_SaveAuthContext [o,d]               " + ((TcTpm)context_.getTpmObject()).isOrdinalSupported(TcTpmOrdinals.TPM_ORD_SaveAuthContext));
			Log.debug("TPM_ORD_SaveContext [n]                     " + ((TcTpm)context_.getTpmObject()).isOrdinalSupported(TcTpmOrdinals.TPM_ORD_SaveContext));
			Log.debug("TPM_ORD_SaveKeyContext [o,d]                " + ((TcTpm)context_.getTpmObject()).isOrdinalSupported(TcTpmOrdinals.TPM_ORD_SaveKeyContext));
			Log.debug("TPM_ORD_SaveState                           " + ((TcTpm)context_.getTpmObject()).isOrdinalSupported(TcTpmOrdinals.TPM_ORD_SaveState));
			Log.debug("TPM_ORD_Seal                                " + ((TcTpm)context_.getTpmObject()).isOrdinalSupported(TcTpmOrdinals.TPM_ORD_Seal));
			Log.debug("TPM_ORD_Sealx [o,n]                         " + ((TcTpm)context_.getTpmObject()).isOrdinalSupported(TcTpmOrdinals.TPM_ORD_Sealx));
			Log.debug("TPM_ORD_SelfTestFull                        " + ((TcTpm)context_.getTpmObject()).isOrdinalSupported(TcTpmOrdinals.TPM_ORD_SelfTestFull));
			Log.debug("TPM_ORD_SetCapability [n]                   " + ((TcTpm)context_.getTpmObject()).isOrdinalSupported(TcTpmOrdinals.TPM_ORD_SetCapability));
			Log.debug("TPM_ORD_SetOperatorAuth [n]                 " + ((TcTpm)context_.getTpmObject()).isOrdinalSupported(TcTpmOrdinals.TPM_ORD_SetOperatorAuth));
			Log.debug("TPM_ORD_SetOrdinalAuditStatus [o]           " + ((TcTpm)context_.getTpmObject()).isOrdinalSupported(TcTpmOrdinals.TPM_ORD_SetOrdinalAuditStatus));
			Log.debug("TPM_ORD_SetOwnerInstall                     " + ((TcTpm)context_.getTpmObject()).isOrdinalSupported(TcTpmOrdinals.TPM_ORD_SetOwnerInstall));
			Log.debug("TPM_ORD_SetOwnerPointer [n]                 " + ((TcTpm)context_.getTpmObject()).isOrdinalSupported(TcTpmOrdinals.TPM_ORD_SetOwnerPointer));
			Log.debug("TPM_ORD_SetRedirection [o]                  " + ((TcTpm)context_.getTpmObject()).isOrdinalSupported(TcTpmOrdinals.TPM_ORD_SetRedirection));
			Log.debug("TPM_ORD_SetTempDeactivated                  " + ((TcTpm)context_.getTpmObject()).isOrdinalSupported(TcTpmOrdinals.TPM_ORD_SetTempDeactivated));
			Log.debug("TPM_ORD_SHA1Complete                        " + ((TcTpm)context_.getTpmObject()).isOrdinalSupported(TcTpmOrdinals.TPM_ORD_SHA1Complete));
			Log.debug("TPM_ORD_SHA1CompleteExtend                  " + ((TcTpm)context_.getTpmObject()).isOrdinalSupported(TcTpmOrdinals.TPM_ORD_SHA1CompleteExtend));
			Log.debug("TPM_ORD_SHA1Start                           " + ((TcTpm)context_.getTpmObject()).isOrdinalSupported(TcTpmOrdinals.TPM_ORD_SHA1Start));
			Log.debug("TPM_ORD_SHA1Update                          " + ((TcTpm)context_.getTpmObject()).isOrdinalSupported(TcTpmOrdinals.TPM_ORD_SHA1Update));
			Log.debug("TPM_ORD_Sign                                " + ((TcTpm)context_.getTpmObject()).isOrdinalSupported(TcTpmOrdinals.TPM_ORD_Sign));
			Log.debug("TPM_ORD_Startup                             " + ((TcTpm)context_.getTpmObject()).isOrdinalSupported(TcTpmOrdinals.TPM_ORD_Startup));
			Log.debug("TPM_ORD_StirRandom                          " + ((TcTpm)context_.getTpmObject()).isOrdinalSupported(TcTpmOrdinals.TPM_ORD_StirRandom));
			Log.debug("TPM_ORD_TakeOwnership                       " + ((TcTpm)context_.getTpmObject()).isOrdinalSupported(TcTpmOrdinals.TPM_ORD_TakeOwnership));
			Log.debug("TPM_ORD_Terminate_Handle [d]                " + ((TcTpm)context_.getTpmObject()).isOrdinalSupported(TcTpmOrdinals.TPM_ORD_Terminate_Handle));
			Log.debug("TPM_ORD_TickStampBlob [n]                   " + ((TcTpm)context_.getTpmObject()).isOrdinalSupported(TcTpmOrdinals.TPM_ORD_TickStampBlob));
			Log.debug("TPM_ORD_UnBind                              " + ((TcTpm)context_.getTpmObject()).isOrdinalSupported(TcTpmOrdinals.TPM_ORD_UnBind));
			Log.debug("TPM_ORD_Unseal [c]                          " + ((TcTpm)context_.getTpmObject()).isOrdinalSupported(TcTpmOrdinals.TPM_ORD_Unseal));

			Log.debug("");
			Log.debug("o ... optional");
			Log.debug("n ... new im TPM 1.2 spec");
			Log.debug("d ... deprecated im TPM 1.2 spec");
			Log.debug("x ... deleted im TPM 1.2 spec");
			Log.debug("c ... changed im TPM 1.2 spec");
			
		} catch (TcTssException e) {
			Log.err(e);
			assertTrue("checking for supported ordinals failed", false);
		}
	}
}
