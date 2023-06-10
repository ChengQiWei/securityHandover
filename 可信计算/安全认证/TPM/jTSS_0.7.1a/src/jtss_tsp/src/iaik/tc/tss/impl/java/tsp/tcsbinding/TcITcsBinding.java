/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.impl.java.tsp.tcsbinding;


import iaik.tc.tss.api.exceptions.common.TcTssException;
import iaik.tc.tss.api.exceptions.tcs.TcTcsException;
import iaik.tc.tss.api.exceptions.tcs.TcTddlException;
import iaik.tc.tss.api.exceptions.tcs.TcTpmException;
import iaik.tc.tss.api.exceptions.tsp.TcTspException;
import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.tss.api.structs.tcs.TcTcsAuth;
import iaik.tc.tss.api.structs.tcs.TcTcsLoadkeyInfo;
import iaik.tc.tss.api.structs.tpm.TcITpmKey;
import iaik.tc.tss.api.structs.tpm.TcITpmKeyNew;
import iaik.tc.tss.api.structs.tpm.TcITpmPcrInfo;
import iaik.tc.tss.api.structs.tpm.TcITpmStoredData;
import iaik.tc.tss.api.structs.tpm.TcTpmCmkAuth;
import iaik.tc.tss.api.structs.tpm.TcTpmDelegateOwnerBlob;
import iaik.tc.tss.api.structs.tpm.TcTpmDelegatePublic;
import iaik.tc.tss.api.structs.tpm.TcTpmDigest;
import iaik.tc.tss.api.structs.tpm.TcTpmEncauth;
import iaik.tc.tss.api.structs.tpm.TcTpmKey;
import iaik.tc.tss.api.structs.tpm.TcTpmKey12;
import iaik.tc.tss.api.structs.tpm.TcTpmKeyParms;
import iaik.tc.tss.api.structs.tpm.TcTpmMigrationkeyAuth;
import iaik.tc.tss.api.structs.tpm.TcTpmMsaComposite;
import iaik.tc.tss.api.structs.tpm.TcTpmNonce;
import iaik.tc.tss.api.structs.tpm.TcTpmNvDataPublic;
import iaik.tc.tss.api.structs.tpm.TcTpmPcrInfoLong;
import iaik.tc.tss.api.structs.tpm.TcTpmPcrSelection;
import iaik.tc.tss.api.structs.tpm.TcTpmPubkey;
import iaik.tc.tss.api.structs.tpm.TcTpmSecret;
import iaik.tc.tss.api.structs.tpm.TcTpmTransportPublic;
import iaik.tc.tss.api.structs.tsp.TcTssKmKeyinfo;
import iaik.tc.tss.api.structs.tsp.TcTssPcrEvent;
import iaik.tc.tss.api.structs.tsp.TcTssUuid;

public interface TcITcsBinding {

	// --------- persistent storage ---------

	public void TcsiRegisterKey(long hContext, TcTssUuid wrappingKeyUuid, TcTssUuid keyUuid,
			TcBlobData key, TcBlobData vendorData) throws TcTssException;


	public void TcsiUnregisterKey(long hContext, TcTssUuid keyUuid) throws TcTssException;


	public void TcsipKeyControlOwner(long hContext, long tcsKeyHandle, long attribName,
			long attribValue, TcTcsAuth ownerAuth, TcTssUuid uuidData) throws TcTssException;


	public TcTssKmKeyinfo[] TcsiEnumRegisteredKeys(long hContext, TcTssUuid keyUuid)
		throws TcTssException;


	public TcTssKmKeyinfo TcsiGetRegisteredKey(long hContext, TcTssUuid keyUuid)
		throws TcTssException;


	public TcBlobData TcsiGetRegisteredKeyBlob(long hContext, TcTssUuid keyUuid)
		throws TcTssException;


	public TcBlobData TcsiGetRegisteredKeyByPublicInfo(long hContext, long algId,
			TcBlobData publicInfo) throws TcTssException;


	public long TcsipLoadKeyByUuid(long hContext, TcTssUuid keyUuid, TcTcsLoadkeyInfo loadKeyInfo)
		throws TcTssException;


	// --------- key management ---------

	public Object[] TcsipLoadKeyByBlob(long hContext, long hUnwrappingKey, TcTpmKey wrappedKeyBlob,
			TcTcsAuth inAuth) throws TcTddlException, TcTpmException, TcTcsException;


	public Object[] TcsipLoadKey2ByBlob(long hContext, long hUnwrappingKey, TcITpmKey wrappedKeyBlob,
			TcTcsAuth inAuth) throws TcTddlException, TcTpmException, TcTcsException;


	public Object[] TcsipGetPubKey(long hContext, long keyHandle, TcTcsAuth inAuth1)
		throws TcTddlException, TcTpmException, TcTcsException;


	public Object[] TcsipEvictKey(long hContext, long tcsKeyHandle)
		throws TcTddlException, TcTpmException, TcTcsException;


	public Object[] TcsipOwnerReadInternalPub(long hContext, long keyHandle, TcTcsAuth inAuth1)
		throws TcTddlException, TcTpmException, TcTcsException;


	// --------- credential management ---------

	public Object[] TcsiGetCredentials(long hContext)
		throws TcTddlException, TcTpmException, TcTcsException;


	public Object[] TcsipMakeIdentity(long hContext, TcTpmEncauth identityAuth,
			TcTpmDigest labelPrivCADigest, TcITpmKeyNew idKeyParams, TcTcsAuth inAuth1, TcTcsAuth inAuth2)
		throws TcTddlException, TcTpmException, TcTcsException;


	public Object[] TcsipMakeIdentity2(long hContext, TcTpmEncauth identityAuth,
			TcTpmDigest labelPrivCADigest, TcITpmKeyNew idKeyParams, TcTcsAuth inAuth1, TcTcsAuth inAuth2)
		throws TcTddlException, TcTpmException, TcTcsException;


	// --------- other TCS calls --------

	public void connect(String hostname) throws TcTspException;


	public Object[] TcsiOpenContext();


	public long TcsiCloseContext(long hContext)
		throws TcTcsException, TcTddlException, TcTpmException;


	public long TcsiFreeMemory(long hContext, long pMemory) throws TcTcsException;


	public TcBlobData TcsiGetCapability(long hContext, long capArea, TcBlobData subCap)
		throws TcTcsException;


	public long TcsiLogPcrEvent(long hContext, TcTssPcrEvent pcrEvent) throws TcTcsException;


	public TcTssPcrEvent TcsiGetPcrEvent(long hContext, long pcrIndex, long number)
		throws TcTcsException;


	public long TcsiGetPcrEventCount(long hContext, long pcrIndex) throws TcTcsException;


	public TcTssPcrEvent[] TcsiGetPcrEventsByPcr(long hContext, long pcrIndex, long firstEvent,
			long eventCount) throws TcTcsException;


	public TcTssPcrEvent[] TcsiGetPcrEventLog(long hContext) throws TcTcsException;


	public Object[] TcsipSelfTestFull(long hContext)
		throws TcTddlException, TcTpmException, TcTcsException;


	public Object[] TcsipContinueSelfTest(long hContext)
		throws TcTddlException, TcTpmException, TcTcsException;


	public Object[] TcsipGetTestResult(long hContext)
		throws TcTddlException, TcTpmException, TcTcsException;


	public Object[] TcsipSetOwnerInstall(long hContext, boolean state)
		throws TcTddlException, TcTpmException, TcTcsException;


	public Object[] TcsipOwnerSetDisable(long hContext, boolean disableState, TcTcsAuth inAuth1)
		throws TcTddlException, TcTpmException, TcTcsException;


	public Object[] TcsipPhysicalEnable(long hContext)
		throws TcTddlException, TcTpmException, TcTcsException;


	public Object[] TcsipPhysicalDisable(long hContext)
		throws TcTddlException, TcTpmException, TcTcsException;


	public Object[] TcsipPhysicalSetDeactivated(long hContext, boolean state)
		throws TcTddlException, TcTpmException, TcTcsException;


	public Object[] TcsipSetTempDeactivated2(long hContext, TcTcsAuth inAuth1)
		throws TcTddlException, TcTpmException, TcTcsException;


	public Object[] TcsipSetTempDeactivated(long hContext)
		throws TcTddlException, TcTpmException, TcTcsException;


	public Object[] TcsipSetOperatorAuth(long hContext, TcTpmSecret operatorAuth)
		throws TcTddlException, TcTpmException, TcTcsException;


	public Object[] TcsipTakeOwnership(long hContext, int protocolID, TcBlobData encOwnerAuth,
			TcBlobData encSrkAuth, TcITpmKeyNew srkParams, TcTcsAuth inAuth1)
		throws TcTddlException, TcTpmException, TcTcsException;


	public Object[] TcsipOwnerClear(long hContext, TcTcsAuth inAuth1)
		throws TcTddlException, TcTpmException, TcTcsException;


	public Object[] TcsipForceClear(long hContext)
		throws TcTddlException, TcTpmException, TcTcsException;


	public Object[] TcsipDisableOwnerClear(long hContext, TcTcsAuth inAuth1)
		throws TcTddlException, TcTpmException, TcTcsException;


	public Object[] TcsipDisableForceClear(long hContext)
		throws TcTddlException, TcTpmException, TcTcsException;


	public Object[] TcsipPhysicalPresence(long hContext, int physicalPresence)
		throws TcTddlException, TcTpmException, TcTcsException;


	public Object[] TcsipGetCapability(long hContext, long capArea, TcBlobData subCap)
		throws TcTddlException, TcTpmException, TcTcsException;


	public Object[] TcsipSetCapability(long hContext, long capArea, TcBlobData subCap,
			TcBlobData setValue, TcTcsAuth inAuth1)
		throws TcTddlException, TcTpmException, TcTcsException;


	public Object[] TcsipGetCapabilityOwner(long hContext, TcTcsAuth inAuth1)
		throws TcTddlException, TcTpmException, TcTcsException;


	public Object[] TcsipGetAuditDigest(long hContext, long startOrdinal)
		throws TcTddlException, TcTpmException, TcTcsException;


	public Object[] TcsipGetAuditDigestSigned(long hContext, long keyHandle, boolean closeAudit,
			TcTpmNonce antiReplay, TcTcsAuth inAuth1)
		throws TcTddlException, TcTpmException, TcTcsException;


	public Object[] TcsipSetOrdinalAuditStatus(long hContext, TcTcsAuth ownerAuth,
			long ordinalToAudit, boolean auditState)
		throws TcTddlException, TcTpmException, TcTcsException;


	public Object[] TcsipFieldUpgrade(long hContext, TcBlobData inData, TcTcsAuth ownerAuth)
		throws TcTddlException, TcTpmException, TcTcsException;


	public Object[] TcsipSetRedirection(long hContext, long keyHandle, long redirCmd,
			TcBlobData inputData, TcTcsAuth inAuth1)
		throws TcTddlException, TcTpmException, TcTcsException;


	public Object[] TcsipResetLockValue(long hContext, TcTcsAuth inAuth1)
		throws TcTddlException, TcTpmException, TcTcsException;


	public Object[] TcsipSeal(long hContext, long keyHandle, TcTpmEncauth encAuth,
			TcITpmPcrInfo pcrInfo, TcBlobData inData, TcTcsAuth inAuth1)
		throws TcTddlException, TcTpmException, TcTcsException;


	public Object[] TcsipUnseal(long hContext, long parentHandle, TcITpmStoredData inData,
			TcTcsAuth inAuth1, TcTcsAuth inAuth2) throws TcTddlException, TcTpmException, TcTcsException;


	public Object[] TcsipUnBind(long hContext, long keyHandle, TcBlobData inData, TcTcsAuth inAuth1)
		throws TcTddlException, TcTpmException, TcTcsException;


	public Object[] TcsipCreateWrapKey(long hContext, long parentHandle, TcTpmEncauth dataUsageAuth,
			TcTpmEncauth dataMigrationAuth, TcITpmKeyNew keyInfo, TcTcsAuth inAuth1)
		throws TcTddlException, TcTpmException, TcTcsException;


	public Object[] TcsipSealx(long hContext, long keyHandle, TcTpmEncauth encAuth,
			TcTpmPcrInfoLong pcrInfo, TcBlobData inData, TcTcsAuth inAuth1)
		throws TcTddlException, TcTpmException, TcTcsException;


	public Object[] TcsipCreateMigrationBlob(long hContext, long parentHandle, int migrationType,
			TcTpmMigrationkeyAuth migrationKeyAuth, TcBlobData encData, TcTcsAuth inAuth1,
			TcTcsAuth inAuth2) throws TcTddlException, TcTpmException, TcTcsException;


	public Object[] TcsipConvertMigrationBlob(long hContext, long parentHandle, TcBlobData inData,
			TcBlobData random, TcTcsAuth inAuth1) throws TcTddlException, TcTpmException, TcTcsException;


	public Object[] TcsipAuthorizeMigrationKey(long hContext, int migrationScheme,
			TcTpmPubkey migrationKey, TcTcsAuth inAuth1)
		throws TcTddlException, TcTpmException, TcTcsException;


	public Object[] TcsipMigrateKey(long hContext, long maKeyHandle, TcTpmPubkey pubKey,
			TcBlobData inData, TcTcsAuth inAuth1) throws TcTddlException, TcTpmException, TcTcsException;


	public Object[] TcsipCmkSetRestrictions(long hContext, long restriction, TcTcsAuth inAuth1)
		throws TcTddlException, TcTpmException, TcTcsException;


	public Object[] TcsipCmkApproveMA(long hContext, TcTpmDigest migrationAuthorityDigest,
			TcTcsAuth inAuth1) throws TcTddlException, TcTpmException, TcTcsException;


	public Object[] TcsipCmkCreateKey(long hContext, long parentHandle, TcTpmEncauth dataUsageAuth,
			TcTpmDigest migrationAuthorityApproval, TcTpmDigest migrationAuthorityDigest,
			TcTpmKey12 keyInfo, TcTcsAuth inAuth1) throws TcTddlException, TcTpmException, TcTcsException;


	public Object[] TcsipCmkCreateTicket(long hContext, TcTpmPubkey verificationKey,
			TcTpmDigest signedData, TcBlobData signatureValue, TcTcsAuth inAuth1)
		throws TcTddlException, TcTpmException, TcTcsException;


	public Object[] TcsipCmkCreateBlob(long hContext, long parentHandle, int migrationType,
			TcTpmMigrationkeyAuth migrationKeyAuth, TcTpmDigest pubSourceKeyDigest,
			TcTpmMsaComposite msaList, TcBlobData restrictTicket, TcBlobData sigTicket,
			TcBlobData encData, TcTcsAuth inAuth1) throws TcTddlException, TcTpmException, TcTcsException;


	public Object[] TcsipCmkConvertMigration(long hContext, long parentHandle,
			TcTpmCmkAuth restrictTicket, TcTpmDigest sigTicket, TcTpmKey12 migratedKey,
			TcTpmMsaComposite msaList, TcBlobData random, TcTcsAuth inAuth1)
		throws TcTddlException, TcTpmException, TcTcsException;


	public Object[] TcsipCreateMaintenanceArchive(long hContext, boolean generateRandom,
			TcTcsAuth inAuth1) throws TcTddlException, TcTpmException, TcTcsException;


	public Object[] TcsipLoadMaintenanceArchive(long hContext, TcBlobData inData, TcTcsAuth ownerAuth)
		throws TcTddlException, TcTpmException, TcTcsException;


	public Object[] TcsipKillMaintenanceFeature(long hContext, TcTcsAuth inAuth1)
		throws TcTddlException, TcTpmException, TcTcsException;


	public Object[] TcsipLoadManuMaintPub(long hContext, TcTpmNonce antiReplay, TcTpmPubkey pubKey)
		throws TcTddlException, TcTpmException, TcTcsException;


	public Object[] TcsipReadManuMaintPub(long hContext, TcTpmNonce antiReplay)
		throws TcTddlException, TcTpmException, TcTcsException;


	public Object[] TcsSHA1Start(long hContext)
		throws TcTddlException, TcTpmException, TcTcsException;


	public Object[] TcsSHA1Update(long hContext, long numBytes, TcBlobData hashData)
		throws TcTddlException, TcTpmException, TcTcsException;


	public Object[] TcsSHA1Complete(long hContext, TcBlobData hashData)
		throws TcTddlException, TcTpmException, TcTcsException;


	public Object[] TcsSHA1CompleteExtend(long hContext, long pcrNum, TcBlobData hashData)
		throws TcTddlException, TcTpmException, TcTcsException;


	public Object[] TcsipSign(long hContext, long keyHandle, TcBlobData areaToSign, TcTcsAuth inAuth1)
		throws TcTddlException, TcTpmException, TcTcsException;


	public Object[] TcsipGetRandom(long hContext, long bytesRequested)
		throws TcTddlException, TcTpmException, TcTcsException;


	public Object[] TcsipStirRandom(long hContext, TcBlobData inData)
		throws TcTddlException, TcTpmException, TcTcsException;


	public Object[] TcsipCertifyKey(long hContext, long certHandle, long keyHandle,
			TcTpmNonce antiReplay, TcTcsAuth inAuth1, TcTcsAuth inAuth2)
		throws TcTddlException, TcTpmException, TcTcsException;


	public Object[] TcsipCertifyKey2(long hContext, long certHandle, long keyHandle,
			TcTpmDigest migrationPubDigest, TcTpmNonce antiReplay, TcTcsAuth inAuth1, TcTcsAuth inAuth2)
		throws TcTddlException, TcTpmException, TcTcsException;


	public Object[] TcsipCreateEndorsementKeyPair(long hContext, TcTpmNonce antiReplay,
			TcTpmKeyParms keyInfo) throws TcTddlException, TcTpmException, TcTcsException;


	public Object[] TcsipCreateRevocableEK(long hContext, TcTpmNonce antiReplay,
			TcTpmKeyParms keyInfo, boolean generateReset, TcTpmNonce inputEKreset)
		throws TcTddlException, TcTpmException, TcTcsException;


	public Object[] TcsipRevokeEndorsementKeyPair(long hContext, TcTpmNonce EKReset)
		throws TcTddlException, TcTpmException, TcTcsException;


	public Object[] TcsipReadPubek(long hContext, TcTpmNonce antiReplay)
		throws TcTddlException, TcTpmException, TcTcsException;


	public Object[] TcsipActivateIdentity(long hContext, long idKeyHandle, TcBlobData blob,
			TcTcsAuth inAuth1, TcTcsAuth inAuth2) throws TcTddlException, TcTpmException, TcTcsException;


	public Object[] TcsipExtend(long hContext, long pcrNum, TcTpmDigest inDigest)
		throws TcTddlException, TcTpmException, TcTcsException;


	public Object[] TcsipPcrRead(long hContext, long pcrIndex)
		throws TcTddlException, TcTpmException, TcTcsException;


	public Object[] TcsipQuote(long hContext, long keyHandle, TcTpmNonce externalData,
			TcTpmPcrSelection targetPCR, TcTcsAuth inAuth1)
		throws TcTddlException, TcTpmException, TcTcsException;


	public Object[] TcsipPcrReset(long hContext, TcTpmPcrSelection pcrSelection)
		throws TcTddlException, TcTpmException, TcTcsException;


	public Object[] TcsipQuote2(long hContext, long keyHandle, TcTpmNonce externalData,
			TcTpmPcrSelection targetPCR, boolean addVersion, TcTcsAuth inAuth1)
		throws TcTddlException, TcTpmException, TcTcsException;


	public Object[] TcsipChangeAuth(long hContext, long parentHandle, int protocolID,
			TcTpmEncauth newAuth, int entityType, TcBlobData encData, TcTcsAuth inAuth1, TcTcsAuth inAuth2)
		throws TcTddlException, TcTpmException, TcTcsException;


	public Object[] TcsipChangeAuthOwner(long hContext, int protocolID, TcTpmEncauth newAuth,
			int entityType, TcTcsAuth inAuth1) throws TcTddlException, TcTpmException, TcTcsException;


	public Object[] TcsipOIAP(long hContext) throws TcTddlException, TcTpmException, TcTcsException;


	public Object[] TcsipOSAP(long hContext, int entityType, long entityValue, TcTpmNonce nonceOddOSAP)
		throws TcTddlException, TcTpmException, TcTcsException;


	public Object[] TcsipDSAP(long hContext, int entityType, long keyHandle, TcTpmNonce nonceOddDSAP,
			TcBlobData entityValue) throws TcTddlException, TcTpmException, TcTcsException;


	public Object[] TcsipDelegateManage(long hContext, long familyID, long opCode, TcBlobData opData,
			TcTcsAuth inAuth1) throws TcTddlException, TcTpmException, TcTcsException;


	public Object[] TcsipDelegateCreateKeyDelegation(long hContext, long keyHandle,
			TcTpmDelegatePublic publicInfo, TcTpmEncauth delAuth, TcTcsAuth inAuth1)
		throws TcTddlException, TcTpmException, TcTcsException;


	public Object[] TcsipDelegateCreateOwnerDelegation(long hContext, boolean increment,
			TcTpmDelegatePublic publicInfo, TcTpmEncauth delAuth, TcTcsAuth inAuth1)
		throws TcTddlException, TcTpmException, TcTcsException;


	public Object[] TcsipDelegateLoadOwnerDelegation(long hContext, long index,
			TcTpmDelegateOwnerBlob blob, TcTcsAuth inAuth1)
		throws TcTddlException, TcTpmException, TcTcsException;


	public Object[] TcsipDelegateReadTable(long hContext)
		throws TcTddlException, TcTpmException, TcTcsException;


	public Object[] TcsipDelegateUpdateVerificationCount(long hContext, TcBlobData inputData,
			TcTcsAuth inAuth1) throws TcTddlException, TcTpmException, TcTcsException;


	public Object[] TcsipDelegateVerifyDelegation(long hContext, TcBlobData delegation)
		throws TcTddlException, TcTpmException, TcTcsException;


	public Object[] TcsipNvDefineOrReleaseSpace(long hContext, TcTpmNvDataPublic pubInfo,
			TcTpmEncauth encAuth, TcTcsAuth inAuth1)
		throws TcTddlException, TcTpmException, TcTcsException;


	public Object[] TcsipNvWriteValue(long hContext, long nvIndex, long offset, TcBlobData data,
			TcTcsAuth inAuth1) throws TcTddlException, TcTpmException, TcTcsException;


	public Object[] TcsipNvWriteValueAuth(long hContext, long nvIndex, long offset, TcBlobData data,
			TcTcsAuth inAuth1) throws TcTddlException, TcTpmException, TcTcsException;


	public Object[] TcsipNvReadValue(long hContext, long nvIndex, long offset, long dataSz,
			TcTcsAuth inAuth1) throws TcTddlException, TcTpmException, TcTcsException;


	public Object[] TcsipNvReadValueAuth(long hContext, long nvIndex, long offset, long dataSz,
			TcTcsAuth inAuth1) throws TcTddlException, TcTpmException, TcTcsException;


	public Object[] TcsipReadCurrentTicks(long hContext)
		throws TcTddlException, TcTpmException, TcTcsException;


	public Object[] TcsipTickStampBlob(long hContext, long keyHandle, TcTpmNonce antiReplay,
			TcTpmDigest digestToStamp, TcTcsAuth inAuth1)
		throws TcTddlException, TcTpmException, TcTcsException;


	public Object[] TcsEstablishTransport(long hContext, long encHandle,
			TcTpmTransportPublic transPublic, TcBlobData secret, TcTcsAuth inAuth1)
		throws TcTddlException, TcTpmException, TcTcsException;


	public Object[] TcsExecuteTransport(long hContext, TcBlobData wrappedCmd, long transHandle,
			TcTcsAuth inAuth1) throws TcTddlException, TcTpmException, TcTcsException;


	public Object[] TcsReleaseTransportSigned(long hContext, long keyHandle, TcTpmNonce antiReplay,
			long transHandle, TcTcsAuth inAuth1, TcTcsAuth inAuth2)
		throws TcTddlException, TcTpmException, TcTcsException;


	public Object[] TcsipCreateCounter(long hContext, TcBlobData label, TcTpmEncauth encAuth,
			TcTcsAuth inAuth1) throws TcTddlException, TcTpmException, TcTcsException;


	public Object[] TcsipIncrementCounter(long hContext, long countID, TcTcsAuth inAuth1)
		throws TcTddlException, TcTpmException, TcTcsException;


	public Object[] TcsipReadCounter(long hContext, long countID)
		throws TcTddlException, TcTpmException, TcTcsException;


	public Object[] TcsipReleaseCounter(long hContext, long countID, TcTcsAuth inAuth1)
		throws TcTddlException, TcTpmException, TcTcsException;


	public Object[] TcsipReleaseCounterOwner(long hContext, long countID, TcTcsAuth inAuth1)
		throws TcTddlException, TcTpmException, TcTcsException;


	public Object[] TcsipDaaJoin(long hContext, long handle, short stage, TcBlobData inputData0,
			TcBlobData inputData1, TcTcsAuth inAuth1)
		throws TcTddlException, TcTpmException, TcTcsException;


	public Object[] TcsipDaaSign(long hContext, long handle, short stage, TcBlobData inputData0,
			TcBlobData inputData1, TcTcsAuth inAuth1)
		throws TcTddlException, TcTpmException, TcTcsException;


	public Object[] TcsipTerminateHandle(long hContext, long handle)
		throws TcTddlException, TcTpmException, TcTcsException;


	public Object[] TcsipDirWriteAuth(long hContext, long dirIndex, TcTpmDigest newContents,
			TcTcsAuth inAuth1) throws TcTddlException, TcTpmException, TcTcsException;


	public Object[] TcsipDirRead(long hContext, long dirIndex)
		throws TcTddlException, TcTpmException, TcTcsException;


	public Object[] TcsipChangeAuthAsymStart(long hContext, long idHandle, TcTpmNonce antiReplay,
			TcTpmKeyParms tempKey, TcTcsAuth inAuth1)
		throws TcTddlException, TcTpmException, TcTcsException;


	public Object[] TcsipChangeAuthAsymFinish(long hContext, long parentHandle, long ephHandle,
			int entityType, TcTpmDigest newAuthLink, TcBlobData encNewAuth, TcBlobData encData,
			TcTcsAuth inAuth1) throws TcTddlException, TcTpmException, TcTcsException;


	public Object[] TcsipOwnerReadPubek(long hContext, TcTcsAuth inAuth1)
		throws TcTddlException, TcTpmException, TcTcsException;


	public Object[] TcsipDisablePubekRead(long hContext, TcTcsAuth inAuth1)
		throws TcTddlException, TcTpmException, TcTcsException;


	public Object[] TcsipIfxReadTpm11EkCert(long hContext, byte index, TcBlobData antiReplay)
		throws TcTddlException, TcTpmException, TcTcsException;

}
