/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.impl.java.tsp.tcsbinding.local;


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
import iaik.tc.tss.impl.java.tcs.tcsi.TcTcsi;
import iaik.tc.tss.impl.java.tsp.tcsbinding.TcITcsBinding;

public class TcTcsBindingLocal implements TcITcsBinding {

	public void connect(String hostname) throws TcTspException
	{
		// doing local calls to TCS -> no connect required
	}


	// --------- persistent storage --------

	public void TcsiRegisterKey(long hContext, TcTssUuid wrappingKeyUuid, TcTssUuid keyUuid,
			TcBlobData key, TcBlobData vendorData) throws TcTssException
	{
		TcTcsi.TcsiRegisterKey(hContext, wrappingKeyUuid, keyUuid, key, vendorData);
	}


	public void TcsiUnregisterKey(long hContext, TcTssUuid keyUuid) throws TcTssException
	{
		TcTcsi.TcsiUnregisterKey(hContext, keyUuid);
	}


	public void TcsipKeyControlOwner(long hContext, long tcsKeyHandle, long attribName,
			long attribValue, TcTcsAuth ownerAuth, TcTssUuid uuidData) throws TcTssException
	{
		TcTcsi.TcsipKeyControlOwner(hContext, tcsKeyHandle, attribName, attribValue, ownerAuth, uuidData);
	}


	public TcTssKmKeyinfo[] TcsiEnumRegisteredKeys(long hContext, TcTssUuid keyUuid)
		throws TcTssException
	{
		return TcTcsi.TcsiEnumRegisteredKeys(hContext, keyUuid);
	}


	public TcTssKmKeyinfo TcsiGetRegisteredKey(long hContext, TcTssUuid keyUuid)
		throws TcTssException
	{
		return TcTcsi.TcsiGetRegisteredKey(hContext, keyUuid);
	}


	public TcBlobData TcsiGetRegisteredKeyBlob(long hContext, TcTssUuid keyUuid)
		throws TcTssException
	{
		return TcTcsi.TcsiGetRegisteredKeyBlob(hContext, keyUuid);
	}


	public TcBlobData TcsiGetRegisteredKeyByPublicInfo(long hContext, long algId,
			TcBlobData publicInfo) throws TcTssException
	{
		return TcTcsi.TcsiGetRegisteredKeyByPublicInfo(hContext, algId, publicInfo);
	}


	public long TcsipLoadKeyByUuid(long hContext, TcTssUuid keyUuid, TcTcsLoadkeyInfo loadKeyInfo)
		throws TcTssException
	{
		return TcTcsi.TcsipLoadKeyByUuid(hContext, keyUuid, loadKeyInfo);
	}


	// --------- key management --------

	public Object[] TcsipLoadKeyByBlob(long hContext, long hUnwrappingKey, TcTpmKey wrappedKeyBlob,
			TcTcsAuth inAuth) throws TcTddlException, TcTpmException, TcTcsException
	{
		return TcTcsi.TcsipLoadKeyByBlob(hContext, hUnwrappingKey, wrappedKeyBlob, inAuth);
	}


	public Object[] TcsipLoadKey2ByBlob(long hContext, long hUnwrappingKey, TcITpmKey wrappedKeyBlob,
			TcTcsAuth inAuth) throws TcTddlException, TcTpmException, TcTcsException
	{
		return TcTcsi.TcsipLoadKey2ByBlob(hContext, hUnwrappingKey, wrappedKeyBlob, inAuth);
	}


	public Object[] TcsipEvictKey(long hContext, long tcsKeyHandle)
		throws TcTddlException, TcTpmException, TcTcsException
	{
		return TcTcsi.TcsipEvictKey(hContext, tcsKeyHandle);
	}


	public Object[] TcsipOwnerReadInternalPub(long hContext, long keyHandle, TcTcsAuth inAuth1)
		throws TcTddlException, TcTpmException, TcTcsException
	{
		return TcTcsi.TcsipOwnerReadInternalPub(hContext, keyHandle, inAuth1);
	}


	public Object[] TcsipGetPubKey(long hContext, long keyHandle, TcTcsAuth inAuth1)
		throws TcTddlException, TcTpmException, TcTcsException
	{
		return TcTcsi.TcsipGetPubKey(hContext, keyHandle, inAuth1);
	}


	// --------- credential management ---------

	public Object[] TcsipMakeIdentity(long hContext, TcTpmEncauth identityAuth,
			TcTpmDigest labelPrivCADigest, TcITpmKeyNew idKeyParams, TcTcsAuth inAuth1, TcTcsAuth inAuth2)
		throws TcTddlException, TcTpmException, TcTcsException
	{
		return TcTcsi.TcsipMakeIdentity(hContext, identityAuth, labelPrivCADigest, idKeyParams,
				inAuth1, inAuth2);
	}


	public Object[] TcsipMakeIdentity2(long hContext, TcTpmEncauth identityAuth,
			TcTpmDigest labelPrivCADigest, TcITpmKeyNew idKeyParams, TcTcsAuth inAuth1, TcTcsAuth inAuth2)
		throws TcTddlException, TcTpmException, TcTcsException
	{
		return TcTcsi.TcsipMakeIdentity2(hContext, identityAuth, labelPrivCADigest, idKeyParams,
				inAuth1, inAuth2);
	}


	public Object[] TcsiGetCredentials(long hContext)
		throws TcTddlException, TcTpmException, TcTcsException
	{
		return TcTcsi.TcsiGetCredentials(hContext);
	}


	// --------- context --------

	public Object[] TcsiOpenContext()
	{
		return TcTcsi.TcsiOpenContext();
	}


	public long TcsiCloseContext(long hContext)
		throws TcTcsException, TcTddlException, TcTpmException
	{
		return TcTcsi.TcsiCloseContext(hContext);
	}


	public long TcsiFreeMemory(long hContext, long pMemory) throws TcTcsException
	{
		return TcTcsi.TcsiFreeMemory(hContext, pMemory);
	}


	public TcBlobData TcsiGetCapability(long hContext, long capArea, TcBlobData subCap)
		throws TcTcsException
	{
		return TcTcsi.TcsiGetCapability(hContext, capArea, subCap);
	}


	// --------- event manager methods --------

	public long TcsiLogPcrEvent(long hContext, TcTssPcrEvent pcrEvent) throws TcTcsException
	{
		return TcTcsi.TcsiLogPcrEvent(hContext, pcrEvent);
	}


	public TcTssPcrEvent TcsiGetPcrEvent(long hContext, long pcrIndex, long number)
		throws TcTcsException
	{
		return TcTcsi.TcsiGetPcrEvent(hContext, pcrIndex, number);
	}


	public long TcsiGetPcrEventCount(long hContext, long pcrIndex) throws TcTcsException
	{
    return TcTcsi.TcsiGetPcrEventCount(hContext, pcrIndex);
	}


	public TcTssPcrEvent[] TcsiGetPcrEventsByPcr(long hContext, long pcrIndex, long firstEvent,
			long eventCount) throws TcTcsException
	{
		return TcTcsi.TcsiGetPcrEventsByPcr(hContext, pcrIndex, firstEvent, eventCount);
	}


	public TcTssPcrEvent[] TcsiGetPcrEventLog(long hContext) throws TcTcsException
	{
		return TcTcsi.TcsiGetPcrEventLog(hContext);
	}


	// --------- other methods --------

	public Object[] TcsipSelfTestFull(long hContext)
		throws TcTddlException, TcTpmException, TcTcsException
	{
		return TcTcsi.TcsipSelfTestFull(hContext);
	}


	public Object[] TcsipContinueSelfTest(long hContext)
		throws TcTddlException, TcTpmException, TcTcsException
	{
		return TcTcsi.TcsipContinueSelfTest(hContext);
	}


	public Object[] TcsipGetTestResult(long hContext)
		throws TcTddlException, TcTpmException, TcTcsException
	{
		return TcTcsi.TcsipGetTestResult(hContext);
	}


	public Object[] TcsipSetOwnerInstall(long hContext, boolean state)
		throws TcTddlException, TcTpmException, TcTcsException
	{
		return TcTcsi.TcsipSetOwnerInstall(hContext, state);
	}


	public Object[] TcsipOwnerSetDisable(long hContext, boolean disableState, TcTcsAuth inAuth1)
		throws TcTddlException, TcTpmException, TcTcsException
	{
		return TcTcsi.TcsipOwnerSetDisable(hContext, disableState, inAuth1);
	}


	public Object[] TcsipPhysicalEnable(long hContext)
		throws TcTddlException, TcTpmException, TcTcsException
	{
		return TcTcsi.TcsipPhysicalEnable(hContext);
	}


	public Object[] TcsipPhysicalDisable(long hContext)
		throws TcTddlException, TcTpmException, TcTcsException
	{
		return TcTcsi.TcsipPhysicalDisable(hContext);
	}


	public Object[] TcsipPhysicalSetDeactivated(long hContext, boolean state)
		throws TcTddlException, TcTpmException, TcTcsException
	{
		return TcTcsi.TcsipPhysicalSetDeactivated(hContext, state);
	}


	public Object[] TcsipSetTempDeactivated2(long hContext, TcTcsAuth inAuth1)
		throws TcTddlException, TcTpmException, TcTcsException
	{
		return TcTcsi.TcsipSetTempDeactivated(hContext, inAuth1);
	}


	public Object[] TcsipSetTempDeactivated(long hContext)
		throws TcTddlException, TcTpmException, TcTcsException
	{
		return TcTcsi.TcsipSetTempDeactivatedNoAuth(hContext);
	}


	public Object[] TcsipSetOperatorAuth(long hContext, TcTpmSecret operatorAuth)
		throws TcTddlException, TcTpmException, TcTcsException
	{
		return TcTcsi.TcsipSetOperatorAuth(hContext, operatorAuth);
	}


	public Object[] TcsipTakeOwnership(long hContext, int protocolID, TcBlobData encOwnerAuth,
			TcBlobData encSrkAuth, TcITpmKeyNew srkParams, TcTcsAuth inAuth1)
		throws TcTddlException, TcTpmException, TcTcsException
	{
		return TcTcsi.TcsipTakeOwnership(hContext, protocolID, encOwnerAuth, encSrkAuth, srkParams,
				inAuth1);
	}


	public Object[] TcsipOwnerClear(long hContext, TcTcsAuth inAuth1)
		throws TcTddlException, TcTpmException, TcTcsException
	{
		return TcTcsi.TcsipOwnerClear(hContext, inAuth1);
	}


	public Object[] TcsipForceClear(long hContext)
		throws TcTddlException, TcTpmException, TcTcsException
	{
		return TcTcsi.TcsipForceClear(hContext);
	}


	public Object[] TcsipDisableOwnerClear(long hContext, TcTcsAuth inAuth1)
		throws TcTddlException, TcTpmException, TcTcsException
	{
		return TcTcsi.TcsipDisableOwnerClear(hContext, inAuth1);
	}


	public Object[] TcsipDisableForceClear(long hContext)
		throws TcTddlException, TcTpmException, TcTcsException
	{
		return TcTcsi.TcsipDisableForceClear(hContext);
	}


	public Object[] TcsipPhysicalPresence(long hContext, int physicalPresence)
		throws TcTddlException, TcTpmException, TcTcsException
	{
		return TcTcsi.TcsipDisableForceClear(hContext);
	}


	public Object[] TcsipGetCapability(long hContext, long capArea, TcBlobData subCap)
		throws TcTddlException, TcTpmException, TcTcsException
	{
		return TcTcsi.TcsipGetCapability(hContext, capArea, subCap);
	}


	public Object[] TcsipSetCapability(long hContext, long capArea, TcBlobData subCap,
			TcBlobData setValue, TcTcsAuth inAuth1)
		throws TcTddlException, TcTpmException, TcTcsException
	{
		return TcTcsi.TcsipSetCapability(hContext, capArea, subCap, setValue, inAuth1);
	}


	public Object[] TcsipGetCapabilityOwner(long hContext, TcTcsAuth inAuth1)
		throws TcTddlException, TcTpmException, TcTcsException
	{
		return TcTcsi.TcsipGetCapabilityOwner(hContext, inAuth1);
	}


	public Object[] TcsipGetAuditDigest(long hContext, long startOrdinal)
		throws TcTddlException, TcTpmException, TcTcsException
	{
		return TcTcsi.TcsipGetAuditDigest(hContext, startOrdinal);
	}


	public Object[] TcsipGetAuditDigestSigned(long hContext, long keyHandle, boolean closeAudit,
			TcTpmNonce antiReplay, TcTcsAuth inAuth1)
		throws TcTddlException, TcTpmException, TcTcsException
	{
		return TcTcsi.TcsipGetAuditDigestSigned(hContext, keyHandle, closeAudit, antiReplay, inAuth1);
	}


	public Object[] TcsipSetOrdinalAuditStatus(long hContext, TcTcsAuth inAuth1, long ordinalToAudit,
			boolean auditState) throws TcTddlException, TcTpmException, TcTcsException
	{
		return TcTcsi.TcsipSetOrdinalAuditStatus(hContext, inAuth1, ordinalToAudit, auditState);
	}


	public Object[] TcsipFieldUpgrade(long hContext, TcBlobData inData, TcTcsAuth ownerAuth)
		throws TcTddlException, TcTpmException, TcTcsException
	{
		return TcTcsi.TcsipFieldUpgrade(hContext, inData, ownerAuth);
	}


	public Object[] TcsipSetRedirection(long hContext, long keyHandle, long redirCmd,
			TcBlobData inputData, TcTcsAuth inAuth1)
		throws TcTddlException, TcTpmException, TcTcsException
	{
		return TcTcsi.TcsipSetRedirection(hContext, keyHandle, redirCmd, inputData, inAuth1);
	}


	public Object[] TcsipResetLockValue(long hContext, TcTcsAuth inAuth1)
		throws TcTddlException, TcTpmException, TcTcsException
	{
		return TcTcsi.TcsipResetLockValue(hContext, inAuth1);
	}


	public Object[] TcsipSeal(long hContext, long keyHandle, TcTpmEncauth encAuth,
			TcITpmPcrInfo pcrInfo, TcBlobData inData, TcTcsAuth inAuth1)
		throws TcTddlException, TcTpmException, TcTcsException
	{
		return TcTcsi.TcsipSeal(hContext, keyHandle, encAuth, pcrInfo, inData, inAuth1);
	}


	public Object[] TcsipUnseal(long hContext, long parentHandle, TcITpmStoredData inData,
			TcTcsAuth inAuth1, TcTcsAuth inAuth2) throws TcTddlException, TcTpmException, TcTcsException
	{
		return TcTcsi.TcsipUnseal(hContext, parentHandle, inData, inAuth1, inAuth2);
	}


	public Object[] TcsipUnBind(long hContext, long keyHandle, TcBlobData inData, TcTcsAuth inAuth1)
		throws TcTddlException, TcTpmException, TcTcsException
	{
		return TcTcsi.TcsipUnBind(hContext, keyHandle, inData, inAuth1);
	}


	public Object[] TcsipCreateWrapKey(long hContext, long parentHandle, TcTpmEncauth dataUsageAuth,
			TcTpmEncauth dataMigrationAuth, TcITpmKeyNew keyInfo, TcTcsAuth inAuth1)
		throws TcTddlException, TcTpmException, TcTcsException
	{
		return TcTcsi.TcsipCreateWrapKey(hContext, parentHandle, dataUsageAuth, dataMigrationAuth,
				keyInfo, inAuth1);
	}


	public Object[] TcsipSealx(long hContext, long keyHandle, TcTpmEncauth encAuth,
			TcTpmPcrInfoLong pcrInfo, TcBlobData inData, TcTcsAuth inAuth1)
		throws TcTddlException, TcTpmException, TcTcsException
	{
		return TcTcsi.TcsipSealx(hContext, keyHandle, encAuth, pcrInfo, inData, inAuth1);
	}


	public Object[] TcsipCreateMigrationBlob(long hContext, long parentHandle, int migrationType,
			TcTpmMigrationkeyAuth migrationKeyAuth, TcBlobData encData, TcTcsAuth inAuth1,
			TcTcsAuth inAuth2) throws TcTddlException, TcTpmException, TcTcsException
	{
		return TcTcsi.TcsipCreateMigrationBlob(hContext, parentHandle, migrationType, migrationKeyAuth,
				encData, inAuth1, inAuth2);
	}


	public Object[] TcsipConvertMigrationBlob(long hContext, long parentHandle, TcBlobData inData,
			TcBlobData random, TcTcsAuth inAuth1) throws TcTddlException, TcTpmException, TcTcsException
	{
		return TcTcsi.TcsipConvertMigrationBlob(hContext, parentHandle, inData, random, inAuth1);
	}


	public Object[] TcsipAuthorizeMigrationKey(long hContext, int migrationScheme,
			TcTpmPubkey migrationKey, TcTcsAuth inAuth1)
		throws TcTddlException, TcTpmException, TcTcsException
	{
		return TcTcsi.TcsipAuthorizeMigrationKey(hContext, migrationScheme, migrationKey, inAuth1);
	}


	public Object[] TcsipMigrateKey(long hContext, long maKeyHandle, TcTpmPubkey pubKey,
			TcBlobData inData, TcTcsAuth inAuth1) throws TcTddlException, TcTpmException, TcTcsException
	{
		return TcTcsi.TcsipMigrateKey(hContext, maKeyHandle, pubKey, inData, inAuth1);
	}


	public Object[] TcsipCmkSetRestrictions(long hContext, long restriction, TcTcsAuth inAuth1)
		throws TcTddlException, TcTpmException, TcTcsException
	{
		return TcTcsi.TcsipCmkSetRestrictions(hContext, restriction, inAuth1);
	}


	public Object[] TcsipCmkApproveMA(long hContext, TcTpmDigest migrationAuthorityDigest,
			TcTcsAuth inAuth1) throws TcTddlException, TcTpmException, TcTcsException
	{
		return TcTcsi.TcsipCmkApproveMA(hContext, migrationAuthorityDigest, inAuth1);
	}


	public Object[] TcsipCmkCreateKey(long hContext, long parentHandle, TcTpmEncauth dataUsageAuth,
			TcTpmDigest migrationAuthorityApproval, TcTpmDigest migrationAuthorityDigest,
			TcTpmKey12 keyInfo, TcTcsAuth inAuth1) throws TcTddlException, TcTpmException, TcTcsException
	{
		return TcTcsi.TcsipCmkCreateKey(hContext, parentHandle, dataUsageAuth,
				migrationAuthorityApproval, migrationAuthorityDigest, keyInfo, inAuth1);
	}


	public Object[] TcsipCmkCreateTicket(long hContext, TcTpmPubkey verificationKey,
			TcTpmDigest signedData, TcBlobData signatureValue, TcTcsAuth inAuth1)
		throws TcTddlException, TcTpmException, TcTcsException
	{
		return TcTcsi.TcsipCmkCreateTicket(hContext, verificationKey, signedData, signatureValue,
				inAuth1);
	}


	public Object[] TcsipCmkCreateBlob(long hContext, long parentHandle, int migrationType,
			TcTpmMigrationkeyAuth migrationKeyAuth, TcTpmDigest pubSourceKeyDigest,
			TcTpmMsaComposite msaList, TcBlobData restrictTicket, TcBlobData sigTicket,
			TcBlobData encData, TcTcsAuth inAuth1) throws TcTddlException, TcTpmException, TcTcsException
	{
		return TcTcsi.TcsipCmkCreateBlob(hContext, parentHandle, migrationType, migrationKeyAuth,
				pubSourceKeyDigest, msaList, restrictTicket, sigTicket, encData, inAuth1);
	}


	public Object[] TcsipCmkConvertMigration(long hContext, long parentHandle,
			TcTpmCmkAuth restrictTicket, TcTpmDigest sigTicket, TcTpmKey12 migratedKey,
			TcTpmMsaComposite msaList, TcBlobData random, TcTcsAuth inAuth1)
		throws TcTddlException, TcTpmException, TcTcsException
	{
		return TcTcsi.TcsipCmkConvertMigration(hContext, parentHandle, restrictTicket, sigTicket,
				migratedKey, msaList, random, inAuth1);
	}


	public Object[] TcsipCreateMaintenanceArchive(long hContext, boolean generateRandom,
			TcTcsAuth inAuth1) throws TcTddlException, TcTpmException, TcTcsException
	{
		return TcTcsi.TcsipCreateMaintenanceArchive(hContext, generateRandom, inAuth1);
	}


	public Object[] TcsipLoadMaintenanceArchive(long hContext, TcBlobData inData, TcTcsAuth ownerAuth)
		throws TcTddlException, TcTpmException, TcTcsException
	{
		return TcTcsi.TcsipLoadMaintenanceArchive(hContext, inData, ownerAuth);
	}


	public Object[] TcsipKillMaintenanceFeature(long hContext, TcTcsAuth inAuth1)
		throws TcTddlException, TcTpmException, TcTcsException
	{
		return TcTcsi.TcsipKillMaintenanceFeature(hContext, inAuth1);
	}


	public Object[] TcsipLoadManuMaintPub(long hContext, TcTpmNonce antiReplay, TcTpmPubkey pubKey)
		throws TcTddlException, TcTpmException, TcTcsException
	{
		return TcTcsi.TcsipLoadManuMaintPub(hContext, antiReplay, pubKey);
	}


	public Object[] TcsipReadManuMaintPub(long hContext, TcTpmNonce antiReplay)
		throws TcTddlException, TcTpmException, TcTcsException
	{
		return TcTcsi.TcsipReadManuMaintPub(hContext, antiReplay);
	}


	public Object[] TcsSHA1Start(long hContext)
		throws TcTddlException, TcTpmException, TcTcsException
	{
		return TcTcsi.TcsSHA1Start(hContext);
	}


	public Object[] TcsSHA1Update(long hContext, long numBytes, TcBlobData hashData)
		throws TcTddlException, TcTpmException, TcTcsException
	{
		return TcTcsi.TcsSHA1Update(hContext, numBytes, hashData);
	}


	public Object[] TcsSHA1Complete(long hContext, TcBlobData hashData)
		throws TcTddlException, TcTpmException, TcTcsException
	{
		return TcTcsi.TcsSHA1Complete(hContext, hashData);
	}


	public Object[] TcsSHA1CompleteExtend(long hContext, long pcrNum, TcBlobData hashData)
		throws TcTddlException, TcTpmException, TcTcsException
	{
		return TcTcsi.TcsSHA1CompleteExtend(hContext, pcrNum, hashData);
	}


	public Object[] TcsipSign(long hContext, long keyHandle, TcBlobData areaToSign, TcTcsAuth inAuth1)
		throws TcTddlException, TcTpmException, TcTcsException
	{
		return TcTcsi.TcsipSign(hContext, keyHandle, areaToSign, inAuth1);
	}


	public Object[] TcsipGetRandom(long hContext, long bytesRequested)
		throws TcTddlException, TcTpmException, TcTcsException
	{
		return TcTcsi.TcsipGetRandom(hContext, bytesRequested);
	}


	public Object[] TcsipStirRandom(long hContext, TcBlobData inData)
		throws TcTddlException, TcTpmException, TcTcsException
	{
		return TcTcsi.TcsipStirRandom(hContext, inData);
	}


	public Object[] TcsipCertifyKey(long hContext, long certHandle, long keyHandle,
			TcTpmNonce antiReplay, TcTcsAuth inAuth1, TcTcsAuth inAuth2)
		throws TcTddlException, TcTpmException, TcTcsException
	{
		return TcTcsi.TcsipCertifyKey(hContext, certHandle, keyHandle, antiReplay, inAuth1, inAuth2);
	}


	public Object[] TcsipCertifyKey2(long hContext, long certHandle, long keyHandle,
			TcTpmDigest migrationPubDigest, TcTpmNonce antiReplay, TcTcsAuth inAuth1, TcTcsAuth inAuth2)
		throws TcTddlException, TcTpmException, TcTcsException
	{
		return TcTcsi.TcsipCertifyKey2(hContext, certHandle, keyHandle, migrationPubDigest, antiReplay,
				inAuth1, inAuth2);
	}


	public Object[] TcsipCreateEndorsementKeyPair(long hContext, TcTpmNonce antiReplay,
			TcTpmKeyParms keyInfo) throws TcTddlException, TcTpmException, TcTcsException
	{
		return TcTcsi.TcsipCreateEndorsementKeyPair(hContext, antiReplay, keyInfo);
	}


	public Object[] TcsipCreateRevocableEK(long hContext, TcTpmNonce antiReplay,
			TcTpmKeyParms keyInfo, boolean generateReset, TcTpmNonce inputEKreset)
		throws TcTddlException, TcTpmException, TcTcsException
	{
		return TcTcsi
				.TcsipCreateRevocableEK(hContext, antiReplay, keyInfo, generateReset, inputEKreset);
	}


	public Object[] TcsipRevokeEndorsementKeyPair(long hContext, TcTpmNonce EKReset)
		throws TcTddlException, TcTpmException, TcTcsException
	{
		return TcTcsi.TcsipRevokeEndorsementKeyPair(hContext, EKReset);
	}


	public Object[] TcsipReadPubek(long hContext, TcTpmNonce antiReplay)
		throws TcTddlException, TcTpmException, TcTcsException
	{
		return TcTcsi.TcsipReadPubek(hContext, antiReplay);
	}


	public Object[] TcsipActivateIdentity(long hContext, long idKeyHandle, TcBlobData blob,
			TcTcsAuth inAuth1, TcTcsAuth inAuth2) throws TcTddlException, TcTpmException, TcTcsException
	{
		return TcTcsi.TcsipActivateTpmIdentity(hContext, idKeyHandle, blob, inAuth1, inAuth2);
	}


	public Object[] TcsipExtend(long hContext, long pcrNum, TcTpmDigest inDigest)
		throws TcTddlException, TcTpmException, TcTcsException
	{
		return TcTcsi.TcsipExtend(hContext, pcrNum, inDigest);
	}


	public Object[] TcsipPcrRead(long hContext, long pcrIndex)
		throws TcTddlException, TcTpmException, TcTcsException
	{
		return TcTcsi.TcsipPcrRead(hContext, pcrIndex);
	}


	public Object[] TcsipQuote(long hContext, long keyHandle, TcTpmNonce externalData,
			TcTpmPcrSelection targetPCR, TcTcsAuth inAuth1)
		throws TcTddlException, TcTpmException, TcTcsException
	{
		return TcTcsi.TcsipQuote(hContext, keyHandle, externalData, targetPCR, inAuth1);
	}


	public Object[] TcsipPcrReset(long hContext, TcTpmPcrSelection pcrSelection)
		throws TcTddlException, TcTpmException, TcTcsException
	{
		return TcTcsi.TcsipPcrReset(hContext, pcrSelection);
	}


	public Object[] TcsipQuote2(long hContext, long keyHandle, TcTpmNonce externalData,
			TcTpmPcrSelection targetPCR, boolean addVersion, TcTcsAuth inAuth1)
		throws TcTddlException, TcTpmException, TcTcsException
	{
		return TcTcsi.TcsipQuote2(hContext, keyHandle, externalData, targetPCR, addVersion, inAuth1);
	}


	public Object[] TcsipChangeAuth(long hContext, long parentHandle, int protocolID,
			TcTpmEncauth newAuth, int entityType, TcBlobData encData, TcTcsAuth inAuth1, TcTcsAuth inAuth2)
		throws TcTddlException, TcTpmException, TcTcsException
	{
		return TcTcsi.TcsipChangeAuth(hContext, parentHandle, protocolID, newAuth, entityType, encData,
				inAuth1, inAuth2);
	}


	public Object[] TcsipChangeAuthOwner(long hContext, int protocolID, TcTpmEncauth newAuth,
			int entityType, TcTcsAuth inAuth1) throws TcTddlException, TcTpmException, TcTcsException
	{
		return TcTcsi.TcsipChangeAuthOwner(hContext, protocolID, newAuth, entityType, inAuth1);
	}


	public Object[] TcsipOIAP(long hContext) throws TcTddlException, TcTpmException, TcTcsException
	{
		return TcTcsi.TcsipOIAP(hContext);
	}


	public Object[] TcsipOSAP(long hContext, int entityType, long entityValue, TcTpmNonce nonceOddOSAP)
		throws TcTddlException, TcTpmException, TcTcsException
	{
		return TcTcsi.TcsipOSAP(hContext, entityType, entityValue, nonceOddOSAP);
	}


	public Object[] TcsipDSAP(long hContext, int entityType, long keyHandle, TcTpmNonce nonceOddDSAP,
			TcBlobData entityValue) throws TcTddlException, TcTpmException, TcTcsException
	{
		return TcTcsi.TcsipDSAP(hContext, entityType, keyHandle, nonceOddDSAP, entityValue);
	}


	public Object[] TcsipDelegateManage(long hContext, long familyID, long opCode, TcBlobData opData,
			TcTcsAuth inAuth1) throws TcTddlException, TcTpmException, TcTcsException
	{
		return TcTcsi.TcsipDelegateManage(hContext, familyID, opCode, opData, inAuth1);
	}


	public Object[] TcsipDelegateCreateKeyDelegation(long hContext, long keyHandle,
			TcTpmDelegatePublic publicInfo, TcTpmEncauth delAuth, TcTcsAuth inAuth1)
		throws TcTddlException, TcTpmException, TcTcsException
	{
		return TcTcsi.TcsipDelegateCreateKeyDelegation(hContext, keyHandle, publicInfo, delAuth,
				inAuth1);
	}


	public Object[] TcsipDelegateCreateOwnerDelegation(long hContext, boolean increment,
			TcTpmDelegatePublic publicInfo, TcTpmEncauth delAuth, TcTcsAuth inAuth1)
		throws TcTddlException, TcTpmException, TcTcsException
	{
		return TcTcsi.TcsipDelegateCreateOwnerDelegation(hContext, increment, publicInfo, delAuth,
				inAuth1);
	}


	public Object[] TcsipDelegateLoadOwnerDelegation(long hContext, long index,
			TcTpmDelegateOwnerBlob blob, TcTcsAuth inAuth1)
		throws TcTddlException, TcTpmException, TcTcsException
	{
		return TcTcsi.TcsipDelegateLoadOwnerDelegation(hContext, index, blob, inAuth1);
	}


	public Object[] TcsipDelegateReadTable(long hContext)
		throws TcTddlException, TcTpmException, TcTcsException
	{
		return TcTcsi.TcsipDelegateReadTable(hContext);
	}


	public Object[] TcsipDelegateUpdateVerificationCount(long hContext, TcBlobData inputData,
			TcTcsAuth inAuth1) throws TcTddlException, TcTpmException, TcTcsException
	{
		return TcTcsi.TcsipDelegateUpdateVerificationCount(hContext, inputData, inAuth1);
	}


	public Object[] TcsipDelegateVerifyDelegation(long hContext, TcBlobData delegation)
		throws TcTddlException, TcTpmException, TcTcsException
	{
		return TcTcsi.TcsipDelegateVerifyDelegation(hContext, delegation);
	}


	public Object[] TcsipNvDefineOrReleaseSpace(long hContext, TcTpmNvDataPublic pubInfo,
			TcTpmEncauth encAuth, TcTcsAuth inAuth1)
		throws TcTddlException, TcTpmException, TcTcsException
	{
		return TcTcsi.TcsipNvDefineOrReleaseSpace(hContext, pubInfo, encAuth, inAuth1);
	}


	public Object[] TcsipNvWriteValue(long hContext, long nvIndex, long offset, TcBlobData data,
			TcTcsAuth inAuth1) throws TcTddlException, TcTpmException, TcTcsException
	{
		return TcTcsi.TcsipNvWriteValue(hContext, nvIndex, offset, data, inAuth1);
	}


	public Object[] TcsipNvWriteValueAuth(long hContext, long nvIndex, long offset, TcBlobData data,
			TcTcsAuth inAuth1) throws TcTddlException, TcTpmException, TcTcsException
	{
		return TcTcsi.TcsipNvWriteValueAuth(hContext, nvIndex, offset, data, inAuth1);
	}


	public Object[] TcsipNvReadValue(long hContext, long nvIndex, long offset, long dataSz,
			TcTcsAuth inAuth1) throws TcTddlException, TcTpmException, TcTcsException
	{
		return TcTcsi.TcsipNvReadValue(hContext, nvIndex, offset, dataSz, inAuth1);
	}


	public Object[] TcsipNvReadValueAuth(long hContext, long nvIndex, long offset, long dataSz,
			TcTcsAuth inAuth1) throws TcTddlException, TcTpmException, TcTcsException
	{
		return TcTcsi.TcsipNvReadValueAuth(hContext, nvIndex, offset, dataSz, inAuth1);
	}


	public Object[] TcsipReadCurrentTicks(long hContext)
		throws TcTddlException, TcTpmException, TcTcsException
	{
		return TcTcsi.TcsipReadCurrentTicks(hContext);
	}


	public Object[] TcsipTickStampBlob(long hContext, long keyHandle, TcTpmNonce antiReplay,
			TcTpmDigest digestToStamp, TcTcsAuth inAuth1)
		throws TcTddlException, TcTpmException, TcTcsException
	{
		return TcTcsi.TcsipTickStampBlob(hContext, keyHandle, antiReplay, digestToStamp, inAuth1);
	}


	public Object[] TcsEstablishTransport(long hContext, long encHandle,
			TcTpmTransportPublic transPublic, TcBlobData secret, TcTcsAuth inAuth1)
		throws TcTddlException, TcTpmException, TcTcsException
	{
		return TcTcsi.TcsEstablishTransport(hContext, encHandle, transPublic, secret, inAuth1);
	}


	public Object[] TcsExecuteTransport(long hContext, TcBlobData wrappedCmd, long transHandle,
			TcTcsAuth inAuth1) throws TcTddlException, TcTpmException, TcTcsException
	{
		return TcTcsi.TcsExecuteTransport(hContext, wrappedCmd, transHandle, inAuth1);
	}


	public Object[] TcsReleaseTransportSigned(long hContext, long keyHandle, TcTpmNonce antiReplay,
			long transHandle, TcTcsAuth inAuth1, TcTcsAuth inAuth2)
		throws TcTddlException, TcTpmException, TcTcsException
	{
		return TcTcsi.TcsReleaseTransportSigned(hContext, keyHandle, antiReplay, transHandle, inAuth1,
				inAuth2);
	}


	public Object[] TcsipCreateCounter(long hContext, TcBlobData label, TcTpmEncauth encAuth,
			TcTcsAuth inAuth1) throws TcTddlException, TcTpmException, TcTcsException
	{
		return TcTcsi.TcsipCreateCounter(hContext, label, encAuth, inAuth1);
	}


	public Object[] TcsipIncrementCounter(long hContext, long countID, TcTcsAuth inAuth1)
		throws TcTddlException, TcTpmException, TcTcsException
	{
		return TcTcsi.TcsipIncrementCounter(hContext, countID, inAuth1);
	}


	public Object[] TcsipReadCounter(long hContext, long countID)
		throws TcTddlException, TcTpmException, TcTcsException
	{
		return TcTcsi.TcsipReadCounter(hContext, countID);
	}


	public Object[] TcsipReleaseCounter(long hContext, long countID, TcTcsAuth inAuth1)
		throws TcTddlException, TcTpmException, TcTcsException
	{
		return TcTcsi.TcsipReleaseCounter(hContext, countID, inAuth1);
	}


	public Object[] TcsipReleaseCounterOwner(long hContext, long countID, TcTcsAuth inAuth1)
		throws TcTddlException, TcTpmException, TcTcsException
	{
		return TcTcsi.TcsipReleaseCounterOwner(hContext, countID, inAuth1);
	}


	public Object[] TcsipDaaJoin(long hContext, long handle, short stage, TcBlobData inputData0,
			TcBlobData inputData1, TcTcsAuth inAuth1)
		throws TcTddlException, TcTpmException, TcTcsException
	{
		return TcTcsi.TcsipDaaJoin(hContext, handle, stage, inputData0, inputData1, inAuth1);
	}


	public Object[] TcsipDaaSign(long hContext, long handle, short stage, TcBlobData inputData0,
			TcBlobData inputData1, TcTcsAuth inAuth1)
		throws TcTddlException, TcTpmException, TcTcsException
	{
		return TcTcsi.TcsipDaaSign(hContext, handle, stage, inputData0, inputData1, inAuth1);
	}


	public Object[] TcsipTerminateHandle(long hContext, long handle)
		throws TcTddlException, TcTpmException, TcTcsException
	{
		return TcTcsi.TcsipTerminateHandle(hContext, handle);
	}


	public Object[] TcsipDirWriteAuth(long hContext, long dirIndex, TcTpmDigest newContents,
			TcTcsAuth inAuth1) throws TcTddlException, TcTpmException, TcTcsException
	{
		return TcTcsi.TcsipDirWriteAuth(hContext, dirIndex, newContents, inAuth1);
	}


	public Object[] TcsipDirRead(long hContext, long dirIndex)
		throws TcTddlException, TcTpmException, TcTcsException
	{
		return TcTcsi.TcsipDirRead(hContext, dirIndex);
	}


	public Object[] TcsipChangeAuthAsymStart(long hContext, long idHandle, TcTpmNonce antiReplay,
			TcTpmKeyParms tempKey, TcTcsAuth inAuth1)
		throws TcTddlException, TcTpmException, TcTcsException
	{
		return TcTcsi.TcsipChangeAuthAsymStart(hContext, idHandle, antiReplay, tempKey, inAuth1);
	}


	public Object[] TcsipChangeAuthAsymFinish(long hContext, long parentHandle, long ephHandle,
			int entityType, TcTpmDigest newAuthLink, TcBlobData encNewAuth, TcBlobData encData,
			TcTcsAuth inAuth1) throws TcTddlException, TcTpmException, TcTcsException
	{
		return TcTcsi.TcsipChangeAuthAsymFinish(hContext, parentHandle, ephHandle, entityType,
				newAuthLink, encNewAuth, encData, inAuth1);
	}


	public Object[] TcsipOwnerReadPubek(long hContext, TcTcsAuth inAuth1)
		throws TcTddlException, TcTpmException, TcTcsException
	{
		return TcTcsi.TcsipOwnerReadPubek(hContext, inAuth1);
	}


	public Object[] TcsipDisablePubekRead(long hContext, TcTcsAuth inAuth1)
		throws TcTddlException, TcTpmException, TcTcsException
	{
		return TcTcsi.TcsipDisablePubekRead(hContext, inAuth1);
	}


	public Object[] TcsipIfxReadTpm11EkCert(long hContext, byte index, TcBlobData antiReplay)
		throws TcTddlException, TcTpmException, TcTcsException
	{
		return TcTcsi.TcsipIfxReadTpm11EkCert(hContext, index, antiReplay);
	}

}
