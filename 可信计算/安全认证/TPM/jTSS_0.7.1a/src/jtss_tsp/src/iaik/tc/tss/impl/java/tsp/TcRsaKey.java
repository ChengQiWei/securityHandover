/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.impl.java.tsp;


import iaik.tc.tss.api.constants.tpm.TcTpmConstants;
import iaik.tc.tss.api.constants.tpm.TcTpmOrdinals;
import iaik.tc.tss.api.constants.tsp.TcTssConstants;
import iaik.tc.tss.api.constants.tsp.TcTssErrors;
import iaik.tc.tss.api.exceptions.common.TcTssException;
import iaik.tc.tss.api.exceptions.tsp.TcTspException;
import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.tss.api.structs.tcs.TcTcsAuth;
import iaik.tc.tss.api.structs.tpm.TcITpmKey;
import iaik.tc.tss.api.structs.tpm.TcITpmKeyNew;
import iaik.tc.tss.api.structs.tpm.TcTpmCertifyInfo;
import iaik.tc.tss.api.structs.tpm.TcTpmCertifyInfo2;
import iaik.tc.tss.api.structs.tpm.TcTpmCmkAuth;
import iaik.tc.tss.api.structs.tpm.TcTpmDigest;
import iaik.tc.tss.api.structs.tpm.TcTpmEncauth;
import iaik.tc.tss.api.structs.tpm.TcTpmKey;
import iaik.tc.tss.api.structs.tpm.TcTpmKey12;
import iaik.tc.tss.api.structs.tpm.TcTpmKey12New;
import iaik.tc.tss.api.structs.tpm.TcTpmKeyNew;
import iaik.tc.tss.api.structs.tpm.TcTpmMigrationkeyAuth;
import iaik.tc.tss.api.structs.tpm.TcTpmMsaComposite;
import iaik.tc.tss.api.structs.tpm.TcTpmNonce;
import iaik.tc.tss.api.structs.tpm.TcTpmPcrInfo;
import iaik.tc.tss.api.structs.tpm.TcTpmPcrInfoLong;
import iaik.tc.tss.api.structs.tpm.TcTpmPubkey;
import iaik.tc.tss.api.structs.tpm.TcTpmRsaKeyParms;
import iaik.tc.tss.api.structs.tpm.TcTpmSecret;
import iaik.tc.tss.api.structs.tpm.TcTpmStoreAsymkey;
import iaik.tc.tss.api.structs.tpm.TcTpmStorePrivkey;
import iaik.tc.tss.api.structs.tpm.TcTpmStructVer;
import iaik.tc.tss.api.structs.tpm.TcTpmVersion;
import iaik.tc.tss.api.structs.tsp.TcTssUuid;
import iaik.tc.tss.api.structs.tsp.TcTssValidation;
import iaik.tc.tss.api.structs.tsp.TcTssVersion;
import iaik.tc.tss.api.tspi.TcIAttributes;
import iaik.tc.tss.api.tspi.TcIAuthObject;
import iaik.tc.tss.api.tspi.TcIContext;
import iaik.tc.tss.api.tspi.TcIMigData;
import iaik.tc.tss.api.tspi.TcIPcrComposite;
import iaik.tc.tss.api.tspi.TcIPolicy;
import iaik.tc.tss.api.tspi.TcIRsaKey;
import iaik.tc.tss.impl.csp.TcCrypto;
import iaik.tc.tss.impl.java.tsp.internal.TcTspInternal;
import iaik.tc.utils.misc.CheckPrecondition;
import iaik.tc.utils.misc.Utils;

public class TcRsaKey extends TcAuthObject implements TcIRsaKey {

	/**
	 * The TPM key structure.
	 */
	private TcITpmKey tpmKey_ = null;

	/**
	 * This flag in which persistent storage (USER, SYSTEM, NONE) a key is registered.
	 */
	private long keyRegister_ = TcTssConstants.TSS_TSPATTRIB_KEYREGISTER_NO;

	/**
	 * The UUID that was assigned to the key (used to address the key in the PS).
	 */
	private TcTssUuid keyUuid_ = null;

	/**
	 * The TCS key handle of the key.
	 */
	private long tcsKeyHandle_ = TcTssConstants.NULL_HKEY;

	/**
	 * The migration policy currently assigned to the object.
	 */
	private TcPolicy migrationPolicy_ = null;

	/**
	 * The authority hmac
	 */
	private TcTpmDigest msaApproval_ = null;

	/**
	 * The msa list digest
	 */
	private TcTpmDigest msaDigest_ = null;

	/*************************************************************************************************
	 * Hidden constructor (factory pattern).
	 */
	protected TcRsaKey(TcIContext context) throws TcTssException
	{
		super(context);
	}

	protected boolean isCmk()
	{
		if((tpmKey_ instanceof TcTpmKey12New) || (tpmKey_ instanceof TcTpmKey12))
			if((tpmKey_.getKeyFlags() & TcTpmConstants.TPM_MIGRATEAUTHORITY) == TcTpmConstants.TPM_MIGRATEAUTHORITY)
				return true;

		return false;
	}

	/*************************************************************************************************
	 * This method is used to decode a set of init flags. It checks if the provided flags contain one
	 * or more valid parameters. If more than one value for a parameter (e.g. TSS_KEY_SIZE_) is found,
	 * the first one is consumed and the following ones are discarded.
	 *
	 * @TSS_1_1_EA 54
	 *
	 * @param flags The init flags.
	 */
	protected synchronized void setInitFlags(long flags) throws TcTssException
	{
		// key structure version

		long keyStructVersion = 0;
		int struct = (int) (flags & TcTssConstants.TSS_KEY_STRUCT_BITMASK);

		if (struct == TcTssConstants.TSS_KEY_STRUCT_DEFAULT) {
			if (context_.getAttribVersionMode(0) == TcTssConstants.TSS_TSPATTRIB_CONTEXT_VERSION_V1_2) {
				keyStructVersion = TcTssConstants.TSS_KEY_STRUCT_KEY12;
			} else {
				keyStructVersion = TcTssConstants.TSS_KEY_STRUCT_KEY;
			}
		} else {
			keyStructVersion = struct;
		}

		// srk template

		int template = (int) (flags & TcTssConstants.TSS_KEY_TEMPLATE_BITMASK);
		if (template == TcTssConstants.TSS_KEY_TSP_SRK) {
			tpmKey_ = TcRsaKeyTemplates.getStorageKeyTemplate(keyStructVersion);
			tcsKeyHandle_ = TcTpmConstants.TPM_KEYHND_SRK;
			// TODO: maybe check if given flags conflict with SRK
		} else {

			// key type

			int type = (int) (flags & TcTssConstants.TSS_KEY_TYPE_BITMASK);
			switch (type) {
				case (int) TcTssConstants.TSS_KEY_TYPE_AUTHCHANGE:
					tpmKey_ = TcRsaKeyTemplates.getAuthChangeKeyTemplate(keyStructVersion);
					break;

				case (int) TcTssConstants.TSS_KEY_TYPE_BIND:
					tpmKey_ = TcRsaKeyTemplates.getBindKeyTemplate(keyStructVersion);
					break;

				case (int) TcTssConstants.TSS_KEY_TYPE_DEFAULT:
				case (int) TcTssConstants.TSS_KEY_TYPE_LEGACY:
					tpmKey_ = TcRsaKeyTemplates.getLegacyKeyTemplate(keyStructVersion);

					break;

				case (int) TcTssConstants.TSS_KEY_TYPE_IDENTITY:
					tpmKey_ = TcRsaKeyTemplates.getIdentityKeyTemplate(keyStructVersion);
					break;

				case (int) TcTssConstants.TSS_KEY_TYPE_MIGRATE:
					tpmKey_ = TcRsaKeyTemplates.getMigrateKeyTemplate(keyStructVersion);
					break;

				case (int) TcTssConstants.TSS_KEY_TYPE_SIGNING:
					tpmKey_ = TcRsaKeyTemplates.getSigningKeyTemplate(keyStructVersion);
					break;

				case (int) TcTssConstants.TSS_KEY_TYPE_STORAGE:
					tpmKey_ = TcRsaKeyTemplates.getStorageKeyTemplate(keyStructVersion);
					break;

				default:
					tpmKey_ = TcRsaKeyTemplates.getEmptyKeyTemplate(keyStructVersion);
			}
		}

		// key size

		long keySizeBits = 0;
		int size = (int) (flags & TcTssConstants.TSS_KEY_SIZE_BITMASK);
		if (size == 0) {
			size = (int) TcTssConstants.TSS_KEY_SIZE_DEFAULT;
		}
		switch (size) {
			case (int) TcTssConstants.TSS_KEY_SIZE_512:
				keySizeBits = 512;
				break;

			case (int) TcTssConstants.TSS_KEY_SIZE_1024:
				keySizeBits = 1024;
				break;

			case (int) TcTssConstants.TSS_KEY_SIZE_DEFAULT: // TODO: determined by TCS
			case (int) TcTssConstants.TSS_KEY_SIZE_2048:
				keySizeBits = 2048;
				break;

			case (int) TcTssConstants.TSS_KEY_SIZE_4096:
				keySizeBits = 4096;
				break;

			case (int) TcTssConstants.TSS_KEY_SIZE_8192:
				keySizeBits = 8192;
				break;

			case (int) TcTssConstants.TSS_KEY_SIZE_16384:
				keySizeBits = 16384;
				break;

			default:
				throw new TcTspException(TcTssErrors.TSS_E_BAD_PARAMETER, "Unknown key size.");
		}
		TcTpmRsaKeyParms params = new TcTpmRsaKeyParms(tpmKey_.getAlgorithmParms().getParms());
		params.setKeyLength(keySizeBits);
		tpmKey_.getAlgorithmParms().setParms(params.getEncoded());

		// authorization

		if ((flags & TcTssConstants.TSS_KEY_AUTHORIZATION) == TcTssConstants.TSS_KEY_AUTHORIZATION) {
			tpmKey_.setAuthDataUsage(TcTpmConstants.TPM_AUTH_ALWAYS);
		} else if ((flags & TcTssConstants.TSS_KEY_AUTHORIZATION_PRIV_USE_ONLY) == TcTssConstants.TSS_KEY_AUTHORIZATION_PRIV_USE_ONLY) {
			tpmKey_.setAuthDataUsage(TcTpmConstants.TPM_AUTH_PRIV_USE_ONLY);
		} else {
			tpmKey_.setAuthDataUsage(TcTpmConstants.TPM_AUTH_NEVER);
		}

		// TPM_KEY_FLAGS
		long keyFlags = 0;

		// volatile

		if ((flags & TcTssConstants.TSS_KEY_VOLATILE) == TcTssConstants.TSS_KEY_VOLATILE) {
			keyFlags |= TcTpmConstants.TPM_VOLATILE;
		}

		// migratable

		if ((flags & TcTssConstants.TSS_KEY_MIGRATABLE) == TcTssConstants.TSS_KEY_MIGRATABLE) {
			keyFlags |= TcTpmConstants.TPM_MIGRATABLE;
		}

		// certified migratable

		if ((flags & TcTssConstants.TSS_KEY_CERTIFIED_MIGRATABLE) == TcTssConstants.TSS_KEY_CERTIFIED_MIGRATABLE) {
			keyFlags |= TcTpmConstants.TPM_MIGRATEAUTHORITY;
		}

		tpmKey_.setKeyFlags(keyFlags);
	}


	/*
	 * (non-Javadoc)
	 *
	 * @see iaik.tss.api.tspi.TcIRsaKey#certifyKey(iaik.tss.api.tspi.TcIRsaKey,
	 *      iaik.tss.api.structs.tsp.TcTssValidation)
	 */
	public synchronized TcTssValidation certifyKey(TcIRsaKey certifyingKey, TcTssValidation validation)
		throws TcTssException
	{
		checkContextOpenAndConnected();
		CheckPrecondition.notNullAndInstanceOf(certifyingKey, "certifyingKey", TcRsaKey.class);
		context_.checkAssociation(certifyingKey, "certifyingKey");
		checkKeyHandleNotNull(((TcRsaKey) certifyingKey).getTcsKeyHandle(), "certifyingKey");
		CheckPrecondition.optionalInstanceOf(validation, "validation", TcTssValidation.class);

		long certHandle = ((TcRsaKey) certifyingKey).getTcsKeyHandle();
		TcTpmSecret certAuth = new TcTpmSecret(((TcPolicy) (certifyingKey.getUsagePolicyObject()))
				.getSecret());
		TcTpmSecret keyAuth = new TcTpmSecret(((TcPolicy) (getUsagePolicyObject())).getSecret());
		TcTpmNonce antiReplay = null;
		if (validation != null) {
			antiReplay = new TcTpmNonce(validation.getExternalData());
		} else {
			antiReplay = TcCrypto.createTcgNonce();
		}

		// start auth sessions
		TcTcsAuth inAuth1 = TcTspInternal.TspOIAP_Internal(context_);
		TcTcsAuth inAuth2 = TcTspInternal.TspOIAP_Internal(context_);

		// call to TPM
		Object[] tpmOutData;
		if(isCmk())
			tpmOutData = TcTspInternal.TspCertifyKey2_Internal(context_, certHandle, getTcsKeyHandle(),
					msaDigest_, antiReplay, inAuth1, inAuth2, certAuth, keyAuth);
		else
			tpmOutData = TcTspInternal.TspCertifyKey_Internal(context_, certHandle,
					getTcsKeyHandle(), antiReplay, inAuth1, inAuth2, certAuth, keyAuth);

		// decode TPM output data
		Object certifyInfoObj = tpmOutData[2];
		TcBlobData validationData = (TcBlobData) tpmOutData[3];

		// certifyInfoBlob can be either a TPM_CERTIFY_INFO or TPM_CERTIFY_INFO2
		TcBlobData certifyInfoBlob = null;
		if (certifyInfoObj instanceof TcTpmCertifyInfo) {
			certifyInfoBlob = ((TcTpmCertifyInfo) certifyInfoObj).getEncoded();
		} else if (certifyInfoObj instanceof TcTpmCertifyInfo2) {
			certifyInfoBlob = ((TcTpmCertifyInfo2) certifyInfoObj).getEncoded();
		} else {
			throw new TcTspException(TcTssErrors.TSS_E_INTERNAL_ERROR, "Unknown certify info structure.");
		}

		// construct return value
		TcTssValidation retVal = new TcTssValidation();
		if (validation != null) {
			retVal.setVersionInfo(validation.getVersionInfo());
		} else {
			retVal.setVersionInfo(TcTssVersion.TPM_V1_1);
		}
		retVal.setExternalData(antiReplay.getEncoded());
		retVal.setData(certifyInfoBlob);
		retVal.setValidationData(validationData);

		return retVal;
	}


	/*
	 * (non-Javadoc)
	 *
	 * @see iaik.tss.api.tspi.TcIRsaKey#convertMigrationBlob(iaik.tss.api.tspi.TcIRsaKey,
	 *      iaik.tss.api.structs.TcBlobData, iaik.tss.api.structs.TcBlobData)
	 */
	public synchronized void convertMigrationBlob(TcIRsaKey parent, TcBlobData random,
			TcBlobData migrationBlob) throws TcTssException
	{
		checkContextOpenAndConnected();
		CheckPrecondition.notNullAndInstanceOf(parent, "parent", TcRsaKey.class);
		context_.checkAssociation(parent, "parent");
		checkKeyHandleNotNull(((TcRsaKey) parent).getTcsKeyHandle(), "parent");

		TcTcsAuth inAuth = TcTspInternal.TspOIAP_Internal(context_);
		TcTpmSecret parentAuth = new TcTpmSecret(((TcPolicy)parent.getUsagePolicyObject()).getSecret());

		tpmKey_ = new TcTpmKey(migrationBlob);
		Object[] tpmOutData = TcTspInternal.TspConvertMigrationBlob_Internal(context_, ((TcRsaKey)parent).getTcsKeyHandle(),
					tpmKey_.getEncData(), random, inAuth, parentAuth);

		tpmKey_.setEncData((TcBlobData)tpmOutData[1]);
	}

	/*
	 * (non-Javadoc)
	 *
	 * @see iaik.tss.api.tspi.TcIRsaKey#migrateKey(iaik.tss.api.tspi.TcIRsaKey,
	 *      iaik.tss.api.tspi.TcIRsaKey)
	 */
	public synchronized void migrateKey(TcIRsaKey publicKey, TcIRsaKey migData)
			throws TcTssException
	{
		checkContextOpenAndConnected();
		CheckPrecondition.notNullAndInstanceOf(publicKey, "publicKey", TcRsaKey.class);
		context_.checkAssociation(publicKey, "publicKey");
		checkKeyHandleNotNull(((TcRsaKey) publicKey).getTcsKeyHandle(), "publicKey");
		CheckPrecondition.notNullAndInstanceOf(migData, "migData", TcRsaKey.class);

		TcTcsAuth inAuth = TcTspInternal.TspOIAP_Internal(context_);
		TcTpmSecret keyAuth = new TcTpmSecret(migrationPolicy_.getSecret());

		TcTpmPubkey pubKey = new TcTpmPubkey(publicKey.getPubKey());

		Object[] tpmOutData = TcTspInternal.TspMigrateKey_Internal(context_, getTcsKeyHandle(), pubKey,
				((TcRsaKey)migData).getInternalTpmKey().getEncData(), inAuth, keyAuth);

		((TcRsaKey)migData).getInternalTpmKey().setEncData((TcBlobData)tpmOutData[1]);
	}

	/*
	 * (non-Javadoc)
	 *
	 * @see iaik.tss.api.tspi.TcIRsaKey#CMKConvertMigration(iaik.tss.api.tspi.TcIRsaKey,
	 *      iaik.tss.api.tspi.TcIMigData, iaik.tss.api.structs.common.TcBlobData)
	 */
	public synchronized void CMKConvertMigration(TcIRsaKey parentKey,
			TcIMigData migrationData, TcBlobData random) throws TcTssException
	{
		checkContextOpenAndConnected();
		CheckPrecondition.notNullAndInstanceOf(parentKey, "parentKey", TcRsaKey.class);
		CheckPrecondition.notNullAndInstanceOf(migrationData, "migrationData", TcMigData.class);
		CheckPrecondition.notNull(random, "random");

		TcTcsAuth inAuth1 = TcTspInternal.TspOIAP_Internal(context_);
		TcTpmSecret parentAuth = new TcTpmSecret(((TcPolicy)((TcRsaKey)parentKey).getUsagePolicyObject()).getSecret());
		TcTpmCmkAuth restrictTicket = new TcTpmCmkAuth(((TcMigData)migrationData).getRestrictTicket());
		TcTpmDigest sigTicket = new TcTpmDigest(
				((TcMigData)migrationData).getAttribTicketData(TcTssConstants.TSS_MIGATTRIB_TICKET_SIG_TICKET));
		TcTpmMsaComposite msaList = ((TcMigData)migrationData).getMsaList();

		TcBlobData blob = ((TcMigData)migrationData).getAttribMigrationBlob(TcTssConstants.TSS_MIGATTRIB_MIGRATION_XOR_BLOB);
		TcTpmKey12 migratedKey = new TcTpmKey12(blob);

		Object[] tpmOutData = TcTspInternal.TspCmkConvertMigration_Internal(context_, ((TcRsaKey)parentKey).getTcsKeyHandle(),
				restrictTicket, sigTicket, migratedKey, msaList, random, inAuth1, parentAuth);

		tpmKey_.setEncData((TcBlobData)tpmOutData[1]);
	}


	/*
	 * (non-Javadoc)
	 *
	 * @see iaik.tss.api.tspi.TcIRsaKey#CMKCreateBlob(iaik.tss.api.tspi.TcIRsaKey,
	 *      iaik.tss.api.tspi.TcIMigData)
	 */
	public synchronized TcBlobData CMKCreateBlob(TcIRsaKey parentKey, TcIMigData migrationData)
		throws TcTssException
	{
		checkContextOpenAndConnected();
		CheckPrecondition.notNullAndInstanceOf(parentKey, "parentKey", TcRsaKey.class);
		CheckPrecondition.notNullAndInstanceOf(migrationData, "migrationData", TcMigData.class);

		TcTcsAuth inAuth1 = TcTspInternal.TspOIAP_Internal(context_);
		TcTpmSecret parentAuth = new TcTpmSecret(((TcPolicy)((TcRsaKey)parentKey).getUsagePolicyObject()).getSecret());

		TcBlobData migTicket = ((TcMigData)migrationData).getMigrationTicket();
		TcTpmMigrationkeyAuth migrationKeyAuth = new TcTpmMigrationkeyAuth(migTicket);
		int migrationType = migrationKeyAuth.getMigrationScheme();
		TcTpmDigest pubSourceKeyDigest = new TcTpmDigest(getPubKey().sha1());
		TcTpmMsaComposite msaList = ((TcMigData)migrationData).getMsaList();

		TcBlobData restrictTicket = null;
		TcBlobData sigTicket = null;
		if(migrationType == TcTpmConstants.TPM_MS_RESTRICT_APPROVE_DOUBLE)
		{
			restrictTicket = ((TcMigData)migrationData).getRestrictTicket();
			sigTicket = ((TcMigData)migrationData).getAttribTicketData(TcTssConstants.TSS_MIGATTRIB_TICKET_SIG_TICKET);
		}

		Object[] tpmOutData = TcTspInternal.TspCmkCreateBlob_Internal(context_, ((TcRsaKey)parentKey).getTcsKeyHandle(),
				migrationType, migrationKeyAuth, pubSourceKeyDigest, msaList, restrictTicket, sigTicket, tpmKey_.getEncData(), inAuth1, parentAuth);

		TcBlobData random = (TcBlobData)tpmOutData[1];
		TcTpmKey migKey = new TcTpmKey(tpmKey_.getEncoded());
		migKey.setEncData((TcBlobData)tpmOutData[2]);
		((TcMigData)migrationData).setBlob(migKey.getEncoded());

		return random;
	}

	/*
	 * (non-Javadoc)
	 *
	 * @see iaik.tss.api.tspi.TcIRsaKey#createKey(iaik.tss.api.tspi.TcIRsaKey,
	 *      iaik.tss.api.tspi.TcIPcrComposite)
	 */
	public synchronized void createKey(TcIRsaKey wrappingKey, TcIPcrComposite pcrComposite)
		throws TcTssException
	{
		checkContextOpenAndConnected();
		CheckPrecondition.notNullAndInstanceOf(wrappingKey, "wrappingKey", TcRsaKey.class);
		context_.checkAssociation(wrappingKey, "wrappingKey");
		checkKeyHandleNotNull(((TcRsaKey) wrappingKey).getTcsKeyHandle(), "wrappingKey");
		// note: pcrComposite can be null
		if (pcrComposite != null) {
			CheckPrecondition.isInstanceOf(pcrComposite, "pcrComposite", TcPcrCompositeBase.class);
			context_.checkAssociation(pcrComposite, "pcrComposite");
		}

		if (!(tpmKey_ instanceof TcITpmKeyNew)) {
			throw new TcTspException(TcTssErrors.TSS_E_INVALID_OBJ_ACCESS,
					"CreateKey can only be called for newly created key objects.");
		}

		long khParent = ((TcRsaKey) wrappingKey).getTcsKeyHandle();

		// set key PCR data
		if (pcrComposite != null) {
			if (tpmKey_ instanceof TcTpmKey12 && pcrComposite instanceof TcPcrCompositeInfoLong) {
				tpmKey_.setPcrInfo(((TcPcrCompositeInfoLong) pcrComposite).getPcrStructEncoded());

			} else if (tpmKey_ instanceof TcTpmKey && pcrComposite instanceof TcPcrCompositeInfo) {
				tpmKey_.setPcrInfo(((TcPcrCompositeInfo) pcrComposite).getPcrStructEncoded());

			} else {
				throw new TcTspException(TcTssErrors.TSS_E_BAD_PARAMETER,
						"Key structure and PcrComposite structure are for different TPM versions.");
			}
		}

		// TODO: check if secrets are null (SECRET_MODE_NONE)
		TcBlobData parentSecret = ((TcPolicy) wrappingKey.getUsagePolicyObject()).getSecret();
		TcBlobData keyUsageSecret = ((TcPolicy) getUsagePolicyObject()).getSecret();
		TcBlobData keyMigrationSecret = ((TcPolicy) getMigrationPolicyObject()).getSecret();

		// start new OSAP session
		TcTpmNonce nonceOddOSAP = TcCrypto.createTcgNonce();
		Object[] tpmOutData = TcTspInternal.TspOSAP_Internal(context_, TcTpmConstants.TPM_ET_XOR
				| TcTpmConstants.TPM_ET_KEYHANDLE, khParent, nonceOddOSAP);
		TcTcsAuth auth = (TcTcsAuth) tpmOutData[0];
		TcTpmNonce nonceEvenOSAP = (TcTpmNonce) tpmOutData[1];

		// calculate the ADIP shared secret
		TcBlobData sharedSecret = (TcBlobData) nonceEvenOSAP.getNonce().clone();
		sharedSecret.append(nonceOddOSAP.getNonce());
		// HMAC key is parent usage auth
		sharedSecret = sharedSecret.hmacSha1(parentSecret);

		// generate new nonce odd
		TcTpmNonce nonceOdd = TcCrypto.createTcgNonce();
		auth.setNonceOdd(nonceOdd);

		// XOR key for usage secret
		TcBlobData xorKeyUsg = (TcBlobData) sharedSecret.clone();
		xorKeyUsg.append(auth.getNonceEven().getNonce());
		xorKeyUsg = xorKeyUsg.sha1();

		// XOR key for migration secret
		TcBlobData xorKeyMig = (TcBlobData) sharedSecret.clone();
		xorKeyMig.append(auth.getNonceOdd().getNonce());
		xorKeyMig = xorKeyMig.sha1();

		// XOR encrypt the usage and migration secret
		TcTpmEncauth dataUsageAuth = new TcTpmEncauth(keyUsageSecret.xor(xorKeyUsg));
		TcTpmEncauth dataMigrationAuth = new TcTpmEncauth(keyMigrationSecret.xor(xorKeyMig));

		// send call to TPM
		if(isCmk()) {
			tpmOutData = TcTspInternal.TspCmkCreateKey_Internal(context_, khParent, dataUsageAuth,
					(TcTpmKey12)tpmKey_, msaApproval_, msaDigest_, auth, new TcTpmSecret(sharedSecret));

		} else {
			tpmOutData = TcTspInternal.TspCreateWrapKey_Internal(context_, khParent, dataUsageAuth,
					dataMigrationAuth, (TcITpmKeyNew) tpmKey_, auth, new TcTpmSecret(sharedSecret));
		}

		tpmKey_ = (TcITpmKey) tpmOutData[1];

		// Original Comment (tw): depending on keyRegister_ automatically register key in PS (Q: what UUID to use?)
		// No, the application needs full control over the hierarchy in the PS
	}

	/*
	 * (non-Javadoc)
	 *
	 * @see iaik.tss.api.tspi.TcIRsaKey#createMigrationBlob(iaik.tss.api.tspi.TcIRsaKey,
	 *      iaik.tss.api.structs.TcBlobData)
	 */
	public synchronized TcBlobData[] createMigrationBlob(TcIRsaKey parent, TcTpmMigrationkeyAuth migTicket)
		throws TcTssException
	{
		checkContextOpenAndConnected();
		CheckPrecondition.notNullAndInstanceOf(parent, "parent", TcRsaKey.class);
		context_.checkAssociation(parent, "parent");
		checkKeyHandleNotNull(((TcRsaKey) parent).getTcsKeyHandle(), "parent");

		TcTcsAuth inAuth1 = TcTspInternal.TspOIAP_Internal(context_);
		TcTpmSecret parentAuth = new TcTpmSecret(((TcPolicy)parent.getUsagePolicyObject()).getSecret());
		TcTcsAuth inAuth2 = TcTspInternal.TspOIAP_Internal(context_);
		TcTpmSecret entityAuth = new TcTpmSecret(migrationPolicy_.getSecret());

		Object[] tpmOutData = TcTspInternal.TspCreateMigrationBlob_Internal(context_, ((TcRsaKey)parent).getTcsKeyHandle(),
							migTicket.getMigrationScheme(), migTicket, tpmKey_.getEncData(), inAuth1, inAuth2, parentAuth, entityAuth);

		TcBlobData random = (TcBlobData)tpmOutData[2];
		TcTpmKey migKey = new TcTpmKey(tpmKey_.getEncoded());
		migKey.setEncData((TcBlobData)tpmOutData[3]);

		return new TcBlobData[] { random, migKey.getEncoded() };
	}


	/*
	 * (non-Javadoc)
	 *
	 * @see iaik.tss.api.tspi.TcIRsaKey#getPubKey()
	 */
	public synchronized TcBlobData getPubKey() throws TcTssException
	{
		checkContextOpenAndConnected();

		TcBlobData retVal = null;
		if (tcsKeyHandle_ == TcTpmConstants.TPM_KEYHND_SRK) {
			// SRK has to be directly retrieved from the TPM
			TcTpmSecret keyAuth = ((TcPolicy) getUsagePolicyObject()).getTpmSecret();
			TcTcsAuth inAuth1 = TcTspInternal.TspOIAP_Internal(context_);
			Object[] tpmOutData = TcTspInternal.TspGetPubKey_Internal(context_, tcsKeyHandle_, inAuth1,
					keyAuth);
			retVal = ((TcTpmPubkey) tpmOutData[1]).getEncoded();

		} else {
			// other keys are expected to be present in the local tpmKey_ structure.

			if (tpmKey_ == null || tpmKey_.getPubKey() == null || tpmKey_.getPubKey().getKey() == null) {
				throw new TcTspException(TcTssErrors.TSS_E_INTERNAL_ERROR, "Unable to retrieve public key.");
			}

			retVal = getAttribKeyBlob(TcTssConstants.TSS_TSPATTRIB_KEYBLOB_PUBLIC_KEY);
		}

		return retVal;
	}


	/*
	 * (non-Javadoc)
	 *
	 * @see iaik.tss.api.tspi.TcIRsaKey#loadKey(iaik.tss.api.tspi.TcIRsaKey)
	 */
	public synchronized void loadKey(TcIRsaKey unwrappingKey) throws TcTssException
	{
		checkContextOpenAndConnected();
		CheckPrecondition.notNullAndInstanceOf(unwrappingKey, "unwrappingKey", TcRsaKey.class);
		context_.checkAssociation(unwrappingKey, "unwrappingKey");
		checkKeyHandleNotNull(((TcRsaKey) unwrappingKey).getTcsKeyHandle(), "unwrappingKey");
		CheckPrecondition.isInstanceOf(context_.getTpmObject(), "tpm", TcTpm.class);

		long hUnwrappingKey = ((TcRsaKey) unwrappingKey).getTcsKeyHandle();

		if (tpmKey_ instanceof TcITpmKeyNew) {
			throw new TcTspException(TcTssErrors.TSS_E_INVALID_OBJ_ACCESS,
					"Can not load key into TPM that has not been initialized "
							+ "(e.g. createKey or load key from persistent storage)");
		}

		// check if key is already loaded
		if (getTcsKeyHandle() != TcTssConstants.NULL_HKEY) {
			return;
		}

		// TODO: check if secret is null


		TcTpmSecret parentAuth = new TcTpmSecret(((TcPolicy) unwrappingKey.getUsagePolicyObject())
				.getSecret());

		TcTcsAuth inAuth1 = TcTspInternal.TspOIAP_Internal(context_);

		Object[] tpmOutData = null;
		if (((TcTpm) context_.getTpmObject()).isOrdinalSupported(TcTpmOrdinals.TPM_ORD_LoadKey2)) {
			tpmOutData = TcTspInternal.TspLoadKey2ByBlob_Internal(context_, hUnwrappingKey, tpmKey_,
					inAuth1, parentAuth);
		} else {
			if (tpmKey_ instanceof TcTpmKey) {
				tpmOutData = TcTspInternal.TspLoadKeyByBlob_Internal(context_, hUnwrappingKey,
						(TcTpmKey) tpmKey_, inAuth1, parentAuth);
			} else {
				throw new TcTspException(TcTssErrors.TSS_E_INTERNAL_ERROR,
						"Unable to load 1.2 key in 1.1 TPM");
			}
		}

		tcsKeyHandle_ = ((Long) tpmOutData[1]).longValue();

	}


	/*
	 * (non-Javadoc)
	 *
	 * @see iaik.tss.api.tspi.TcIRsaKey#unloadKey()
	 */
	public synchronized void unloadKey() throws TcTssException
	{
		checkContextOpenAndConnected();
		checkKeyHandleNotNull(getTcsKeyHandle(), "key");

		TcTspInternal.TcsipEvictKey(context_, tcsKeyHandle_);
		tcsKeyHandle_ = TcTssConstants.NULL_HKEY;
	}


	/*
	 * (non-Javadoc)
	 *
	 * @see iaik.tss.api.tspi.TcIRsaKey#wrapKey(iaik.tss.api.tspi.TcIRsaKey,
	 *      iaik.tss.api.tspi.TcIPcrComposite)
	 */
	public synchronized void wrapKey(TcIRsaKey wrappingKey, TcIPcrComposite pcrComposite)
		throws TcTssException
	{
		checkContextOpenAndConnected();
		CheckPrecondition.notNullAndInstanceOf(wrappingKey, "wrappingKey", TcRsaKey.class);
		checkKeyHandleNotNull(((TcRsaKey) wrappingKey).getTcsKeyHandle(), "wrappingKey");
		context_.checkAssociation(wrappingKey, "wrappingKey");
		CheckPrecondition.optionalInstanceOf(pcrComposite, "pcrComposite", TcPcrCompositeBase.class);
		if (pcrComposite != null) {
			context_.checkAssociation(pcrComposite, "pcrComposite");
		}

		// convert if tpmKey is a TcITpmKeyNew
		if (tpmKey_ instanceof TcITpmKeyNew) {
			TcITpmKey temp = null;
			if (tpmKey_ instanceof TcTpmKey12New) {
				TcTpmKey12 temp2 = new TcTpmKey12();
				temp2.setTag(((TcTpmKey12)tpmKey_).getTag());
				temp2.setFill(((TcTpmKey12)tpmKey_).getFill());
				temp = temp2;
			} else if (tpmKey_ instanceof TcTpmKeyNew) {
				TcTpmKey temp2 = new TcTpmKey();
				temp2.setVer(((TcTpmStructVer)((TcTpmKey)tpmKey_).getVer()));//why do get/setVer have different types?
				temp = temp2;
			}
			temp.setKeyUsage(tpmKey_.getKeyUsage());
			temp.setKeyFlags(tpmKey_.getKeyFlags());
			temp.setAuthDataUsage(tpmKey_.getAuthDataUsage());
			temp.setAlgorithmParms(tpmKey_.getAlgorithmParms());
			temp.setPcrInfo(tpmKey_.getPcrInfo());
			temp.setPubKey(tpmKey_.getPubKey());
			temp.setEncData(tpmKey_.getEncData());

			tpmKey_ = temp;
		}


		// set key PCR data
		if (pcrComposite != null) {
			if (tpmKey_ instanceof TcTpmKey12 && pcrComposite instanceof TcPcrCompositeInfoLong) {
				tpmKey_.setPcrInfo(((TcPcrCompositeInfoLong) pcrComposite).getPcrStructEncoded());

			} else if (tpmKey_ instanceof TcTpmKey && pcrComposite instanceof TcPcrCompositeInfo) {
				tpmKey_.setPcrInfo(((TcPcrCompositeInfo) pcrComposite).getPcrStructEncoded());

			} else {
				throw new TcTspException(TcTssErrors.TSS_E_BAD_PARAMETER,
						"Key structure and PcrComposite structure are for different TPM versions.");
			}
		}

		TcTpmPubkey wrappingPubKey = new TcTpmPubkey(wrappingKey.getPubKey());

		//retrieving relevant data for pubDataDigest in TPM_STORE_ASYMKEY
		TcBlobData keyBlobHash = null;
		if (tpmKey_ instanceof TcTpmKey12) {
			keyBlobHash = TcBlobData.newUINT16(((TcTpmKey12)tpmKey_).getTag());
			keyBlobHash.append(TcBlobData.newUINT16(((TcTpmKey12)tpmKey_).getFill()));
		} else if (tpmKey_ instanceof TcTpmKey) {
			keyBlobHash = TcBlobData.newBlobData(((TcTpmKey)tpmKey_).getVer().getEncoded());
		}
		keyBlobHash.append(TcBlobData.newUINT16(tpmKey_.getKeyUsage()));
		keyBlobHash.append(TcBlobData.newUINT32(tpmKey_.getKeyFlags()));
		keyBlobHash.append(TcBlobData.newBYTE(tpmKey_.getAuthDataUsage()));
		keyBlobHash.append(TcBlobData.newBlobData(tpmKey_.getAlgorithmParms().getEncoded()));
		keyBlobHash.append(TcBlobData.newUINT32(tpmKey_.getPcrInfoSize()));
		if (tpmKey_.getPcrInfoSize() != 0) {
			keyBlobHash.append(TcBlobData.newBlobData(tpmKey_.getPcrInfo()));
		}
		keyBlobHash.append(TcBlobData.newBlobData(tpmKey_.getPubKey().getEncoded()));

		TcTpmDigest pubDataDigest = new TcTpmDigest(keyBlobHash.sha1());

		//create store private key
		TcTpmStorePrivkey privKey = new TcTpmStorePrivkey();
		TcBlobData key = tpmKey_.getEncData();
		privKey.setKey(key);
		privKey.setKeyLength(key.getLengthAsLong());

		TcTpmStoreAsymkey asymKey = new TcTpmStoreAsymkey();
		asymKey.setPayload(TcTpmConstants.TPM_PT_ASYM);
		asymKey.setUsageAuth(((TcPolicy)getUsagePolicyObject()).getTpmSecret());
		asymKey.setMigrationAuth(((TcPolicy)getMigrationPolicyObject()).getTpmSecret());
		asymKey.setPubDataDigest(pubDataDigest);
		asymKey.setPrivKey(privKey);

		TcBlobData asymKeyBlob = asymKey.getEncoded();

		TcBlobData encData = null;

		if (wrappingKey.getAttribUint32(TcTssConstants.TSS_TSPATTRIB_KEY_INFO,
				TcTssConstants.TSS_TSPATTRIB_KEYINFO_ENCSCHEME)
				== TcTssConstants.TSS_ES_RSAESPKCSV15) {
			 encData = TcCrypto.pubEncryptRsaEcbPkcs1Padding(wrappingPubKey, asymKeyBlob);
		} else if (wrappingKey.getAttribUint32(TcTssConstants.TSS_TSPATTRIB_KEY_INFO,
				TcTssConstants.TSS_TSPATTRIB_KEYINFO_ENCSCHEME)
				== TcTssConstants.TSS_ES_RSAESOAEP_SHA1_MGF1) {
			encData = TcCrypto.pubEncryptRsaOaepSha1Mgf1(wrappingPubKey, asymKeyBlob);
		}

		tpmKey_.setEncData(encData);

	}


	/*
	 * (non-Javadoc)
	 *
	 * @see iaik.tss.impl.java.tsp.TcAuthObject#getPolicy(long)
	 */
	public synchronized TcIPolicy getPolicyObject(long policyType) throws TcTssException
	{
		if (policyType == TcTssConstants.TSS_POLICY_MIGRATION) {
			return migrationPolicy_;
		} else {
			return super.getPolicyObject(policyType);
		}
	}


	/*************************************************************************************************
	 * This method returns a policy object representing the migration policy currently assigned to the
	 * object. It is based on the getPolicy method of the TSS with TSS_POLICY_MIGRATION as parameter.
	 *
	 * Note: Policy objects are returned by reference. Keep that in mind when modifying a policy.
	 *
	 * @TSS_V1 73
	 *
	 * @TSS_1_2_EA 182
	 *
	 * @return Migration policy object.
	 *
	 * @throws TcTssException
	 */
	public synchronized TcIPolicy getMigrationPolicyObject() throws TcTssException
	{
		return getPolicyObject(TcTssConstants.TSS_POLICY_MIGRATION);
	}


	/*************************************************************************************************
	 * This method sets the migration policy object that is assigned to this key object. This
	 * functionality is used internally only and is therefore package protected.
	 *
	 * @param policy The policy object to be set.
	 */
	protected synchronized void setMigrationPolicy(TcIPolicy policy) throws TcTssException
	{
		checkContextOpen();
		CheckPrecondition.notNullAndInstanceOf(policy, "policy", TcPolicy.class);

		migrationPolicy_ = (TcPolicy) policy;
	}


	/*************************************************************************************************
	 * Internal method returning the TCS key handle. If the key is not loaded,
	 * {@link TcTssConstants#NULL_HKEY} is returned.
	 */
	protected synchronized long getTcsKeyHandle()
	{
		return tcsKeyHandle_;
	}


	/*************************************************************************************************
	 * Non public method that allows package protected access to the TPM key structure.
	 */
	protected synchronized void setInternalTpmKey(TcITpmKey key)
	{
		tpmKey_ = key;
	}


	/*************************************************************************************************
	 * Non public method that allows package protected access to the TPM key structure. This method
	 * returns a reference to the internal structure and therefore has to be handled with care!
	 */
	protected synchronized TcITpmKey getInternalTpmKey() throws TcTspException
	{
		return tpmKey_;
	}


	/*
	 * (non-Javadoc)
	 *
	 * @see iaik.tss.api.tspi.TcIAuthObject#changeAuth(iaik.tss.api.tspi.TcIAuthObject,
	 *      iaik.tss.api.tspi.TcIPolicy)
	 */
	public synchronized void changeAuth(TcIAuthObject parentObject, TcIPolicy newPolicy)
		throws TcTssException
	{
		checkContextOpenAndConnected();

		if (getTcsKeyHandle() == TcTpmConstants.TPM_KH_SRK) {
			// The only case where the parent object is not a key is where the SRK auth is changed.
			// In this case, the parent is the TPM (i.e. owner authorized).
			if (!(parentObject instanceof TcTpm)) {
				throw new TcTspException(TcTssErrors.TSS_E_BAD_PARAMETER,
						"For changing the SRK auth the parent object must be the TPM object.");
			}
		} else {
			CheckPrecondition.notNullAndInstanceOf(parentObject, "parentObject", TcRsaKey.class);
			checkKeyHandleNotNull(((TcRsaKey) parentObject).getTcsKeyHandle(),
					"parentObject.tcsKeyHandle");
		}
		CheckPrecondition.notNullAndInstanceOf(newPolicy, "newPolicy", TcPolicy.class);
		context_.checkAssociation(newPolicy, "newPolicy");
		checkKeyHandleNotNull(getTcsKeyHandle(), "key");

		if (getTcsKeyHandle() == TcTpmConstants.TPM_KH_SRK) {
			// SRK

			// do auth change
			genericChangeAuthOwner(TcTpmConstants.TPM_ET_SRK, ((TcTpm) parentObject)
					.getUsagePolicyObject(), newPolicy);

		} else {
			// normal RsaKey

			if (!(parentObject instanceof TcRsaKey)) {
				throw new TcTspException(TcTssErrors.TSS_E_BAD_PARAMETER,
						"For changing the key auth the parent object must be of type RsaKey.");
			}

			long parentHandle = ((TcRsaKey) parentObject).getTcsKeyHandle();

			TcBlobData newEncData = null;
			if (((TcPolicy) newPolicy).getPolicyType() == 1) {
				// do auth change for a usagePolicy
				newEncData = genericChangeAuth(TcTpmConstants.TPM_ET_KEYHANDLE, parentHandle,
						TcTpmConstants.TPM_ET_KEY, tpmKey_.getEncData(), parentHandle, parentObject
								.getUsagePolicyObject(), (TcPolicy) newPolicy,
						(TcPolicy) getUsagePolicyObject());
			} else {
				// do auth change for a migrationPolicy
				newEncData = genericChangeAuth(TcTpmConstants.TPM_ET_KEYHANDLE, parentHandle,
						TcTpmConstants.TPM_ET_KEY, tpmKey_.getEncData(), parentHandle, parentObject
								.getUsagePolicyObject(), (TcPolicy) newPolicy,
						(TcPolicy) getMigrationPolicyObject());
			}

			// set new encrypted blob
			tpmKey_.setEncData(newEncData);
		}

		// assign key to new policy
		newPolicy.assignToObject(this);
	}


	protected synchronized void closeObject() throws TcTssException
	{
		// remove migration policy association
		((TcPolicy) getMigrationPolicyObject()).removeAssignedAuthObj(this);

		// unload the key from the TPM
		unloadKey();

		super.closeObject();
	}


	// ----------------------------------------------------------------------------------------------
	// TSS attribute getters and setter
	// ----------------------------------------------------------------------------------------------

	/*************************************************************************************************
	 * This method defines the mapping of attribute flags to getter methods.
	 */
	protected void initAttribGetters()
	{
		// UINT32
		addGetterUINT32(TcTssConstants.TSS_TSPATTRIB_KEY_REGISTER, "getAttribKeyRegister");
		addGetterUINT32(TcTssConstants.TSS_TSPATTRIB_KEY_INFO, "getAttribKeyInfoUINT32");
		addGetterUINT32(TcTssConstants.TSS_TSPATTRIB_KEY_PCR_LONG, "getAttribKeyPcrLongUINT32");
		addGetterUINT32(TcTssConstants.TSS_TSPATTRIB_RSAKEY_INFO, "getAttribRsaKeyInfoUINT32");

		// Data
		addGetterData(TcTssConstants.TSS_TSPATTRIB_KEY_BLOB, "getAttribKeyBlob");
		addGetterData(TcTssConstants.TSS_TSPATTRIB_KEY_INFO, "getAttribKeyInfo");
		addGetterData(TcTssConstants.TSS_TSPATTRIB_RSAKEY_INFO, "getAttribRsaKeyInfo");
		// addGetterData(TcTssConstants.TSS_TSPATTRIB_KEY_UUID, "getAttribKeyUuid");
		addGetterData(TcTssConstants.TSS_TSPATTRIB_KEY_PCR_LONG, "getAttribKeyPcrLong");
		addGetterData(TcTssConstants.TSS_TSPATTRIB_KEY_PCR, "getAttribKeyPcr");
		addGetterData(TcTssConstants.TSS_TSPATTRIB_KEY_CMKINFO, "getAttribCmkInfo");
	}


	/*************************************************************************************************
	 * This method defines the mapping of attribute flags to setter methods.
	 */
	protected void initAttribSetters()
	{
		// UINT32
		addSetterUINT32(TcTssConstants.TSS_TSPATTRIB_KEY_INFO, "setAttribKeyInfo");
		addSetterUINT32(TcTssConstants.TSS_TSPATTRIB_RSAKEY_INFO, "setAttribRsaKeyInfoUINT32");

		// Data
		addSetterData(TcTssConstants.TSS_TSPATTRIB_KEY_BLOB, "setAttribKeyBlob");
		addSetterData(TcTssConstants.TSS_TSPATTRIB_RSAKEY_INFO, "setAttribRsaKeyInfo");
		addSetterData(TcTssConstants.TSS_TSPATTRIB_KEY_CMKINFO, "setAttribCmkInfo");
	}


	/*
	 * (non-Javadoc)
	 *
	 * @see iaik.tss.api.tspi.TcIRsaKey#getAttribKeyInfoVersion()
	 */
	public synchronized TcTssVersion getAttribKeyInfoVersion() throws TcTssException
	{
		TcTpmVersion tpmVer = new TcTpmVersion(getAttribKeyInfo(TcTssConstants.TSS_TSPATTRIB_KEYINFO_VERSION));
		TcTssVersion tssVer = new TcTssVersion();
		tssVer.setMajor(tpmVer.getMajor());
		tssVer.setMinor(tpmVer.getMinor());
		tssVer.setRevMajor(tpmVer.getRevMajor());
		tssVer.setRevMinor(tpmVer.getRevMinor());
		return tssVer;
	}


	/*
	 * (non-Javadoc)
	 *
	 * @see iaik.tss.api.tspi.TcIRsaKey#getAttribUuid()
	 */
	public synchronized TcTssUuid getAttribUuid() throws TcTssException
	{
		return (TcTssUuid) keyUuid_.clone();
	}


	/*
	 * (non-Javadoc)
	 *
	 * @see iaik.tss.api.tspi.TcIRsaKey#setAttribUuid()
	 */
	public void setAttribUuid(TcTssUuid uuid) throws TcTssException
	{
		keyUuid_=(TcTssUuid) uuid.clone();
	}

	/*************************************************************************************************
	 * This method returns the register the key is registered in. This method is an alternative to
	 * using {@link TcIAttributes#getAttribUint32(long, long)} using
	 * {@link TcTssConstants#TSS_TSPATTRIB_KEY_REGISTER} as flag.
	 *
	 * @param subFlag Ignored (set to 0).
	 *
	 * @return {@link TcTssConstants#TSS_TSPATTRIB_KEYREGISTER_SYSTEM} or
	 *         {@link TcTssConstants#TSS_TSPATTRIB_KEYREGISTER_USER} or
	 *         {@link TcTssConstants#TSS_TSPATTRIB_KEYREGISTER_NO}
	 */
	public synchronized long getAttribKeyRegister(long subFlag) throws TcTspException
	{

		throw new TcTspException(TcTssErrors.TSS_E_NOTIMPL);

		//return keyRegister_;
	}


	/*************************************************************************************************
	 * This method returns information about the key. This method is an alternative to using
	 * {@link TcIAttributes#getAttribUint32(long, long)} with
	 * {@link TcTssConstants#TSS_TSPATTRIB_KEY_INFO} as flag.
	 *
	 * @param subFlag Valid subFlags are:
	 *          <ul>
	 *          <li> {@link TcTssConstants#TSS_TSPATTRIB_KEYINFO_USAGE}; returns TSS_KEY_USAGE_XX
	 *          <li> {@link TcTssConstants#TSS_TSPATTRIB_KEYINFO_MIGRATABLE}; returns boolean vale
	 *          <li> {@link TcTssConstants#TSS_TSPATTRIB_KEYINFO_CMK}; returns boolean vale
	 *          <li> {@link TcTssConstants#TSS_TSPATTRIB_KEYINFO_REDIRECTED}; returns boolean vale
	 *          <li> {@link TcTssConstants#TSS_TSPATTRIB_KEYINFO_VOLATILE}; returns boolean vale
	 *          <li> {@link TcTssConstants#TSS_TSPATTRIB_KEYINFO_AUTHDATAUSAGE}; returns boolean vale
	 *          <li> {@link TcTssConstants#TSS_TSPATTRIB_KEYINFO_ALGORITHM}; returns TSS_ALG_XX
	 *          <li> {@link TcTssConstants#TSS_TSPATTRIB_KEYINFO_ENCSCHEME}; returns TSS_ES_XX
	 *          <li> {@link TcTssConstants#TSS_TSPATTRIB_KEYINFO_SIGSCHEME}; returns TSS_SS_XX
	 *          <li> {@link TcTssConstants#TSS_TSPATTRIB_KEYINFO_KEYFLAGS}; returns keyFlags
	 *          <li> {@link TcTssConstants#TSS_TSPATTRIB_KEYINFO_AUTHUSAGE}; returns authDataUsage
	 *          <li> {@link TcTssConstants#TSS_TSPATTRIB_KEYINFO_KEYSTRUCT}; returns
	 *          TSS_KEY_STRUCT_XX
	 *          <li> {@link TcTssConstants#TSS_TSPATTRIB_KEYINFO_SIZE}; returns key size in bits
	 *          </ul>
	 *
	 * @return Returns values depend on the actual subFlag.
	 */
	public synchronized long getAttribKeyInfoUINT32(long subFlag) throws TcTssException
	{
		long retVal = 0;
		if (subFlag == TcTssConstants.TSS_TSPATTRIB_KEYINFO_USAGE) {
			retVal = TcConstantsMappings.keyUsageMap.getTssForTpmVal(tpmKey_.getKeyUsage());

		} else if (subFlag == TcTssConstants.TSS_TSPATTRIB_KEYINFO_MIGRATABLE) {
			boolean val = ((tpmKey_.getKeyFlags() & TcTpmConstants.TPM_MIGRATABLE) == TcTpmConstants.TPM_MIGRATABLE);
			retVal = Utils.booleanToByte(val);

		} else if (subFlag == TcTssConstants.TSS_TSPATTRIB_KEYINFO_CMK) {
			boolean val = ((tpmKey_.getKeyFlags() & TcTpmConstants.TPM_MIGRATEAUTHORITY) == TcTpmConstants.TPM_MIGRATEAUTHORITY);
			retVal = Utils.booleanToByte(val);

		} else if (subFlag == TcTssConstants.TSS_TSPATTRIB_KEYINFO_REDIRECTED) {
			boolean val = ((tpmKey_.getKeyFlags() & TcTpmConstants.TPM_REDIRECTION) == TcTpmConstants.TPM_REDIRECTION);
			retVal = Utils.booleanToByte(val);

		} else if (subFlag == TcTssConstants.TSS_TSPATTRIB_KEYINFO_VOLATILE) {
			boolean val = ((tpmKey_.getKeyFlags() & TcTpmConstants.TPM_VOLATILE) == TcTpmConstants.TPM_VOLATILE);
			retVal = Utils.booleanToByte(val);

		} else if (subFlag == TcTssConstants.TSS_TSPATTRIB_KEYINFO_AUTHDATAUSAGE) {
			boolean val = true;
			if (tpmKey_.getAuthDataUsage() == TcTpmConstants.TPM_AUTH_NEVER) {
				val = false;
			}
			retVal = Utils.booleanToByte(val);

		} else if (subFlag == TcTssConstants.TSS_TSPATTRIB_KEYINFO_ALGORITHM) {
			long tpmAlg = tpmKey_.getAlgorithmParms().getAlgorithmID();
			return TcConstantsMappings.algMap.getTssForTpmVal(tpmAlg);

		} else if (subFlag == TcTssConstants.TSS_TSPATTRIB_KEYINFO_ENCSCHEME) {
			long tpmES = tpmKey_.getAlgorithmParms().getEncScheme();
			return TcConstantsMappings.esMap.getTssForTpmVal(tpmES);

		} else if (subFlag == TcTssConstants.TSS_TSPATTRIB_KEYINFO_SIGSCHEME) {
			long tpmSS = tpmKey_.getAlgorithmParms().getSigScheme();
			return TcConstantsMappings.ssMap.getTssForTpmVal(tpmSS);

		} else if (subFlag == TcTssConstants.TSS_TSPATTRIB_KEYINFO_KEYFLAGS) {
			return tpmKey_.getKeyFlags();

		} else if (subFlag == TcTssConstants.TSS_TSPATTRIB_KEYINFO_AUTHUSAGE) {
			return tpmKey_.getAuthDataUsage();

		} else if (subFlag == TcTssConstants.TSS_TSPATTRIB_KEYINFO_KEYSTRUCT) {
			if (tpmKey_ instanceof TcTpmKey12) {
				return TcTssConstants.TSS_KEY_STRUCT_KEY12;
			} else {
				return TcTssConstants.TSS_KEY_STRUCT_KEY;
			}

		} else if (subFlag == TcTssConstants.TSS_TSPATTRIB_KEYINFO_SIZE) {
			TcTpmRsaKeyParms params = new TcTpmRsaKeyParms(tpmKey_.getAlgorithmParms().getParms());
			return params.getKeyLength();

		} else {
			throw new TcTspException(TcTssErrors.TSS_E_INVALID_ATTRIB_SUBFLAG);
		}

		return retVal;
	}


	/*************************************************************************************************
	 * This method sets key information as defined for {@link TcTssConstants#TSS_TSPATTRIB_KEY_INFO}.
	 * This method is an alternative to using {@link TcIAttributes#setAttribUint32(long, long, long)}.
	 * Note that this method is not standardized as part of the TSP Interface (TSPI).
	 *
	 * @param subFlag Valid subFlags are:
	 *          <ul>
	 *          <li> {@link TcTssConstants#TSS_TSPATTRIB_KEYINFO_USAGE}
	 *          <li> {@link TcTssConstants#TSS_TSPATTRIB_KEYINFO_MIGRATABLE}
	 *          <li> {@link TcTssConstants#TSS_TSPATTRIB_KEYINFO_REDIRECTED}
	 *          <li> {@link TcTssConstants#TSS_TSPATTRIB_KEYINFO_VOLATILE}
	 *          <li> {@link TcTssConstants#TSS_TSPATTRIB_KEYINFO_AUTHDATAUSAGE}
	 *          <li> {@link TcTssConstants#TSS_TSPATTRIB_KEYINFO_ALGORITHM}
	 *          <li> {@link TcTssConstants#TSS_TSPATTRIB_KEYINFO_ENCSCHEME}
	 *          <li> {@link TcTssConstants#TSS_TSPATTRIB_KEYINFO_SIGSCHEME}
	 *          <li> {@link TcTssConstants#TSS_TSPATTRIB_KEYINFO_SIZE}
	 *          <li> {@link TcTssConstants#TSS_TSPATTRIB_KEYINFO_KEYFLAGS}
	 *          <li> {@link TcTssConstants#TSS_TSPATTRIB_KEYINFO_AUTHUSAGE}
	 *          <li> {@link TcTssConstants#TSS_TSPATTRIB_KEYINFO_KEYSTRUCT}
	 *          </ul>
	 *
	 * @param attrib The attribute value corresponding to the given subFlag.
	 */
	public synchronized void setAttribKeyInfo(long subFlag, long attrib) throws TcTssException
	{
		if (subFlag == TcTssConstants.TSS_TSPATTRIB_KEYINFO_USAGE) {
			tpmKey_.setKeyUsage((int) TcConstantsMappings.keyUsageMap.getTpmForTssVal(attrib));

		} else if (subFlag == TcTssConstants.TSS_TSPATTRIB_KEYINFO_MIGRATABLE) {
			boolean val = Utils.byteToBoolean((byte) attrib);
			if (val) {
				long keyFlags = tpmKey_.getKeyFlags();
				tpmKey_.setKeyFlags(keyFlags |= TcTpmConstants.TPM_MIGRATABLE);
			}

		} else if (subFlag == TcTssConstants.TSS_TSPATTRIB_KEYINFO_REDIRECTED) {
			boolean val = Utils.byteToBoolean((byte) attrib);
			if (val) {
				long keyFlags = tpmKey_.getKeyFlags();
				tpmKey_.setKeyFlags(keyFlags |= TcTpmConstants.TPM_REDIRECTION);
			}

		} else if (subFlag == TcTssConstants.TSS_TSPATTRIB_KEYINFO_VOLATILE) {
			boolean val = Utils.byteToBoolean((byte) attrib);
			if (val) {
				long keyFlags = tpmKey_.getKeyFlags();
				tpmKey_.setKeyFlags(keyFlags |= TcTpmConstants.TPM_VOLATILE);
			}

		} else if (subFlag == TcTssConstants.TSS_TSPATTRIB_KEYINFO_AUTHDATAUSAGE) {
			tpmKey_.setAuthDataUsage(TcTpmConstants.TPM_AUTH_ALWAYS);
			// note: defined as boolean value in the spec although there are three possible values...

		} else if (subFlag == TcTssConstants.TSS_TSPATTRIB_KEYINFO_ALGORITHM) {
			long tpmAlg = TcConstantsMappings.algMap.getTpmForTssVal(attrib);
			tpmKey_.getAlgorithmParms().setAlgorithmID(tpmAlg);

		} else if (subFlag == TcTssConstants.TSS_TSPATTRIB_KEYINFO_ENCSCHEME) {
			long tpmES = TcConstantsMappings.esMap.getTpmForTssVal(attrib);
			tpmKey_.getAlgorithmParms().setEncScheme((int) tpmES);

		} else if (subFlag == TcTssConstants.TSS_TSPATTRIB_KEYINFO_SIGSCHEME) {
			long tpmSS = TcConstantsMappings.ssMap.getTpmForTssVal(attrib);
			tpmKey_.getAlgorithmParms().setSigScheme((int) tpmSS);

		} else if (subFlag == TcTssConstants.TSS_TSPATTRIB_KEYINFO_SIZE) {
			TcTpmRsaKeyParms params = new TcTpmRsaKeyParms(tpmKey_.getAlgorithmParms().getParms());
			params.setKeyLength(attrib);
			tpmKey_.getAlgorithmParms().setParms(params.getEncoded());

		} else if (subFlag == TcTssConstants.TSS_TSPATTRIB_KEYINFO_KEYFLAGS) {
			tpmKey_.setKeyFlags(attrib);

		} else if (subFlag == TcTssConstants.TSS_TSPATTRIB_KEYINFO_AUTHUSAGE) {
			tpmKey_.setAuthDataUsage((short) attrib);

		} else if (subFlag == TcTssConstants.TSS_TSPATTRIB_KEYINFO_KEYSTRUCT) {
			throw new TcTspException(
					TcTssErrors.TSS_E_INVALID_ATTRIB_SUBFLAG,
					"This TSP implementation does not alow to alter the key structure type after object initialization.");

		} else {
			throw new TcTspException(TcTssErrors.TSS_E_INVALID_ATTRIB_SUBFLAG);
		}

	}


	/*************************************************************************************************
	 * This method sets RSA key information as defined for
	 * {@link TcTssConstants#TSS_TSPATTRIB_RSAKEY_INFO}. This method is an alternative to using
	 * {@link TcIAttributes#setAttribUint32(long, long, long)} with
	 * Constants#TSS_TSPATTRIB_RSAKEY_INFO} as flag.
	 *
	 * @param subFlag Valid subFlags are:
	 *          <ul>
	 *          <li> {@link TcTssConstants#TSS_TSPATTRIB_KEYINFO_RSA_PRIMES}
	 *          </ul>
	 *
	 * @param attrib The attribute value corresponding to the given subFlag.
	 */
	public synchronized void setAttribRsaKeyInfoUINT32(long subFlag, long attrib)
		throws TcTssException
	{
		if (subFlag == TcTssConstants.TSS_TSPATTRIB_KEYINFO_RSA_PRIMES) {
			TcTpmRsaKeyParms params = new TcTpmRsaKeyParms(tpmKey_.getAlgorithmParms().getParms());
			params.setNumPrimes(attrib);
		} else {
			throw new TcTspException(TcTssErrors.TSS_E_INVALID_ATTRIB_SUBFLAG);
		}
	}


	/*************************************************************************************************
	 * This method returns RSA key information as defined for
	 * {@link TcTssConstants#TSS_TSPATTRIB_RSAKEY_INFO}. This method is an alternative to using
	 * {@link TcIAttributes#getAttribUint32(long, long)} with
	 * {@link TcTssConstants#TSS_TSPATTRIB_RSAKEY_INFO} as flag.
	 *
	 * @param subFlag Valid subFlags are:
	 *          <ul>
	 *          <li> {@link TcTssConstants#TSS_TSPATTRIB_KEYINFO_RSA_KEYSIZE}
	 *          <li> {@link TcTssConstants#TSS_TSPATTRIB_KEYINFO_RSA_PRIMES}
	 *          </ul>
	 *
	 * @return The requested key information.
	 */
	public synchronized long getAttribRsaKeyInfoUINT32(long subFlag) throws TcTssException
	{
		long retVal = 0;
		TcTpmRsaKeyParms params = new TcTpmRsaKeyParms(tpmKey_.getAlgorithmParms().getParms());
		if (subFlag == TcTssConstants.TSS_TSPATTRIB_KEYINFO_RSA_KEYSIZE) {
			retVal = params.getKeyLength();
		} else if (subFlag == TcTssConstants.TSS_TSPATTRIB_KEYINFO_RSA_PRIMES) {
			retVal = params.getNumPrimes();
		} else {
			throw new TcTspException(TcTssErrors.TSS_E_INVALID_ATTRIB_SUBFLAG);
		}
		return retVal;
	}


	/*************************************************************************************************
	 * This method returns locality information as defined for
	 * {@link TcTssConstants#TSS_TSPATTRIB_KEY_PCR_LONG}. This method is an alternative to using
	 * {@link TcIAttributes#getAttribUint32(long, long)} with Constants#TSS_TSPATTRIB_KEY_PCR_LONG} as
	 * flag.
	 *
	 * @param subFlag Valid subFlags are:
	 *          <ul>
	 *          <li> {@link TcTssConstants#TSS_TSPATTRIB_KEYPCRLONG_LOCALITY_ATCREATION}
	 *          <li> {@link TcTssConstants#TSS_TSPATTRIB_KEYPCRLONG_LOCALITY_ATRELEASE}
	 *          </ul>
	 *
	 * @return The requested locality information.
	 */
	public synchronized long getAttribKeyPcrLongUINT32(long subFlag) throws TcTssException
	{
		if (tpmKey_.getPcrInfo() == null) {
			throw new TcTspException(TcTssErrors.TSS_E_NO_PCRS_SET, "No PCRs set for this key.");
		}
		if (tpmKey_ instanceof TcTpmKey) {
			throw new TcTspException(TcTssErrors.TSS_E_INVALID_OBJECT_TYPE,
					"No locality support for 1.1 type keys.");
		}

		TcTpmPcrInfoLong pcrInfo = new TcTpmPcrInfoLong(tpmKey_.getPcrInfo());
		long retVal = 0;
		if (subFlag == TcTssConstants.TSS_TSPATTRIB_KEYPCRLONG_LOCALITY_ATRELEASE) {
			retVal = pcrInfo.getLocalityAtRelease();
		} else if (subFlag == TcTssConstants.TSS_TSPATTRIB_KEYPCRLONG_LOCALITY_ATCREATION) {
			retVal = pcrInfo.getLocalityAtCreation();
		} else {
			throw new TcTspException(TcTssErrors.TSS_E_INVALID_ATTRIB_SUBFLAG);
		}
		return retVal;
	}


	/*************************************************************************************************
	 * This method sets RSA key information as defined for
	 * {@link TcTssConstants#TSS_TSPATTRIB_RSAKEY_INFO}. This method is an alternative to using
	 * {@link TcIAttributes#setAttribData(long, long, TcBlobData)} with
	 * {@link TcTssConstants#TSS_TSPATTRIB_RSAKEY_INFO} as flag.
	 *
	 * @param subFlag Valid subFlags are:
	 *          <ul>
	 *          <li> {@link TcTssConstants#TSS_TSPATTRIB_KEYINFO_RSA_EXPONENT}
	 *          <li> {@link TcTssConstants#TSS_TSPATTRIB_KEYINFO_RSA_MODULUS}
	 *          </ul>
	 *
	 * @param attrib The attribute value corresponding to the given subFlag.
	 */
	public synchronized void setAttribRsaKeyInfo(long subFlag, TcBlobData attrib)
		throws TcTssException
	{
		if (subFlag == TcTssConstants.TSS_TSPATTRIB_KEYINFO_RSA_EXPONENT) {
			TcTpmRsaKeyParms rsaKeyParms = new TcTpmRsaKeyParms(tpmKey_.getAlgorithmParms().getParms());
			rsaKeyParms.setExponent(attrib);
			tpmKey_.getAlgorithmParms().setParms(rsaKeyParms.getEncoded());
		} else if (subFlag == TcTssConstants.TSS_TSPATTRIB_KEYINFO_RSA_MODULUS) {
			tpmKey_.getPubKey().setKey(attrib);
		} else {
			throw new TcTspException(TcTssErrors.TSS_E_INVALID_ATTRIB_SUBFLAG);
		}
	}


	/*************************************************************************************************
	 * This method returns RSA key information as defined for
	 * {@link TcTssConstants#TSS_TSPATTRIB_RSAKEY_INFO}. This method is an alternative to using
	 * {@link TcIAttributes#getAttribData(long, long)} with
	 * {@link TcTssConstants#TSS_TSPATTRIB_RSAKEY_INFO} as subFlag.
	 *
	 * @param subFlag Valid subFlags are:
	 *          <ul>
	 *          <li> {@link TcTssConstants#TSS_TSPATTRIB_KEYINFO_RSA_EXPONENT}
	 *          <li> {@link TcTssConstants#TSS_TSPATTRIB_KEYINFO_RSA_MODULUS}
	 *          </ul>
	 *
	 * @return The requested information as specified by subFlag.
	 */
	public synchronized TcBlobData getAttribRsaKeyInfo(long subFlag) throws TcTssException
	{
		TcBlobData retVal = null;
		if (subFlag == TcTssConstants.TSS_TSPATTRIB_KEYINFO_RSA_EXPONENT) {
			TcTpmRsaKeyParms rsaKeyParms = new TcTpmRsaKeyParms(tpmKey_.getAlgorithmParms().getParms());
		
			if (rsaKeyParms.getExponent()!=null)
			  retVal = (TcBlobData) rsaKeyParms.getExponent().clone();
			else
				retVal = TcBlobData.newUINT32(65537); //the default exponent

		} else if (subFlag == TcTssConstants.TSS_TSPATTRIB_KEYINFO_RSA_MODULUS) {
			retVal = (TcBlobData) tpmKey_.getPubKey().getKey().clone();

		} else {
			throw new TcTspException(TcTssErrors.TSS_E_INVALID_ATTRIB_SUBFLAG);
		}
		return retVal;
	}


	/*************************************************************************************************
	 * This method sets RSA key information as defined for
	 * {@link TcTssConstants#TSS_TSPATTRIB_KEY_BLOB}. This method is an alternative to using
	 * {@link TcIAttributes#setAttribData(long, long, TcBlobData)} with
	 * {@link TcTssConstants#TSS_TSPATTRIB_KEY_BLOB} as flag.
	 *
	 * @param subFlag Valid subFlags are:
	 *          <ul>
	 *          <li> {@link TcTssConstants#TSS_TSPATTRIB_KEYBLOB_BLOB} Note: When setting the key
	 *          blob, it is assumed that it is of the same structure type (1.1 vs. 1.2) as specified
	 *          in the initFlags of the key object.
	 *          <li> {@link TcTssConstants#TSS_TSPATTRIB_KEYBLOB_PUBLIC_KEY}
	 *          <li> {@link TcTssConstants#TSS_TSPATTRIB_KEYBLOB_PRIVATE_KEY}
	 *          </ul>
	 *
	 * @param attrib The attribute value corresponding to the given subFlag.
	 */
	public synchronized void setAttribKeyBlob(long subFlag, TcBlobData attrib) throws TcTssException
	{
		if (subFlag == TcTssConstants.TSS_TSPATTRIB_KEYBLOB_BLOB) {
			// Note: There is no chance to determine the type of the key blob (1.1 vs. 1.2).
			// As a consequence, we assume that the given blob is of the same type as the current
			// TPM key instance. Via the init flags, callers can explicitly define the key struct
			// type used by the key.
			if (tpmKey_ instanceof TcTpmKey) {
				tpmKey_ = new TcTpmKey(attrib);
			} else {
				tpmKey_ = new TcTpmKey12(attrib);
			}
		} else if (subFlag == TcTssConstants.TSS_TSPATTRIB_KEYBLOB_PUBLIC_KEY) {
			TcTpmPubkey pubKey = new TcTpmPubkey(attrib);
			tpmKey_.setAlgorithmParms(pubKey.getAlgorithmParms());
			tpmKey_.setPubKey(pubKey.getPubKey());

		} else if (subFlag == TcTssConstants.TSS_TSPATTRIB_KEYBLOB_PRIVATE_KEY) {
			tpmKey_.setEncData(attrib);

		} else {
			throw new TcTspException(TcTssErrors.TSS_E_INVALID_ATTRIB_SUBFLAG);
		}
	}


	/*************************************************************************************************
	 * This method returns key blobs as defined for {@link TcTssConstants#TSS_TSPATTRIB_KEY_BLOB}.
	 * This method is an alternative to using {@link TcIAttributes#getAttribData(long, long)} with
	 * {@link TcTssConstants#TSS_TSPATTRIB_KEY_BLOB} as flag.
	 *
	 * @param subFlag Valid subFlags are:
	 *          <ul>
	 *          <li> {@link TcTssConstants#TSS_TSPATTRIB_KEYBLOB_BLOB}
	 *          <li> {@link TcTssConstants#TSS_TSPATTRIB_KEYBLOB_PRIVATE_KEY}
	 *          <li> {@link TcTssConstants#TSS_TSPATTRIB_KEYBLOB_PUBLIC_KEY}
	 *          </ul>
	 *
	 * @return The requested key blob (or null if the key blob is not available).
	 */
	public synchronized TcBlobData getAttribKeyBlob(long subFlag) throws TcTssException
	{
		if (tcsKeyHandle_ == TcTpmConstants.TPM_KEYHND_SRK) {
			throw new TcTspException(TcTssErrors.TSS_E_BAD_PARAMETER,
					"The SRK must be obtained from the TPM using the getPubKey method.");
		}

		TcBlobData retVal = null;
		if (subFlag == TcTssConstants.TSS_TSPATTRIB_KEYBLOB_BLOB) {
			retVal = tpmKey_.getEncoded();

		} else if (subFlag == TcTssConstants.TSS_TSPATTRIB_KEYBLOB_PUBLIC_KEY) {
			TcTpmPubkey pubKey = new TcTpmPubkey();
			pubKey.setAlgorithmParms(tpmKey_.getAlgorithmParms());
			pubKey.setPubKey(tpmKey_.getPubKey());
			retVal = pubKey.getEncoded();

		} else if (subFlag == TcTssConstants.TSS_TSPATTRIB_KEYBLOB_PRIVATE_KEY) {
			retVal = (TcBlobData) tpmKey_.getEncData().clone();

		} else {
			throw new TcTspException(TcTssErrors.TSS_E_INVALID_ATTRIB_SUBFLAG);
		}

		return retVal;
	}


	/*************************************************************************************************
	 * This method returns key version information as defined for
	 * {@link TcTssConstants#TSS_TSPATTRIB_KEY_INFO}. The data returned by this method is a
	 * TcTpmVersion struct, not a TcTssVersion struct. To get the key version field as a TcTssVersion
	 * us {@link TcRsaKey#getAttribKeyInfoVersion()}. This method is an alternative to using
	 * {@link TcIAttributes#getAttribData(long, long)} with
	 * {@link TcTssConstants#TSS_TSPATTRIB_KEY_INFO} as flag.
	 *
	 * @param subFlag Valid subFlags are:
	 *          <ul>
	 *          <li> {@link TcTssConstants#TSS_TSPATTRIB_KEYINFO_VERSION}
	 *          </ul>
	 *
	 * @return The requested information as specified by subFlag.
	 */
	public synchronized TcBlobData getAttribKeyInfo(long subFlag) throws TcTssException
	{
		if (!(tpmKey_ instanceof TcTpmKey)) {
			throw new TcTspException(TcTssErrors.TSS_E_INVALID_OBJECT_TYPE,
					"The key structure is not a version 1.1 structure and therefore has no version field.");
		}
		if (subFlag != TcTssConstants.TSS_TSPATTRIB_KEYINFO_VERSION) {
			throw new TcTspException(TcTssErrors.TSS_E_INVALID_ATTRIB_SUBFLAG);
		}

		TcTpmVersion tpmVer = ((TcTpmKey) tpmKey_).getVer();
		return tpmVer.getEncoded();
	}


	/*************************************************************************************************
	 * This method returns PCR_LONG information as defined for
	 * {@link TcTssConstants#TSS_TSPATTRIB_KEY_PCR_LONG}. This method is an alternative to using
	 * {@link TcIAttributes#getAttribData(long, long)} with
	 * {@link TcTssConstants#TSS_TSPATTRIB_KEY_PCR_LONG} as flag.
	 *
	 * @param subFlag Valid subFlags are:
	 *          <ul>
	 *          <li> {@link TcTssConstants#TSS_TSPATTRIB_KEYPCRLONG_CREATION_SELECTION}
	 *          <li> {@link TcTssConstants#TSS_TSPATTRIB_KEYPCRLONG_RELEASE_SELECTION}
	 *          <li> {@link TcTssConstants#TSS_TSPATTRIB_KEYPCRLONG_DIGEST_ATCREATION}
	 *          <li> {@link TcTssConstants#TSS_TSPATTRIB_KEYPCRLONG_DIGEST_ATRELEASE}
	 *          </ul>
	 *
	 * @return The requested information as specified by subFlag.
	 */
	public synchronized TcBlobData getAttribKeyPcrLong(long subFlag) throws TcTssException
	{
		if (tpmKey_.getPcrInfo() == null) {
			throw new TcTspException(TcTssErrors.TSS_E_NO_PCRS_SET, "No PCRs set for this key.");
		}
		if (!(tpmKey_ instanceof TcTpmKey12)) {
			throw new TcTspException(TcTssErrors.TSS_E_INVALID_OBJECT_TYPE,
					"The key structure is not a version 1.1 structure and therefore has no pcrInfoLong information.");
		}
		TcTpmPcrInfoLong pcrInfo = new TcTpmPcrInfoLong(tpmKey_.getPcrInfo());

		TcBlobData retVal = null;
		if (subFlag == TcTssConstants.TSS_TSPATTRIB_KEYPCRLONG_CREATION_SELECTION) {
			retVal = pcrInfo.getCreationPCRSelection().getEncoded();

		} else if (subFlag == TcTssConstants.TSS_TSPATTRIB_KEYPCRLONG_RELEASE_SELECTION) {
			retVal = pcrInfo.getReleasePcrSelection().getEncoded();

		} else if (subFlag == TcTssConstants.TSS_TSPATTRIB_KEYPCRLONG_DIGEST_ATCREATION) {
			retVal = pcrInfo.getDigestAtCreation().getEncoded();

		} else if (subFlag == TcTssConstants.TSS_TSPATTRIB_KEYPCRLONG_DIGEST_ATRELEASE) {
			retVal = pcrInfo.getDigestAtRelease().getEncoded();

		} else {
			throw new TcTspException(TcTssErrors.TSS_E_INVALID_ATTRIB_SUBFLAG);
		}

		return retVal;
	}


	/*************************************************************************************************
	 * This method returns PCR_INFO information as defined for
	 * {@link TcTssConstants#TSS_TSPATTRIB_KEY_PCR}. This method is an alternative to using
	 * {@link TcIAttributes#getAttribData(long, long)} with
	 * {@link TcTssConstants#TSS_TSPATTRIB_KEY_PCR} as flag.
	 *
	 * @param subFlag Valid subFlags are:
	 *          <ul>
	 *          <li> {@link TcTssConstants#TSS_TSPATTRIB_KEYPCR_DIGEST_ATCREATION}
	 *          <li> {@link TcTssConstants#TSS_TSPATTRIB_KEYPCR_DIGEST_ATRELEASE}
	 *          <li> {@link TcTssConstants#TSS_TSPATTRIB_KEYPCR_SELECTION}
	 *          </ul>
	 *
	 * @return The requested information as specified by subFlag.
	 */
	public synchronized TcBlobData getAttribKeyPcr(long subFlag) throws TcTssException
	{
		if (tpmKey_.getPcrInfo() == null) {
			throw new TcTspException(TcTssErrors.TSS_E_NO_PCRS_SET, "No PCRs set for this key.");
		}

		TcTpmPcrInfo pcrInfo = new TcTpmPcrInfo(tpmKey_.getPcrInfo());

		TcBlobData retVal = null;
		if (subFlag == TcTssConstants.TSS_TSPATTRIB_KEYPCR_DIGEST_ATCREATION) {
			retVal = pcrInfo.getDigestAtCreation().getEncoded();

		} else if (subFlag == TcTssConstants.TSS_TSPATTRIB_KEYPCR_DIGEST_ATRELEASE) {
			retVal = pcrInfo.getDigestAtRelease().getEncoded();

		} else if (subFlag == TcTssConstants.TSS_TSPATTRIB_KEYPCR_SELECTION) {
			retVal = pcrInfo.getPcrSelection().getEncoded();

		} else {
			throw new TcTspException(TcTssErrors.TSS_E_INVALID_ATTRIB_SUBFLAG);
		}

		return retVal;
	}

	/*************************************************************************************************
	 * This method sets CMK information as defined for
	 * {@link TcTssConstants#TSS_TSPATTRIB_KEY_CMKINFO}. This method is an alternative to using
	 * {@link TcIAttributes#setAttribData(long, long, TcBlobData)} with
	 * {@link TcTssConstants#TSS_TSPATTRIB_KEY_CMKINFO} as flag.
	 *
	 * @param subFlag Valid subFlags are:
	 *          <ul>
	 *          <li> {@link TcTssConstants#TSS_TSPATTRIB_KEYINFO_CMK_MA_APPROVAL}
	 *          <li> {@link TcTssConstants#TSS_TSPATTRIB_KEYINFO_CMK_MA_DIGEST}
	 *          </ul>
	 *
	 * @param attrib The attribute value corresponding to the given subFlag.
	 */
	public synchronized void setAttribCmkInfo(long subFlag, TcBlobData attrib)
		throws TcTssException
	{
		if (subFlag == TcTssConstants.TSS_TSPATTRIB_KEYINFO_CMK_MA_APPROVAL) {
			if(msaApproval_ == null)
				msaApproval_ = new TcTpmDigest();
			msaApproval_.setDigest(attrib);
		} else if (subFlag == TcTssConstants.TSS_TSPATTRIB_KEYINFO_CMK_MA_DIGEST) {
			if(msaDigest_ == null)
				msaDigest_ = new TcTpmDigest();
			msaDigest_.setDigest(attrib);
		} else {
			throw new TcTspException(TcTssErrors.TSS_E_INVALID_ATTRIB_SUBFLAG);
		}
	}


	/*************************************************************************************************
	 * This method returns CMK information as defined for
	 * {@link TcTssConstants#TSS_TSPATTRIB_KEY_CMKINFO}. This method is an alternative to using
	 * {@link TcIAttributes#getAttribData(long, long)} with
	 * {@link TcTssConstants#TSS_TSPATTRIB_KEY_CMKINFO} as subFlag.
	 *
	 * @param subFlag Valid subFlags are:
	 *          <ul>
	 *          <li> {@link TcTssConstants#TSS_TSPATTRIB_KEYINFO_CMK_MA_APPROVAL}
	 *          <li> {@link TcTssConstants#TSS_TSPATTRIB_KEYINFO_CMK_MA_DIGEST}
	 *          </ul>
	 *
	 * @return The requested information as specified by subFlag.
	 */
	public synchronized TcBlobData getAttribCmkInfo(long subFlag) throws TcTssException
	{
		if (subFlag == TcTssConstants.TSS_TSPATTRIB_KEYINFO_CMK_MA_APPROVAL) {
			if(msaApproval_ == null)
				throw new TcTspException(TcTssErrors.TSS_E_FAIL, "msa approval not set.");
			return msaApproval_.getDigest();
		} else if (subFlag == TcTssConstants.TSS_TSPATTRIB_KEYINFO_CMK_MA_DIGEST) {
			if(msaDigest_ == null)
				throw new TcTspException(TcTssErrors.TSS_E_FAIL, "msa digest not set.");
			return msaDigest_.getDigest();
		} else {
			throw new TcTspException(TcTssErrors.TSS_E_INVALID_ATTRIB_SUBFLAG);
		}
	}

}
