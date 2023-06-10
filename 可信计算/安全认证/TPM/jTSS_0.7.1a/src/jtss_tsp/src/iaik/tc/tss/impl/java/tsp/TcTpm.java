/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.impl.java.tsp;


import iaik.tc.tss.api.constants.pcclient.TcPcclientConstants;
import iaik.tc.tss.api.constants.tcs.TcTcsErrors;
import iaik.tc.tss.api.constants.tpm.TcTpmConstants;
import iaik.tc.tss.api.constants.tpm.TcTpmErrors;
import iaik.tc.tss.api.constants.tpm.TcTpmOrdinals;
import iaik.tc.tss.api.constants.tsp.TcTssConstants;
import iaik.tc.tss.api.constants.tsp.TcTssErrors;
import iaik.tc.tss.api.exceptions.common.TcTssException;
import iaik.tc.tss.api.exceptions.tcs.TcTcsException;
import iaik.tc.tss.api.exceptions.tcs.TcTddlException;
import iaik.tc.tss.api.exceptions.tcs.TcTpmException;
import iaik.tc.tss.api.exceptions.tsp.TcTspException;
import iaik.tc.tss.api.structs.common.TcBasicTypeDecoder;
import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.tss.api.structs.pcclient.TcTcgFullCert;
import iaik.tc.tss.api.structs.pcclient.TcTcgPcclientStoredCert;
import iaik.tc.tss.api.structs.tcs.TcTcsAuth;
import iaik.tc.tss.api.structs.tpm.TcITpmKey;
import iaik.tc.tss.api.structs.tpm.TcITpmKeyNew;
import iaik.tc.tss.api.structs.tpm.TcTpmCapVersionInfo;
import iaik.tc.tss.api.structs.tpm.TcTpmChosenIdHash;
import iaik.tc.tss.api.structs.tpm.TcTpmCompositeHash;
import iaik.tc.tss.api.structs.tpm.TcTpmCounterValue;
import iaik.tc.tss.api.structs.tpm.TcTpmCurrentTicks;
import iaik.tc.tss.api.structs.tpm.TcTpmDigest;
import iaik.tc.tss.api.structs.tpm.TcTpmEncauth;
import iaik.tc.tss.api.structs.tpm.TcTpmIdentityProof;
import iaik.tc.tss.api.structs.tpm.TcTpmIdentityReq;
import iaik.tc.tss.api.structs.tpm.TcTpmKeyParms;
import iaik.tc.tss.api.structs.tpm.TcTpmMigrationkeyAuth;
import iaik.tc.tss.api.structs.tpm.TcTpmNonce;
import iaik.tc.tss.api.structs.tpm.TcTpmPcrComposite;
import iaik.tc.tss.api.structs.tpm.TcTpmPcrInfoShort;
import iaik.tc.tss.api.structs.tpm.TcTpmPcrSelection;
import iaik.tc.tss.api.structs.tpm.TcTpmPubkey;
import iaik.tc.tss.api.structs.tpm.TcTpmQuoteInfo;
import iaik.tc.tss.api.structs.tpm.TcTpmQuoteInfo2;
import iaik.tc.tss.api.structs.tpm.TcTpmSecret;
import iaik.tc.tss.api.structs.tpm.TcTpmSelectSize;
import iaik.tc.tss.api.structs.tpm.TcTpmStructVer;
import iaik.tc.tss.api.structs.tpm.TcTpmSymCaAttestation;
import iaik.tc.tss.api.structs.tpm.TcTpmSymmetricKey;
import iaik.tc.tss.api.structs.tpm.TcTpmSymmetricKeyParms;
import iaik.tc.tss.api.structs.tpm.TcTpmVersion;
import iaik.tc.tss.api.structs.tpm.TcTpmNonce;
import iaik.tc.tss.api.structs.tsp.TcTssPcrEvent;
import iaik.tc.tss.api.structs.tsp.TcTssValidation;
import iaik.tc.tss.api.structs.tsp.TcTssVersion;
import iaik.tc.tss.api.tspi.TcIAuthObject;
import iaik.tc.tss.api.tspi.TcIContext;
import iaik.tc.tss.api.tspi.TcIHash;
import iaik.tc.tss.api.tspi.TcIMigData;
import iaik.tc.tss.api.tspi.TcINvRam;
import iaik.tc.tss.api.tspi.TcIPcrComposite;
import iaik.tc.tss.api.tspi.TcIPolicy;
import iaik.tc.tss.api.tspi.TcIRsaKey;
import iaik.tc.tss.api.tspi.TcITpm;
import iaik.tc.tss.impl.csp.TcCrypto;
import iaik.tc.tss.impl.java.tsp.internal.TcTspInternal;
import iaik.tc.tss.impl.java.tsp.internal.TcTspProperties;
import iaik.tc.utils.logging.Log;
import iaik.tc.utils.misc.CheckPrecondition;
import iaik.tc.utils.misc.Utils;
import iaik.tc.utils.properties.Properties;

import java.util.HashMap;
import java.util.SortedMap;
import java.util.TreeMap;


/**
 * TPM class implemented using singleton pattern.
 */
public class TcTpm extends TcAuthObject implements TcITpm {

	/**
	 * This HashMap is used to hold the endorsement, platform, platform conformance and conformance
	 * credentials. The keys are the credential IDs ({@link TcTssConstants#TSS_TPMATTRIB_EKCERT},
	 * {@link TcTssConstants#TSS_TPMATTRIB_PLATFORM_CC},
	 * {@link TcTssConstants#TSS_TPMATTRIB_PLATFORMCERT} and
	 * {@link TcTssConstants#TSS_TPMATTRIB_TPM_CC}).
	 */
	protected HashMap credentials_ = new HashMap();

	/**
	 * cache of supported ordinals (mapping: <Long>Ordinal -> <Boolean>isSupported)
	 */
	protected static SortedMap supportedOrdinals_ = new TreeMap();

	/**
	 * The operator policy currently assigned to the object.
	 */
	private TcPolicy operatorPolicy_ = null;

	/**
	 * if set to true: use TrouSerS compatible encoding @ collateIdentityRequest and activateIdentity
	 */
	protected boolean trousersCompatible_ = false;

	public boolean isTrousersCompatible() {
		return trousersCompatible_;
	}

	public void setTrousersCompatible(boolean trousersCompatible) {
		trousersCompatible_ = trousersCompatible;
	}

	/*************************************************************************************************
	 * Hidden constructor (singleton pattern).
	 */
	protected TcTpm(TcIContext context) throws TcTssException
	{
		super(context);

		try {
			Properties prop = TcTspProperties.getInstance();
			String comp = prop.getProperty("Compatibility", "trousersAikEncoding");
			if(comp.equals("true"))
				trousersCompatible_ = true;
			else
				trousersCompatible_ = false;
		}
		catch (Exception e) {
			// set to default value
			trousersCompatible_ = false;
		}
	}


	/*
	 * (non-Javadoc)
	 *
	 * @see iaik.tss.api.tspi.TcITpm#activateIdentity(iaik.tss.api.tspi.TcIRsaKey,
	 *      iaik.tss.api.structs.TcBlobData, iaik.tss.api.structs.TcBlobData)
	 */

    /**
     *  returns the Constants for the given AlgorithmID
     * @throws TcTspException
     */
	protected HashMap getAlgorithmConstants(long algId) throws TcTspException
	{
		HashMap retval = new HashMap();

		switch ((int) algId) {
		case (int) TcTssConstants.TSS_ALG_AES128:
		case (int) TcTpmConstants.TPM_ALG_AES128:
			// note: same as TSS_ALG_AES
			retval.put("blockSize", 128);
			retval.put("keyLength", 128);
			retval.put("ivSize", 128);
			retval.put("algName", "AES");
			break;

		case (int) TcTssConstants.TSS_ALG_AES192:
		case (int) TcTpmConstants.TPM_ALG_AES192:
			retval.put("blockSize", 128);
			retval.put("keyLength", 192);
			retval.put("ivSize", 128);
			retval.put("algName", "AES");
			break;

		case (int) TcTssConstants.TSS_ALG_AES256:
		case (int) TcTpmConstants.TPM_ALG_AES256:
			retval.put("blockSize", 128);
			retval.put("keyLength", 256);
			retval.put("ivSize", 128);
			retval.put("algName", "AES");
			break;

		case (int) TcTssConstants.TSS_ALG_3DES:
		case (int) TcTpmConstants.TPM_ALG_3DES:
			retval.put("blockSize", 64);
			retval.put("keyLength", 192);
			retval.put("ivSize", 64);
			retval.put("algName", "DESede");
			break;

		default:
			throw new TcTspException(TcTssErrors.TSS_E_BAD_PARAMETER,
					"The selected symmetric encryption algorithm is not supported.");
		}

		return retval;
	}




	/*************************************************************************************************
	 * For general information about this method refer to
	 * {@link TcITpm#activateIdentity(TcIRsaKey, TcBlobData, TcBlobData)}.
	 *
	 * Implementation note: The following symmetric algorithms are supported:
	 * <ul>
	 * <li> {@link TcTssConstants#TSS_ALG_AES} (same as AES_128)
	 * <li> {@link TcTssConstants#TSS_ALG_AES128}
	 * <li> {@link TcTssConstants#TSS_ALG_AES192}
	 * <li> {@link TcTssConstants#TSS_ALG_AES256}
	 * <li> {@link TcTssConstants#TSS_ALG_3DES}
	 * </ul>
	 */
	public TcBlobData activateIdentity(TcIRsaKey identityKey, TcBlobData asymCaContentsBlob,
			TcBlobData symCaAttestationBlob) throws TcTssException
	{
		checkContextOpenAndConnected();
		CheckPrecondition.notNullAndInstanceOf(identityKey, "identityKey", TcRsaKey.class);
		context_.checkAssociation(identityKey, "identityKey");
		checkKeyHandleNotNull(((TcRsaKey) identityKey).getTcsKeyHandle(), "identityKey");
		CheckPrecondition.notNull(asymCaContentsBlob, "asymCaContentsBlob");
		CheckPrecondition.notNull(symCaAttestationBlob, "symCaAttestationBlob");

		TcTpmSymCaAttestation symCaAttestation = new TcTpmSymCaAttestation(symCaAttestationBlob);
		TcTpmKeyParms caKeyParams = symCaAttestation.getAlgorithm();
		HashMap algConstants = getAlgorithmConstants(caKeyParams.getAlgorithmID());
		TcTpmSymmetricKeyParms caKeyParamsSym = null;
		if(trousersCompatible_) {
			Log.debug("activateIdentity: using TrouSerS compatible encoding");
			caKeyParamsSym = new TcTpmSymmetricKeyParms();
			int ivLength = (Integer)algConstants.get("ivSize") / 8;
			caKeyParamsSym.setIV(TcBlobData.newByteArray(symCaAttestation.getCredential().getRange(0, ivLength)));
			byte[] newCredential = symCaAttestation.getCredential().getRange(ivLength, (int)symCaAttestation.getCredSize() - ivLength);
			symCaAttestation.setCredential(TcBlobData.newByteArray(newCredential));
		}
		else {
			caKeyParamsSym = new TcTpmSymmetricKeyParms(caKeyParams.getParms());
		}

		long idKeyHandle = ((TcRsaKey) identityKey).getTcsKeyHandle();
		TcTpmSecret idKeyAuth = new TcTpmSecret(((TcPolicy) identityKey.getUsagePolicyObject())
				.getSecret());
		TcTpmSecret ownerAuth = new TcTpmSecret(((TcPolicy) getUsagePolicyObject()).getSecret());

		// start OIAP sessions
		TcTcsAuth inAuth1 = TcTspInternal.TspOIAP_Internal(context_);
		TcTcsAuth inAuth2 = TcTspInternal.TspOIAP_Internal(context_);

		// call to TPM
		Object[] tpmOutData = TcTspInternal.TspActivateIdentity_Internal(context_, idKeyHandle,
				asymCaContentsBlob, inAuth1, inAuth2, idKeyAuth, ownerAuth);

		// The TPM returns the decrypted symmetric key
		TcTpmSymmetricKey symKey = (TcTpmSymmetricKey) tpmOutData[2];
		String javaAlgo = (String)algConstants.get("algName");

		TcBlobData decryptedCredential = TcCrypto.decryptSymmetricCbcPkcs5Pad(javaAlgo, symKey
				.getData(), caKeyParamsSym.getIV(), symCaAttestation.getCredential());

		return decryptedCredential;
	}


	/*
	 * (non-Javadoc)
	 *
	 * @see iaik.tss.api.tspi.TcITpm#authorizeMigrationTicket(iaik.tss.api.tspi.TcIRsaKey, long)
	 */
	public TcTpmMigrationkeyAuth authorizeMigrationTicket(TcIRsaKey migrationKey, long migrationScheme)
		throws TcTssException
	{
		checkContextOpenAndConnected();
		CheckPrecondition.notNullAndInstanceOf(migrationKey, "migrationKey", TcRsaKey.class);
		context_.checkAssociation(migrationKey, "migrationKey");

		TcTpmSecret ownerAuth = new TcTpmSecret(usagePolicy_.getSecret());
		TcTcsAuth inAuth = TcTspInternal.TspOIAP_Internal(context_);

		int tpmMigrationScheme = (int)TcConstantsMappings.msMap.getTpmForTssVal(migrationScheme);
		TcTpmPubkey migrationPubKey = new TcTpmPubkey(migrationKey.getPubKey());

		Object[] retVal = TcTspInternal.TspAuthorizeMigrationKey_Internal(context_, tpmMigrationScheme,
					migrationPubKey, inAuth, ownerAuth);

		return (TcTpmMigrationkeyAuth)retVal[1];
	}


	/*
	 * (non-Javadoc)
	 *
	 * @see iaik.tss.api.tspi.TcITpm#certifySelfTest(iaik.tss.api.tspi.TcIRsaKey,
	 *      iaik.tss.api.structs.tsp.TcTssValidation)
	 */
	public TcTssValidation certifySelfTest(TcIRsaKey key, TcTssValidation validation)
		throws TcTssException
	{
		throw new TcTspException(TcTssErrors.TSS_E_NOTIMPL,
				"The CertifySelfTest command was deleted in TPM specification 1.2 and therefore is not supported.");
	}


	/*
	 * (non-Javadoc)
	 *
	 * @see iaik.tss.api.tspi.TcITpm#checkMaintenancePubKey(iaik.tss.api.tspi.TcIRsaKey,
	 *      iaik.tss.api.structs.tsp.TcTssValidation)
	 */
	public TcTssValidation checkMaintenancePubKey(TcIRsaKey key, TcTssValidation validationData)
		throws TcTssException
	{
		checkContextOpenAndConnected();
		CheckPrecondition.notNullAndInstanceOf(key, "key", TcRsaKey.class);
		context_.checkAssociation(key, "key");
		// validation can be null

		throw new TcTspException(TcTssErrors.TSS_E_NOTIMPL);
	}


	/*
	 * (non-Javadoc)
	 *
	 * @see iaik.tss.api.tspi.TcITpm#clearOwner(boolean)
	 */
	public void clearOwner(boolean forcedClear) throws TcTssException
	{
		checkContextOpenAndConnected();

		if (forcedClear) {
			TcTspInternal.TspForceClear_Internal(context_);
		} else {
			TcTpmSecret ownerAuth = new TcTpmSecret(usagePolicy_.getSecret());
			TcTcsAuth inAuth = TcTspInternal.TspOIAP_Internal(context_);
			TcTspInternal.TspOwnerClear_Internal(context_, inAuth, ownerAuth);
		}
	}


	/*************************************************************************************************
	 * Implementation specific notes: This implementation only supports AES for symmetric encryption.
	 * Valid algId parameters are:
	 * <ul>
	 * <li> {@link TcTssConstants#TSS_ALG_AES} (same as AES_128)
	 * <li> {@link TcTssConstants#TSS_ALG_AES128}
	 * <li> {@link TcTssConstants#TSS_ALG_AES192}
	 * <li> {@link TcTssConstants#TSS_ALG_AES256}
	 * <li> {@link TcTssConstants#TSS_ALG_3DES}
	 * </ul>
	 *
	 * Note: If using the jTSS Core Services, the EK credentials of IFX 1.1 and 1.2 TPMs will be
	 * automatically included in the collageIdentityReq blob. For IFX 1.1 chips the credential is read
	 * from the TPM using vendor specific mechanisms. For IFX 1.2 TPMs the credential is read from the
	 * NV storage.
	 *
	 * The mode of operation is fixed to CBC and the padding is set to PKCS5 ({@link TcTssConstants#TSS_ES_SYM_CBC_PKCS5PAD}).
	 *
	 * For general information about this method refer to
	 * {@link TcITpm#collateIdentityRequest(TcIRsaKey, TcIRsaKey, TcBlobData, TcIRsaKey, long)}.
	 */
	public TcBlobData collateIdentityRequest(TcIRsaKey srk, TcIRsaKey caPubKeyRsa,
			TcBlobData identityLabel, TcIRsaKey identityKey, long algId) throws TcTssException
	{
		checkContextOpenAndConnected();
		CheckPrecondition.notNullAndInstanceOf(srk, "srk", TcRsaKey.class);
		context_.checkAssociation(srk, "srk");
		CheckPrecondition.notNullAndInstanceOf(caPubKeyRsa, "caPubKey", TcRsaKey.class);
		context_.checkAssociation(caPubKeyRsa, "caPubKeyRsa");
		CheckPrecondition.notNull(identityLabel, "identityLabel");
		CheckPrecondition.notNullAndInstanceOf(identityKey, "identityKey", TcRsaKey.class);
		context_.checkAssociation(identityKey, "identityKey");

		// The following code operates on the internal TPM key structure of of identityKey.
		// Synchronization ensures that nobody else has access to the key internals at the same time
		// (all public access methods of TcRsaKey are synchronized).
		synchronized (identityKey) {

			// the identity key must be a "new" key; that is an empty key template
			TcITpmKey idKeyParams = ((TcRsaKey) identityKey).getInternalTpmKey();
			if (!(idKeyParams instanceof TcITpmKeyNew)) {
				throw new TcTspException(TcTssErrors.TSS_E_INTERNAL_ERROR,
						"identityKey must be a newly created (i.e. empty) RSA key object.");
			}

			// get public part of CA key
			TcBlobData caPubKeyBlob = ((TcRsaKey) caPubKeyRsa)
					.getAttribKeyBlob(TcTssConstants.TSS_TSPATTRIB_KEYBLOB_PUBLIC_KEY);
			TcTpmPubkey caPubKey = new TcTpmPubkey(caPubKeyBlob);

			// compute chosenId hash
			TcBlobData chosenIdHashData = (TcBlobData) identityLabel.clone();
			chosenIdHashData.append(caPubKeyBlob);
			TcTpmChosenIdHash chosenIdHash = new TcTpmChosenIdHash(chosenIdHashData.sha1());

			// get SRK secret
			TcTpmSecret srkAuth = new TcTpmSecret(((TcPolicy) srk.getUsagePolicyObject()).getSecret());

			// start OSAP session
			Object[] osapData = createOsapSession(TcTpmConstants.TPM_ET_OWNER, TcTpmConstants.TPM_KH_SRK,
					getUsagePolicyObject(), identityKey.getUsagePolicyObject());
			TcTcsAuth osapSession = (TcTcsAuth) osapData[0];
			TcTpmEncauth encIdentityAuth = (TcTpmEncauth) osapData[1];
			TcTpmSecret osapSecret = (TcTpmSecret) osapData[2];

			// start OIAP session
			TcTcsAuth oiapSession = TcTspInternal.TspOIAP_Internal(context_);

			// call to TPM
			Object[] tpmOutData = TcTspInternal.TspMakeIdentity_Internal(context_, encIdentityAuth,
					chosenIdHash, (TcITpmKeyNew) idKeyParams, oiapSession, osapSession, srkAuth, osapSecret);

			// decode output data
			TcITpmKey newIdKey = (TcITpmKey) tpmOutData[2];
			TcBlobData identityBinding = (TcBlobData) tpmOutData[3];
			TcTpmPubkey newIdKeyPub = new TcTpmPubkey();
			newIdKeyPub.setAlgorithmParms(newIdKey.getAlgorithmParms());
			newIdKeyPub.setPubKey(newIdKey.getPubKey());
			TcBlobData endorsementCredential = (TcBlobData) tpmOutData[4];
			TcBlobData platformCredential = (TcBlobData) tpmOutData[5];
			TcBlobData conformanceCredential = (TcBlobData) tpmOutData[6];

			// override credentials if they have been set by user
			synchronized (credentials_) {
				Long key = new Long(TcTssConstants.TSS_TPMATTRIB_EKCERT);
				if (credentials_.containsKey(key)) {
					endorsementCredential = (TcBlobData) credentials_.get(key);
				}
				key = new Long(TcTssConstants.TSS_TPMATTRIB_PLATFORMCERT);
				if (credentials_.containsKey(key)) {
					platformCredential = (TcBlobData) credentials_.get(key);
				}
				key = new Long(TcTssConstants.TSS_TPMATTRIB_PLATFORM_CC);
				if (credentials_.containsKey(key)) {
					conformanceCredential = (TcBlobData) credentials_.get(key);
				}
			}
			// Note: The TSS spec defines 4 certificates but only 3 are used in the collateIdentityRequest

			if (endorsementCredential == null) {
				/*
				 * This is the last chance to obtain EK Cert. At this point neither
				 * automatic EK Cert extraction succeeded nor the user provided one.
				 *
				 * If we have a IFX 1.2 TPM that requires owner auth, we try this.
				 */
				Log.info("no EK Cert obtained yet, trying to read from NV Ram with owner authorization");
				endorsementCredential = getEndorsementCredentialAlternative();
			}

			if(endorsementCredential == null){
				Log.err("failed to acquire EK Cert");
			}

			// set newly created TPM key data
			((TcRsaKey) identityKey).setInternalTpmKey(newIdKey);

			// put together the identity proof structure (i.e. data to be symmetrically encrypted)
			TcTpmIdentityProof identityProof = new TcTpmIdentityProof();
			// Note on StructVer: We use the version reported by the TPMCAP_VERSION for the StructVer.
			// For 1.1b chips this is the actual TPM version, for 1.2 TPMs this is fixed to 1.1.0.0.
			// Having the TPM version set in this struct (instead of a fixed 1.1.0.0) allows the PrivacyCa
			// to determine which version string to use when verifying request data received from the
			// client.
			identityProof.setVersion(new TcTpmStructVer(getCapability(TcTssConstants.TSS_TPMCAP_VERSION,
					null)));
			identityProof.setIdentityBinding(identityBinding);
			identityProof.setIdentityKey(newIdKeyPub);
			identityProof.setLabelArea(identityLabel);
			identityProof.setEndorsementCredential(endorsementCredential);
			identityProof.setPlatformCredential(platformCredential);
			identityProof.setConformanceCredential(conformanceCredential);

			HashMap algConstants = getAlgorithmConstants(algId);
			long symBlockSize = (Integer)algConstants.get("blockSize");
			long symKeyLength = (Integer)algConstants.get("keyLength");
			long symIvSize = (Integer)algConstants.get("ivSize");
			String symAlg = (String)algConstants.get("algName");

			// setup parameters for symmetric encryption
			TcTpmSymmetricKeyParms symKeyParams = new TcTpmSymmetricKeyParms();
			symKeyParams.setBlockSize(symBlockSize);
			symKeyParams.setKeyLength(symKeyLength);
			symKeyParams.setIV(TcCrypto.getRandom((int) symIvSize / 8));

			TcTpmKeyParms keyParms = new TcTpmKeyParms();
			keyParms.setAlgorithmID(algId);
			keyParms.setEncScheme((int) TcTssConstants.TSS_ES_SYM_CBC_PKCS5PAD);
			keyParms.setSigScheme((int) TcTssConstants.TSS_SS_NONE);
			keyParms.setParms(symKeyParams.getEncoded());

			// create the symmetric key
			TcTpmSymmetricKey symKey = new TcTpmSymmetricKey();
			symKey.setAlgId(algId);
			if (symAlg.equals("DESede")) {
				symKey.setData(TcCrypto.create3DESkey());
			} else {
				symKey.setData(TcCrypto.createAESkey((int) symKeyLength));
			}
			symKey.setEncScheme(keyParms.getEncScheme());

			// symmetrically encrypt the identityProof data blob
			TcBlobData symBlob = TcCrypto.encryptSymmetricCbcPkcs5Pad(symAlg, symKey.getData(),
					symKeyParams.getIV(), identityProof.getEncoded());

			// asymmetrically encrypt the symmetric key
			int encScheme = (int) ((TcRsaKey) caPubKeyRsa)
					.getAttribKeyInfoUINT32(TcTssConstants.TSS_TSPATTRIB_KEYINFO_ENCSCHEME);

			TcBlobData asymBlob = null;
			switch (encScheme) {
				case (int) TcTssConstants.TSS_ES_RSAESPKCSV15:
					asymBlob = TcCrypto.pubEncryptRsaEcbPkcs1Padding(caPubKey, symKey.getEncoded());
					break;
				case (int) TcTssConstants.TSS_ES_RSAESOAEP_SHA1_MGF1:
					asymBlob = TcCrypto.pubEncryptRsaOaepSha1Mgf1(caPubKey, symKey.getEncoded());
					break;
				default:
					throw new TcTspException(TcTssErrors.TSS_E_BAD_PARAMETER,
							"Only TSS_ES_RSAESPKCSV15, TSS_ES_RSAESPKCSV15 are supported for the "
									+ "asymmetric encryption scheme (when encrypting data with the public CA key).");
			}

			// put together the identity request blob to be sent to the privacy CA
			TcTpmIdentityReq identityReq = new TcTpmIdentityReq();
			identityReq.setAsymAlgorithm(caPubKey.getAlgorithmParms());
			identityReq.setAsymBlob(asymBlob);

			if(trousersCompatible_) {
				TcTpmKeyParms tmpKeyParms = new TcTpmKeyParms();
				tmpKeyParms.setAlgorithmID(algId);
				tmpKeyParms.setEncScheme((int) TcTssConstants.TSS_ES_NONE);
				tmpKeyParms.setSigScheme((int) TcTssConstants.TSS_SS_NONE);
				identityReq.setSymAlgorithm(tmpKeyParms);

				symBlob.prepend(symKeyParams.getIV());

				Log.debug("collateIdentityRequest: using TrouSerS compatible encoding");
			}
			else {
				identityReq.setSymAlgorithm(keyParms);
			}

			identityReq.setSymBlob(symBlob);

			return identityReq.getEncoded();

		} // end of synchronized (identityKey)
	}


	/*
	 * (non-Javadoc)
	 *
	 * @see iaik.tss.api.tspi.TcITpm#createEndorsementKey(iaik.tss.api.tspi.TcIRsaKey,
	 *      iaik.tss.api.structs.tsp.TcTssValidation)
	 */
	public TcTssValidation createEndorsementKey(TcIRsaKey key, TcTssValidation validationData)
		throws TcTssException, TcTcsException, TcTpmException, TcTddlException
	{
		checkContextOpenAndConnected();
		CheckPrecondition.notNullAndInstanceOf(key, "key", TcRsaKey.class);
		context_.checkAssociation(key, "key");
		// validation data can be null (i.e. validation is done by TSP).
		CheckPrecondition.optionalInstanceOf(validationData, "validationData", TcTssValidation.class);

		// set up the validation data to be returned to the caller
		TcTssValidation outValidation = new TcTssValidation();
		outValidation.setVersionInfo(TcTssVersion.TPM_V1_2);
		if (validationData != null) {
			outValidation.setExternalData(validationData.getExternalData());
		} else {
			outValidation.setExternalData(TcCrypto.createTcgNonce().getEncoded());
		}

		// The following code operates on the internal TPM key structure of of key.
		// Synchronization ensures that nobody else has access to the key internals at the same time
		// (all public access methods of TcRsaKey are synchronized).
		synchronized (key) {
			// check the provided key for suitability
			TcITpmKey tpmKey = ((TcRsaKey) key).getInternalTpmKey();
			if (tpmKey == null || tpmKey.getAlgorithmParms() == null) {
				throw new TcTspException(TcTssErrors.TSS_E_BAD_PARAMETER,
						"The provided public EK object was not set up correctly.");
			}
			TcTpmKeyParms keyParams = tpmKey.getAlgorithmParms();

			// call to TPM
			Object[] tpmOutData = TcTspInternal.TspCreateEndorsementKeyPair_Internal(context_, keyParams,
					new TcTpmNonce(outValidation.getExternalData()));

			TcTpmPubkey tpmPubEk = (TcTpmPubkey) tpmOutData[0];
			TcTpmDigest checksum = (TcTpmDigest) tpmOutData[1];

			// fill outValidation
			TcBlobData plainData = (TcBlobData) tpmPubEk.getEncoded().clone();
			plainData.append(outValidation.getExternalData());
			outValidation.setData(plainData);
			outValidation.setValidationData(checksum.getEncoded());

			// if no incoming validation data was provided, validation is done by the TSP
			if (validationData == null) {
				validateChecksum(outValidation, checksum);
			}

			// set public EK
			tpmKey.setPubKey(tpmPubEk.getPubKey());
			tpmKey.setAlgorithmParms(tpmPubEk.getAlgorithmParms());
			((TcRsaKey) key).setInternalTpmKey(tpmKey);

			return outValidation;
		} // end of synchronized(key)
	}

	/*
	 * (non-Javadoc)
	 *
	 * @see iaik.tss.api.tspi.TcITpm#createRevocableEndorsementKey(iaik.tss.api.tspi.TcIRsaKey,
	 *      iaik.tss.api.structs.tsp.TcTssValidation,
	 *      iaik.tss.api.structs.tpm.TcTpmNonce)
	 */
	public Object[] createRevocableEndorsementKey(TcIRsaKey key, TcTssValidation validationData, TcTpmNonce ekResetData)
		throws TcTssException, TcTcsException, TcTpmException, TcTddlException
	{
		checkContextOpenAndConnected();
		CheckPrecondition.notNullAndInstanceOf(key, "key", TcRsaKey.class);
		context_.checkAssociation(key, "key");
		// validation data can be null (i.e. validation is done by TSP).
		CheckPrecondition.optionalInstanceOf(validationData, "validationData", TcTssValidation.class);
		CheckPrecondition.optionalInstanceOf(ekResetData, "ekResetData", TcTpmNonce.class);

		// check if TPM should create reset data
		boolean generateReset = true;
		if (ekResetData != null) {
		    generateReset = false;
		}

		// set up the validation data to be returned to the caller
		TcTssValidation outValidation = new TcTssValidation();
		outValidation.setVersionInfo(TcTssVersion.TPM_V1_2);
		if (validationData != null) {
			outValidation.setExternalData(validationData.getExternalData());
		} else {
			outValidation.setExternalData(TcCrypto.createTcgNonce().getEncoded());
		}

		// The following code operates on the internal TPM key structure of of key.
		// Synchronization ensures that nobody else has access to the key internals at the same time
		// (all public access methods of TcRsaKey are synchronized).
		synchronized (key) {
			// check the provided key for suitability
			TcITpmKey tpmKey = ((TcRsaKey) key).getInternalTpmKey();
			if (tpmKey == null || tpmKey.getAlgorithmParms() == null) {
				throw new TcTspException(TcTssErrors.TSS_E_BAD_PARAMETER,
						"The provided public EK object was not set up correctly.");
			}
			TcTpmKeyParms keyParams = tpmKey.getAlgorithmParms();

			// call to TPM
			Object[] tpmOutData = TcTspInternal.TspCreateRevocableEK_Internal(context_, keyParams,
					new TcTpmNonce(outValidation.getExternalData()), generateReset, ekResetData);

			TcTpmPubkey tpmPubEk = (TcTpmPubkey) tpmOutData[0];
			TcTpmDigest checksum = (TcTpmDigest) tpmOutData[1];
			TcTpmNonce  rstData  = (TcTpmNonce)  tpmOutData[2];

			// fill outValidation
			TcBlobData plainData = (TcBlobData) tpmPubEk.getEncoded().clone();
			plainData.append(outValidation.getExternalData());
			outValidation.setData(plainData);
			outValidation.setValidationData(checksum.getEncoded());

			// if no incoming validation data was provided, validation is done by the TSP
			if (validationData == null) {
				validateChecksum(outValidation, checksum);
			}

			// set public EK
			tpmKey.setPubKey(tpmPubEk.getPubKey());
			tpmKey.setAlgorithmParms(tpmPubEk.getAlgorithmParms());
			((TcRsaKey) key).setInternalTpmKey(tpmKey);

			return new Object[] { outValidation, rstData };
		} // end of synchronized(key)
	}


	/*
	 * (non-Javadoc)
	 *
	 * @see iaik.tss.api.tspi.TcITpm#revokeEndorsementKey(iaik.tss.api.structs.tpm.TcTpmNonce)
	 */
	public void revokeEndorsementKey(TcTpmNonce ekResetData)
		throws TcTssException, TcTcsException, TcTpmException, TcTddlException
	{
		checkContextOpenAndConnected();
		CheckPrecondition.notNullAndInstanceOf(ekResetData, "ekResetData", TcTpmNonce.class);

		// call to TPM
		TcTspInternal.TspRevokeEndorsementKeyPair_Internal(context_, ekResetData);
	}


	/*
	 * (non-Javadoc)
	 *
	 * @see iaik.tss.api.tspi.TcITpm#dirRead(long)
	 */
	public TcBlobData dirRead(long dirIndex) throws TcTssException
	{
		checkContextOpenAndConnected();

		TcTpmDigest retVal = TcTspInternal.TspDirRead_Internal(context_, dirIndex);
		return retVal.getEncoded();
	}


	/*
	 * (non-Javadoc)
	 *
	 * @see iaik.tss.api.tspi.TcITpm#dirWrite(long, iaik.tss.api.structs.TcBlobData)
	 */
	public void dirWrite(long dirIndex, TcBlobData dirData) throws TcTssException
	{
		checkContextOpenAndConnected();

		TcTpmDigest newContents = new TcTpmDigest(dirData);
		TcTpmSecret ownerAuth = ((TcPolicy) getUsagePolicyObject()).getTpmSecret();
		TcTcsAuth inAuth1 = TcTspInternal.TspOIAP_Internal(context_);

		TcTspInternal.TspDirWriteAuth_Internal(context_, dirIndex, newContents, inAuth1, ownerAuth);
	}


	/*
	 * (non-Javadoc)
	 *
	 * @see iaik.tss.api.tspi.TcITpm#getCapability(long, iaik.tss.api.structs.TcBlobData)
	 */
	public TcBlobData getCapability(long capArea, TcBlobData subCap) throws TcTssException
	{
		checkContextOpenAndConnected();
		// subCap can be null

		long tpmCapArea = 0;
		TcBlobData tpmSubCap = null;

		if (capArea == TcTssConstants.TSS_TPMCAP_ORD) {
			tpmCapArea = TcTpmConstants.TPM_CAP_ORD;
			CheckPrecondition.notNull(subCap, "subCap");
			tpmSubCap = subCap;

		} else if (capArea == TcTssConstants.TSS_TPMCAP_ALG) {
			tpmCapArea = TcTpmConstants.TPM_CAP_ALG;
			CheckPrecondition.notNull(subCap, "subCap");
			tpmSubCap = (TcBlobData) TcConstantsMappings.algMap.getTpmForTssVal(subCap);
			if (tpmSubCap == null) {
				throw new TcTspException(TcTssErrors.TSS_E_BAD_PARAMETER, "Unknown subFlag.");
			}

		} else if (capArea == TcTssConstants.TSS_TPMCAP_FLAG) {
			tpmCapArea = TcTpmConstants.TPM_CAP_FLAG;
			// subCap ignored

			// returns a bitmap of both permanent and volatile flags
			//
			// TPM_CAP_FLAG_VOLATILE will be used in a second run and appended to the
			// first result
			tpmSubCap = TcBlobData.newUINT32(TcTpmConstants.TPM_CAP_FLAG_PERMANENT);

		} else if (capArea == TcTssConstants.TSS_TPMCAP_PROPERTY) {
			tpmCapArea = TcTpmConstants.TPM_CAP_PROPERTY;
			CheckPrecondition.notNull(subCap, "subCap");
			tpmSubCap = (TcBlobData) TcConstantsMappings.propMap.getTpmForTssVal(subCap);
			if (tpmSubCap == null) {
				throw new TcTspException(TcTssErrors.TSS_E_BAD_PARAMETER, "Unknown subFlag.");
			}

		} else if (capArea == TcTssConstants.TSS_TPMCAP_VERSION) {
			tpmCapArea = TcTpmConstants.TPM_CAP_VERSION;
			// subCap ignored

		} else if (capArea == TcTssConstants.TSS_TPMCAP_VERSION_VAL) {
			tpmCapArea = TcTpmConstants.TPM_CAP_VERSION_VAL;
			// subCap ignored

		} else if (capArea == TcTssConstants.TSS_TPMCAP_NV_LIST) {
			tpmCapArea = TcTpmConstants.TPM_CAP_NV_LIST;
			// subCap ignored

		} else if (capArea == TcTssConstants.TSS_TPMCAP_NV_INDEX) {
			tpmCapArea = TcTpmConstants.TPM_CAP_NV_INDEX;
			CheckPrecondition.notNull(subCap, "subCap");
			tpmSubCap = subCap;

		} else if (capArea == TcTssConstants.TSS_TPMCAP_MFR) {
			tpmCapArea = TcTpmConstants.TPM_CAP_MFR;
			// subCap ignored

		} else if (capArea == TcTssConstants.TSS_TPMCAP_SYM_MODE) {
			tpmCapArea = TcTpmConstants.TPM_CAP_SYM_MODE;
			CheckPrecondition.notNull(subCap, "subCap");
			tpmSubCap = subCap;
			// Note: TSS 1.2 EA spec says "one of TPM_SYM_MODE_*".
			// Because these are TPM values, not translation is done
			// (unclear what TSS_ES_SYM_* war for as they are not in spec)

		} else if (capArea == TcTssConstants.TSS_TPMCAP_HANDLE) {
			tpmCapArea = TcTpmConstants.TPM_CAP_HANDLE;
			CheckPrecondition.notNull(subCap, "subCap");
			tpmSubCap = (TcBlobData) TcConstantsMappings.rtMap.getTpmForTssVal(subCap);
			if (tpmSubCap == null) {
				throw new TcTspException(TcTssErrors.TSS_E_BAD_PARAMETER, "Unknown subFlag.");
			}

		} else if (capArea == TcTssConstants.TSS_TPMCAP_TRANS_ES) {
			tpmCapArea = TcTpmConstants.TPM_CAP_TRANS_ES;
			CheckPrecondition.notNull(subCap, "subCap");
			tpmSubCap = (TcBlobData) TcConstantsMappings.esMap.getTpmForTssVal(subCap);
			if (tpmSubCap == null) {
				throw new TcTspException(TcTssErrors.TSS_E_BAD_PARAMETER, "Unknown subFlag.");
			}

		} else if (capArea == TcTssConstants.TSS_TPMCAP_AUTH_ENCRYPT) {
			tpmCapArea = TcTpmConstants.TPM_CAP_AUTH_ENCRYPT;
			CheckPrecondition.notNull(subCap, "subCap");
			tpmSubCap = (TcBlobData) TcConstantsMappings.algMap.getTpmForTssVal(subCap);
			if (tpmSubCap == null) {
				throw new TcTspException(TcTssErrors.TSS_E_BAD_PARAMETER, "Unknown subFlag.");
			}

		} else if (capArea == TcTssConstants.TSS_TPMCAP_SELECT_SIZE) {
			tpmCapArea = TcTpmConstants.TPM_CAP_SELECT_SIZE;
			CheckPrecondition.notNull(subCap, "subCap");
			tpmSubCap = subCap;

		} else {
			throw new TcTspException(TcTssErrors.TSS_E_BAD_PARAMETER, "Unknown capArea.");
		}

		TcBlobData retVal = null;
		try {
			retVal = TcTspInternal.TspGetCapability_Internal(context_, tpmCapArea, tpmSubCap);

			if (capArea == TcTssConstants.TSS_TPMCAP_FLAG) {
				// append volatile flags to already obtained permanent flags
				retVal.append(TcTspInternal.TspGetCapability_Internal(context_,
						tpmCapArea, TcBlobData.newUINT32(TcTpmConstants.TPM_CAP_FLAG_VOLATILE)));
			}
		} catch (TcTpmException e) {
			if (e.getErrCode() == TcTpmErrors.TPM_E_AUTHFAIL) {
				// TODO: retry using auth
				Log.debug("TODO: retry using auth");
				throw e;
			} else {
				throw e;
			}
		}

		return retVal;
	}


	/*
	 * (non-Javadoc)
	 *
	 * @see iaik.tss.api.tspi.TcITpm#getCapabilityBoolean(long, iaik.tss.api.structs.TcBlobData)
	 */
	public boolean getCapabilityBoolean(long capArea, TcBlobData subCap) throws TcTssException
	{
		TcBlobData retVal = getCapability(capArea, subCap);
		return (new TcBasicTypeDecoder(retVal)).decodeBoolean();
	}


	/*
	 * (non-Javadoc)
	 *
	 * @see iaik.tss.api.tspi.TcITpm#getCapabilityUINT32(long, iaik.tss.api.structs.TcBlobData)
	 */
	public long getCapabilityUINT32(long capArea, TcBlobData subCap) throws TcTssException
	{
		TcBlobData retVal = getCapability(capArea, subCap);
		return (new TcBasicTypeDecoder(retVal)).decodeUINT32();
	}


	/*
	 * (non-Javadoc)
	 *
	 * @see iaik.tss.api.tspi.TcITpm#getCapabilityVersion(long, iaik.tss.api.structs.TcBlobData)
	 */
	public TcTssVersion getCapabilityVersion(long capArea, TcBlobData subCap) throws TcTssException
	{
		TcBlobData retVal = getCapability(capArea, subCap);
		TcTpmVersion tpmVersion = null;
		if (capArea == TcTssConstants.TSS_TPMCAP_VERSION) {
			tpmVersion = new TcTpmVersion(retVal);
		} else if (capArea == TcTssConstants.TSS_TPMCAP_VERSION_VAL) {
			tpmVersion = (new TcTpmCapVersionInfo(retVal)).getVersion();
		} else {
			throw new TcTspException(TcTssErrors.TSS_E_BAD_PARAMETER, "Bad subcap given.");
		}

		TcTssVersion tssVersion = new TcTssVersion();
		tssVersion.setMajor(tpmVersion.getMajor());
		tssVersion.setMinor(tpmVersion.getMinor());
		tssVersion.setRevMajor(tpmVersion.getRevMajor());
		tssVersion.setRevMinor(tpmVersion.getRevMinor());

		return tssVersion;
	}


	/*************************************************************************************************
	 * This internal method returns the TPM version as reported by using
	 * {@link TcTssConstants#TSS_TPMCAP_VERSION} .
	 */
	protected TcTssVersion getTpmVersion() throws TcTssException
	{
		checkContextOpenAndConnected();
		TcTssVersion tpmVersion = getCapabilityVersion(TcTssConstants.TSS_TPMCAP_VERSION, null);
		return tpmVersion;
	}


	/*************************************************************************************************
	 * This internal method returns the TPM version as reported by using
	 * {@link TcTssConstants#TSS_TPMCAP_VERSION_VAL} for 1.2 chips and
	 * {@link TcTssConstants#TSS_TPMCAP_VERSION} for 1.1 chips.
	 */
	public TcTssVersion getRealTpmVersion() throws TcTssException
	{
		checkContextOpenAndConnected();
		TcTssVersion tpmVersion = null;
		try {
			// first try 1.2 style
			tpmVersion = getCapabilityVersion(TcTssConstants.TSS_TPMCAP_VERSION_VAL, null);
		} catch (TcTpmException e) {
			// alternatively try 1.1 style
			tpmVersion = getCapabilityVersion(TcTssConstants.TSS_TPMCAP_VERSION, null);
		}

		return tpmVersion;
	}


	/*************************************************************************************************
	 * This method returns true if for the given TPM structure version the requested select size is
	 * supported. Otherwise false is returned. This check is required to determine the selection size
	 * that can be set in e.g TPM_PCR_INFO structures.
	 */
	protected boolean isSelectSizeSupported(TcTssVersion ver, int reqSize) throws TcTssException
	{
		CheckPrecondition.notNull(ver, "ver");
		CheckPrecondition.gtZero(reqSize, "size");

		TcTpmSelectSize selectSize = new TcTpmSelectSize();
		selectSize.setMajor(ver.getMajor());
		selectSize.setMinor(ver.getMinor());
		selectSize.setReqSize(reqSize);

		return getCapabilityBoolean(TcTssConstants.TSS_TPMCAP_SELECT_SIZE, selectSize.getEncoded());
	}


	/*
	 * (non-Javadoc)
	 *
	 * @see iaik.tss.api.tspi.TcITpm#getCapabilityVersionSigned()
	 */
	public void getCapabilitySigned() throws TcTssException
	{
		throw new TcTspException(TcTssErrors.TSS_E_NOTIMPL,
				"This function has been removed from the TSS specification due to security problems.");
	}


	/*
	 * (non-Javadoc)
	 *
	 * @see iaik.tss.api.tspi.TcITpm#getEvent(long, long)
	 */
	public TcTssPcrEvent getEvent(long pcrIndex, long eventNumber) throws TcTssException
	{
		checkContextOpenAndConnected();

		return TcTspInternal.TspGetPcrEvent(context_, pcrIndex, eventNumber);
	}


	/*
	 * (non-Javadoc)
	 *
	 * @see iaik.tss.api.tspi.TcITpm#getEventCount(long)
	 */
	public int getEventCount(long pcrIndex) throws TcTssException
	{
		checkContextOpenAndConnected();

		return (int) TcTspInternal.TspGetPcrEventCount(context_, pcrIndex);
	}


	/*
	 * (non-Javadoc)
	 *
	 * @see iaik.tss.api.tspi.TcITpm#getEventLog()
	 */
	public TcTssPcrEvent[] getEventLog() throws TcTssException
	{
		checkContextOpenAndConnected();

		return TcTspInternal.TspGetPcrEventLog(context_);
	}


	/*
	 * (non-Javadoc)
	 *
	 * @see iaik.tss.api.tspi.TcITpm#getEvents(long, long, long)
	 */
	public TcTssPcrEvent[] getEvents(long pcrIndex, long startNumber, long eventNumber)
		throws TcTssException
	{
		checkContextOpenAndConnected();

		return TcTspInternal.TspGetPcrEventsByPcr(context_, pcrIndex, startNumber, eventNumber);
	}


	/*
	 * (non-Javadoc)
	 *
	 * @see iaik.tss.api.tspi.TcITpm#getPubEndorsementKey(boolean)
	 */
	public Object[] getPubEndorsementKey(boolean ownerAuthorized, TcTssValidation validationData)
		throws TcTssException
	{
		checkContextOpenAndConnected();
		// validation can be null (i.e. TSP does validation)

		TcTpmPubkey tpmPubEk = null;
		TcTssValidation outValidation = new TcTssValidation();

		if (!ownerAuthorized) {
			outValidation.setVersionInfo(getRealTpmVersion());
			if (validationData != null) {
				outValidation.setExternalData(validationData.getExternalData());
			} else {
				outValidation.setExternalData(TcCrypto.createTcgNonce().getEncoded());
			}

			Object[] tpmOutData = TcTspInternal.TspReadPubek_Internal(context_, new TcTpmNonce(
					outValidation.getExternalData()));
			tpmPubEk = (TcTpmPubkey) tpmOutData[0];
			TcTpmDigest checksum = (TcTpmDigest) tpmOutData[1];

			TcBlobData plainData = (TcBlobData) tpmPubEk.getEncoded().clone();
			plainData.append(outValidation.getExternalData());
			outValidation.setData(plainData);
			outValidation.setValidationData(checksum.getEncoded());

			if (validationData == null) {
				validateChecksum(outValidation, checksum);
			}

		} else {
			TcTcsAuth inAuth1 = TcTspInternal.TspOIAP_Internal(context_);
			TcTpmSecret ownerAuth = new TcTpmSecret(usagePolicy_.getSecret());

			if (isOrdinalSupported(TcTpmOrdinals.TPM_ORD_OwnerReadInternalPub)) {
				// TPM 1.2
				Object[] tpmOutData = TcTspInternal.TspOwnerReadInternalPub_Internal(context_,
						TcTpmConstants.TPM_KH_EK, inAuth1, ownerAuth);
				tpmPubEk = (TcTpmPubkey) tpmOutData[1];

			} else {
				// TPM 1.1
				Object[] tpmOutData = TcTspInternal
						.TspOwnerReadPubek_Internal(context_, inAuth1, ownerAuth);
				tpmPubEk = (TcTpmPubkey) tpmOutData[1];
			}

		}

		TcIRsaKey pubEk = context_.createRsaKeyObject(0);
		pubEk.setAttribData(TcTssConstants.TSS_TSPATTRIB_KEY_BLOB,
				TcTssConstants.TSS_TSPATTRIB_KEYBLOB_PUBLIC_KEY, tpmPubEk.getEncoded());

		return new Object[] { pubEk, outValidation };
	}


	/*
	 * (non-Javadoc)
	 *
	 * @see iaik.tc.tss.api.tspi.TcITpm#getPubEndorsementKeyOwner()
	 */
	public TcIRsaKey getPubEndorsementKeyOwner() throws TcTssException
	{
		return (TcIRsaKey) (getPubEndorsementKey(true, null)[0]);
	}


	/*
	 * (non-Javadoc)
	 *
	 * @see iaik.tss.api.tspi.TcITpm#getRandom(long)
	 */
	public TcBlobData getRandom(long length) throws TcTssException
	{
		checkContextOpenAndConnected();

		// Note: The 4096 length limit is specified in the TSS 1.2 spec not the TPM spec.
		CheckPrecondition.ltOrEq(length, "length", 4096);
		return TcTspInternal.TspGetRandom_Internal(context_, length);
	}


	/*
	 * (non-Javadoc)
	 *
	 * @see iaik.tss.api.tspi.TcITpm#getStatus(long)
	 */
	public boolean getStatus(long statusFlag) throws TcTssException
	{
		checkContextOpenAndConnected();

		TcTpmSecret ownerAuth = ((TcPolicy) getUsagePolicyObject()).getTpmSecret();
		TcTcsAuth inAuth1 = TcTspInternal.TspOIAP_Internal(context_);
		Object[] tpmOutData = TcTspInternal
				.TspGetCapabilityOwner_Internal(context_, inAuth1, ownerAuth);

		long permanentFlags = ((Long) tpmOutData[2]).longValue();
		long volatileFlags = ((Long) tpmOutData[3]).longValue();

		boolean retVal = false;

		switch ((int) statusFlag) {
			case (int) TcTssConstants.TSS_TPMSTATUS_DISABLEOWNERCLEAR:
				retVal = Utils.longToBoolean(permanentFlags & TcTpmConstants.TPM_PF_DISABLEOWNERCLEAR);
				break;

			case (int) TcTssConstants.TSS_TPMSTATUS_DISABLEFORCECLEAR:
				retVal = Utils.longToBoolean(volatileFlags & TcTpmConstants.TPM_SF_DISABLEFORCECLEAR); // STCLEAR
				break;

			// case (int) TcTssConstants.TSS_TPMSTATUS_OWNERSETDISABLE:
			// break;

			// case (int) TcTssConstants.TSS_TPMSTATUS_PHYSICALDISABLE:
			// break;

			// case (int) TcTssConstants.TSS_TPMSTATUS_PHYSICALSETDEACTIVATED:
			// break;

			case (int) TcTssConstants.TSS_TPMSTATUS_SETTEMPDEACTIVATED:
				retVal = Utils.longToBoolean(volatileFlags & TcTpmConstants.TPM_SF_DEACTIVATED); // STCLEAR
				break;

			case (int) TcTssConstants.TSS_TPMSTATUS_SETOWNERINSTALL:
				retVal = Utils.longToBoolean(permanentFlags & TcTpmConstants.TPM_PF_OWNERSHIP);
				break;

			case (int) TcTssConstants.TSS_TPMSTATUS_DISABLEPUBEKREAD:
				retVal = Utils.longToBoolean(permanentFlags & TcTpmConstants.TPM_PF_READPUBEK);
				break;

			case (int) TcTssConstants.TSS_TPMSTATUS_DISABLED:
				retVal = Utils.longToBoolean(permanentFlags & TcTpmConstants.TPM_PF_DISABLE);
				break;

			case (int) TcTssConstants.TSS_TPMSTATUS_DEACTIVATED:
				retVal = Utils.longToBoolean(permanentFlags & TcTpmConstants.TPM_PF_DEACTIVATED);
				break;

			case (int) TcTssConstants.TSS_TPMSTATUS_ALLOWMAINTENANCE:
				retVal = Utils.longToBoolean(permanentFlags & TcTpmConstants.TPM_PF_ALLOWMAINTENANCE);
				break;

			case (int) TcTssConstants.TSS_TPMSTATUS_MAINTENANCEUSED:
				retVal = Utils.longToBoolean(permanentFlags & TcTpmConstants.TPM_PF_MAINTENANCEDONE);
				break;

			case (int) TcTssConstants.TSS_TPMSTATUS_PHYSPRES_LIFETIMELOCK:
				retVal = Utils.longToBoolean(permanentFlags
						& TcTpmConstants.TPM_PF_PHYSICALPRESENCELIFETIMELOCK);
				break;

			case (int) TcTssConstants.TSS_TPMSTATUS_PHYSPRES_HWENABLE:
				retVal = Utils.longToBoolean(permanentFlags
						& TcTpmConstants.TPM_PF_PHYSICALPRESENCEHWENABLE);
				break;

			case (int) TcTssConstants.TSS_TPMSTATUS_PHYSPRES_CMDENABLE:
				retVal = Utils.longToBoolean(permanentFlags
						& TcTpmConstants.TPM_PF_PHYSICALPRESENCECMDENABLE);
				break;

			case (int) TcTssConstants.TSS_TPMSTATUS_CEKP_USED:
				retVal = Utils.longToBoolean(permanentFlags & TcTpmConstants.TPM_PF_CEKPUSED);
				break;

			case (int) TcTssConstants.TSS_TPMSTATUS_PHYSPRESENCE:
				retVal = Utils.longToBoolean(volatileFlags & TcTpmConstants.TPM_SF_PHYSICALPRESENCE); // STCLEAR
				break;

			case (int) TcTssConstants.TSS_TPMSTATUS_PHYSPRES_LOCK:
				retVal = Utils.longToBoolean(volatileFlags & TcTpmConstants.TPM_SF_PHYSICALPRESENCELOCK); // STCLEAR
				break;

			case (int) TcTssConstants.TSS_TPMSTATUS_POSTINITIALISE:
				retVal = Utils.longToBoolean(volatileFlags & TcTpmConstants.TPM_AF_POSTINITIALIZE); // STANY
				break;

			case (int) TcTssConstants.TSS_TPMSTATUS_TPMPOST:
				retVal = Utils.longToBoolean(permanentFlags & TcTpmConstants.TPM_PF_TPMPOST);
				break;

			case (int) TcTssConstants.TSS_TPMSTATUS_TPMPOSTLOCK:
				retVal = Utils.longToBoolean(permanentFlags & TcTpmConstants.TPM_PF_TPMPOSTLOCK);
				break;

			case (int) TcTssConstants.TSS_TPMSTATUS_DISABLEPUBSRKREAD:
				retVal = Utils.longToBoolean(permanentFlags & TcTpmConstants.TPM_PF_READSRKPUB);
				break;

			case (int) TcTssConstants.TSS_TPMSTATUS_OPERATOR_INSTALLED:
				break;

			case (int) TcTssConstants.TSS_TPMSTATUS_FIPS:
				retVal = Utils.longToBoolean(permanentFlags & TcTpmConstants.TPM_PF_FIPS);
				break;

			case (int) TcTssConstants.TSS_TPMSTATUS_ENABLE_REVOKEEK:
				retVal = Utils.longToBoolean(permanentFlags & TcTpmConstants.TPM_PF_ENABLEREVOKEEK);
				break;

			case (int) TcTssConstants.TSS_TPMSTATUS_NV_LOCK:
				retVal = Utils.longToBoolean(permanentFlags & TcTpmConstants.TPM_PF_NV_LOCKED);
				break;

			// note: missing define in spec
			// case (int) TcTssConstants.TSS_TPMSTATUS_TPM_ESTABLISHED:
			// retVal = Utils.longToBoolean(permanentFlags & TcTpmConstants.TPM_PF_TPMESTABLISHED);
			// break;

			default:
				throw new TcTspException(TcTssErrors.TSS_E_BAD_PARAMETER,
						"Unknown/unsupported status flag.");
		}

		return retVal;
	}


	/*
	 * (non-Javadoc)
	 *
	 * @see iaik.tss.api.tspi.TcITpm#getTestResult()
	 */
	public TcBlobData getTestResult() throws TcTssException
	{
		checkContextOpenAndConnected();

		return TcTspInternal.TspGetTestResult_Internal(context_);
	}


	/*
	 * (non-Javadoc)
	 *
	 * @see iaik.tss.api.tspi.TcITpm#killMaintenanceFeature()
	 */
	public void killMaintenanceFeature() throws TcTssException
	{
		checkContextOpenAndConnected();

		throw new TcTspException(TcTssErrors.TSS_E_NOTIMPL);
	}


	/*
	 * (non-Javadoc)
	 *
	 * @see iaik.tss.api.tspi.TcITpm#loadMaintenancePubKey(iaik.tss.api.tspi.TcIRsaKey,
	 *      iaik.tss.api.structs.tsp.TcTssValidation)
	 */
	public TcTssValidation loadMaintenancePubKey(TcIRsaKey key, TcTssValidation validationData)
		throws TcTssException
	{
		checkContextOpenAndConnected();
		CheckPrecondition.notNullAndInstanceOf(key, "key", TcRsaKey.class);
		context_.checkAssociation(key, "key");
		// validationData can be null

		throw new TcTspException(TcTssErrors.TSS_E_NOTIMPL);
	}


	/*
	 * (non-Javadoc)
	 *
	 * @see iaik.tss.api.tspi.TcITpm#pcrExtend(long, iaik.tss.api.structs.TcBlobData,
	 *      iaik.tss.api.structs.tsp.TcTssPcrEvent)
	 */
	public TcBlobData pcrExtend(long pcrIndex, TcBlobData data, TcTssPcrEvent pcrEvent)
		throws TcTssException
	{
		checkContextOpenAndConnected();
		CheckPrecondition.notNull(data, "data");
		// pcrEvent can be null
		if (pcrEvent != null) {
			if (pcrEvent.getPcrIndex() != pcrIndex) {
				throw new TcTspException(TcTssErrors.TSS_E_BAD_PARAMETER,
						"pcrIndex and pcrEvent.pcrIndex do not match");
			}
		}

		if (data.getLength() != TcTpmConstants.TPM_SHA1_160_HASH_LEN) {
			throw new TcTspException(TcTssErrors.TSS_E_BAD_PARAMETER, "Data must be of length "
					+ TcTpmConstants.TPM_SHA1_160_HASH_LEN + "(SHA-1 hash length).");
		}

		TcTpmDigest digest = null;
		if (pcrEvent == null) {
			digest = new TcTpmDigest(data);

		} else {

			// Note: digest calculation according to TSS spec 1.2:
			// SHA-1(ulPcrIndex || pbPcrData || eventType || rgbEvent)
			TcBlobData digestInput = TcBlobData.newUINT32(pcrIndex);
			digestInput.append(data);
			digestInput.append(TcBlobData.newUINT32(pcrEvent.getEventType()));
			digestInput.append(pcrEvent.getEvent());
			digest = new TcTpmDigest(digestInput.sha1());
			pcrEvent.setPcrValue(digest.getEncoded());

			// Note: some 1.1 TSPs may calculate SHA-1(eventLenght || pcrIndex || rgbEvent || eventType)
			// here.
		}

		// synchronization note:
		// The extend and logPcrEvent operations are 2 distinct (and therefore non-atomic) operations in
		// the TCS. For multiple TSP instances it therefore can not be ensured that the extend and
		// logPcrEvent operations are done atomically. This might result in bogus event logs
		// (incorrectly ordered log entries).
		// As far as the TSP is concerned all that can be done is that it is ensured that all TPM
		// objects of the TSP are synchronized and therefore the Log entries produced by this TSP
		// instance are ordered properly
		synchronized (TcTpm.class) {
			TcTpmDigest newPcrContent = TcTspInternal.TspExtend_Internal(context_, pcrIndex, digest);
			if (pcrEvent != null) {
				TcTspInternal.TspLogPcrEvent(context_, pcrEvent);
			}
			return newPcrContent.getEncoded();
		}
	}


	/*
	 * (non-Javadoc)
	 *
	 * @see iaik.tss.api.tspi.TcITpm#pcrRead(long)
	 */
	public TcBlobData pcrRead(long pcrIndex) throws TcTssException
	{
		checkContextOpenAndConnected();
		TcTpmDigest digest = TcTspInternal.TspPcrRead_Internal(context_, pcrIndex);
		return digest.getEncoded();
	}


	/*
	 * (non-Javadoc)
	 *
	 * @see iaik.tss.api.tspi.TcITpm#pcrReset(iaik.tss.api.tspi.TcIPcrComposite)
	 */
	public void pcrReset(TcIPcrComposite pcrComposite) throws TcTssException
	{
		checkContextOpenAndConnected();
		CheckPrecondition.notNullAndInstanceOf(pcrComposite, "pcrComposite", TcPcrCompositeBase.class);
		context_.checkAssociation(pcrComposite, "pcrComposite");

		if (!(pcrComposite instanceof TcPcrCompositeInfo)
				&& !(pcrComposite instanceof TcPcrCompositeInfoShort)) {
			throw new TcTspException(TcTssErrors.TSS_E_BAD_PARAMETER,
					"Only TcPcrCompositeInfoShort and TcPcrCompositeInfo are valid parameter types.");
		}

		TcTspInternal.TspPcrReset_Internal(context_, ((TcPcrCompositeBase) pcrComposite)
				.getPcrSelection());
	}


	/*
	 * (non-Javadoc)
	 *
	 * @see iaik.tss.api.tspi.TcITpm#quote(iaik.tss.api.tspi.TcIRsaKey,
	 *      iaik.tss.api.tspi.TcIPcrComposite, iaik.tss.api.structs.tsp.TcTssValidation)
	 */
	public TcTssValidation quote(TcIRsaKey identKey, TcIPcrComposite pcrComposite,
			TcTssValidation validation) throws TcTssException
	{
		checkContextOpenAndConnected();
		CheckPrecondition.notNullAndInstanceOf(identKey, "identKey", TcRsaKey.class);
		context_.checkAssociation(identKey, "identKey");
		checkKeyHandleNotNull(((TcRsaKey) identKey).getTcsKeyHandle(), "identKey");
		CheckPrecondition.notNullAndInstanceOf(pcrComposite, "pcrComposite", TcPcrCompositeBase.class);
		context_.checkAssociation(pcrComposite, "pcrComposite");

		// validation can be null - TSP does validation
		if (!(pcrComposite instanceof TcPcrCompositeInfo)
				&& !(pcrComposite instanceof TcPcrCompositeInfoShort)) {
			throw new TcTspException(TcTssErrors.TSS_E_BAD_PARAMETER,
					"Only TcPcrCompositeInfoShort and TcPcrCompositeInfo are valid parameter types.");
		}

		TcTpmNonce externalData = null;
		if (validation != null && validation.getExternalData() != null) {
			externalData = new TcTpmNonce(validation.getExternalData());
		} else {
			externalData = TcCrypto.createTcgNonce();
		}

		TcTpmPcrSelection targetPcr = ((TcPcrCompositeBase) pcrComposite).getPcrSelection();
		TcTpmSecret authSecret = new TcTpmSecret(((TcPolicy) identKey.getUsagePolicyObject())
				.getSecret());
		long identKH = ((TcRsaKey) identKey).getTcsKeyHandle();

		// start auth session
		TcTcsAuth inAuth1 = TcTspInternal.TspOIAP_Internal(context_);

		// call to TPM
		Object[] tpmOutData = TcTspInternal.TspQuote_Internal(context_, identKH, externalData,
				targetPcr, inAuth1, authSecret);

		// decode TPM output
		TcTpmPcrComposite pcrComp = (TcTpmPcrComposite) tpmOutData[1];
		TcBlobData signedBlob = (TcBlobData) tpmOutData[2];

		// determine the version to be included in quote_info
		TcTssVersion realVer = getRealTpmVersion();
		TcTpmStructVer ver = new TcTpmStructVer();
		if (realVer.equalsMinMaj(TcTssVersion.TPM_V1_1)) {
			// for 1.1 TPMs take the real version as reported by the TPM
			ver.setMajor(realVer.getMajor());
			ver.setMinor(realVer.getMinor());
			ver.setRevMajor(realVer.getRevMajor());
			ver.setRevMinor(realVer.getRevMinor());
		} else {
			// for 1.2 TPMs the version is fixed to "1.1.0.0"
			ver.setMajor((short) 1);
			ver.setMinor((short) 1);
		}

		// fill quote_info structure
		TcTpmQuoteInfo qInfo = new TcTpmQuoteInfo();
		qInfo.setFixed("QUOT");
		qInfo.setVersion(ver);
		qInfo.setDigestValue(new TcTpmCompositeHash(pcrComp.getEncoded().sha1()));
		qInfo.setExternalData(externalData);

		// create TSS validation structure to be returned
		TcTssValidation retVal = new TcTssValidation();
		retVal.setExternalData(externalData.getEncoded());
		retVal.setData(qInfo.getEncoded());
		retVal.setValidationData(signedBlob);
		retVal.setVersionInfo(getTpmVersion());

		if (validation == null) {
			// TSP has to check the validationData
			TcIHash hash = context_.createHashObject(TcTssConstants.TSS_HASH_SHA1);
			hash.setHashValue(qInfo.getEncoded().sha1());
			hash.verifySignature(retVal.getValidationData(), identKey);
		}

		return retVal;
	}


	/*
	 * (non-Javadoc)
	 *
	 * @see iaik.tss.api.tspi.TcITpm#quote2(iaik.tss.api.tspi.TcIRsaKey, boolean,
	 *      iaik.tss.api.tspi.TcIPcrComposite, iaik.tss.api.structs.tsp.TcTssValidation)
	 */
	public Object[] quote2(TcIRsaKey identKey, boolean addVersion, TcIPcrComposite pcrComposite,
			TcTssValidation validation) throws TcTssException
	{
		checkContextOpenAndConnected();
		CheckPrecondition.notNullAndInstanceOf(identKey, "identKey", TcRsaKey.class);
		context_.checkAssociation(identKey, "identKey");
		CheckPrecondition.notNullAndInstanceOf(pcrComposite, "pcrComposite", TcPcrCompositeBase.class);
		context_.checkAssociation(pcrComposite, "pcrComposite");

		// validation can be null - TSP does validation
		if (!(pcrComposite instanceof TcPcrCompositeInfoShort)) {
			throw new TcTspException(TcTssErrors.TSS_E_BAD_PARAMETER,
					"Only TcPcrCompositeInfoShort is a valid parameter type.");
		}

		TcTpmNonce externalData = null;
		if (validation != null && validation.getExternalData() != null) {
			externalData = new TcTpmNonce(validation.getExternalData());
		} else {
			externalData = TcCrypto.createTcgNonce();
		}

		TcTpmPcrSelection targetPcr = ((TcPcrCompositeBase) pcrComposite).getPcrSelection();
		TcTpmSecret authSecret = new TcTpmSecret(((TcPolicy) identKey.getUsagePolicyObject())
				.getSecret());
		long identKH = ((TcRsaKey) identKey).getTcsKeyHandle();

		// start auth session
		TcTcsAuth inAuth1 = TcTspInternal.TspOIAP_Internal(context_);

		// call to TPM
		Object[] tpmOutData = TcTspInternal.TspQuote2_Internal(context_, identKH, externalData,
				targetPcr, addVersion, inAuth1, authSecret);

		// decode TPM output
		TcTpmPcrInfoShort pcrInfo = (TcTpmPcrInfoShort) tpmOutData[1];
		TcTpmCapVersionInfo versionInfo = (TcTpmCapVersionInfo) tpmOutData[2];
		TcBlobData signedBlob = (TcBlobData) tpmOutData[3];

		// the version to be included in quote_info (fixed to 1.1.0.0 for 1.2 TPMs)
		TcTpmStructVer ver = new TcTpmStructVer();
		ver.setMajor((short) 1);
		ver.setMinor((short) 1);

		// fill quote_info structure
		TcTpmQuoteInfo2 qInfo = new TcTpmQuoteInfo2();
		qInfo.setFixed("QUT2");
		qInfo.setInfoShort(pcrInfo);
		qInfo.setTag(TcTpmConstants.TPM_TAG_QUOTE_INFO2);
		qInfo.setExternalData(externalData);

		// create TSS validation structure to be returned
		TcTssValidation outValidation = new TcTssValidation();
		outValidation.setExternalData(externalData.getEncoded());
		outValidation.setData(qInfo.getEncoded());
		outValidation.setValidationData(signedBlob);
		outValidation.setVersionInfo(getTpmVersion());

		if (validation == null) {
			// TSP has to check the validationData
			TcBlobData expectedData = qInfo.getEncoded();
			if (addVersion) {
				expectedData.append(versionInfo.getEncoded());
			}

			TcIHash hash = context_.createHashObject(TcTssConstants.TSS_HASH_SHA1);
			hash.setHashValue(expectedData.sha1());
			hash.verifySignature(outValidation.getValidationData(), identKey);
		}

		return new Object[] { outValidation, versionInfo };
	}


	/*
	 * (non-Javadoc)
	 *
	 * @see iaik.tss.api.tspi.TcITpm#selfTestFull()
	 */
	public void selfTestFull() throws TcTssException
	{
		checkContextOpenAndConnected();

		TcTspInternal.TspSelfTestFull_Internal(context_);
	}


	/*
	 * (non-Javadoc)
	 *
	 * @see iaik.tss.api.tspi.TcITpm#setStatus(long, boolean)
	 */
	public void setStatus(long statusFlag, boolean tpmState) throws TcTssException
	{
		checkContextOpenAndConnected();

		TcTpmSecret ownerAuth = null;
		TcTcsAuth inAuth1 = null;

		switch ((int) statusFlag) {
			case (int) TcTssConstants.TSS_TPMSTATUS_DISABLEOWNERCLEAR:
				ownerAuth = ((TcPolicy) getUsagePolicyObject()).getTpmSecret();
				inAuth1 = TcTspInternal.TspOIAP_Internal(context_);
				TcTspInternal.TspDisableOwnerClear_Internal(context_, inAuth1, ownerAuth);
				break;

			case (int) TcTssConstants.TSS_TPMSTATUS_DISABLEFORCECLEAR:
				TcTspInternal.TspDisableForceClear_Internal(context_);
				break;

			case (int) TcTssConstants.TSS_TPMSTATUS_OWNERSETDISABLE:
				ownerAuth = ((TcPolicy) getUsagePolicyObject()).getTpmSecret();
				inAuth1 = TcTspInternal.TspOIAP_Internal(context_);
				TcTspInternal.TspOwnerSetDisable_Internal(context_, tpmState, inAuth1, ownerAuth);
				break;

			case (int) TcTssConstants.TSS_TPMSTATUS_PHYSICALDISABLE:
				TcTspInternal.TspPhysicalDisable_Internal(context_);
				break;

			case (int) TcTssConstants.TSS_TPMSTATUS_PHYSICALSETDEACTIVATED:
				TcTspInternal.TspPhysicalSetDeactivated_Internal(context_, tpmState);
				break;

			case (int) TcTssConstants.TSS_TPMSTATUS_SETTEMPDEACTIVATED:
				TcTspInternal.TspSetTempDeactivated_Internal(context_);
				ownerAuth = ((TcPolicy) getUsagePolicyObject()).getTpmSecret();
				inAuth1 = TcTspInternal.TspOIAP_Internal(context_);
				TcTspInternal.TspSetTempDeactivated2_Internal(context_, inAuth1, ownerAuth);
				break;

			case (int) TcTssConstants.TSS_TPMSTATUS_SETOWNERINSTALL:
				TcTspInternal.TspSetOwnerInstall_Internal(context_, tpmState);
				break;

			case (int) TcTssConstants.TSS_TPMSTATUS_DISABLEPUBEKREAD:
				ownerAuth = ((TcPolicy) getUsagePolicyObject()).getTpmSecret();
				inAuth1 = TcTspInternal.TspOIAP_Internal(context_);
				TcTspInternal.TspDisablePubekRead_Internal(context_, inAuth1, ownerAuth);
				break;

			// case (int) TcTssConstants.TSS_TPMSTATUS_DISABLEPUBSRKREAD:
			// break;

			// case (int) TcTssConstants.TSS_TPMSTATUS_ALLOWMAINTENANCE:
			// break;

			// case (int) TcTssConstants.TSS_TPMSTATUS_DISABLED:
			// break;

			// case (int) TcTssConstants.TSS_TPMSTATUS_DEACTIVATED:
			// break;

			case (int) TcTssConstants.TSS_TPMSTATUS_RESETLOCK:
				ownerAuth = ((TcPolicy) getUsagePolicyObject()).getTpmSecret();
				inAuth1 = TcTspInternal.TspOIAP_Internal(context_);
				TcTspInternal.TspResetLockValue_Internal(context_, inAuth1, ownerAuth);
				break;

			default:
				throw new TcTspException(TcTssErrors.TSS_E_BAD_PARAMETER,
						"Unknown/unsupported status flag.");
		}
	}


	/*
	 * (non-Javadoc)
	 *
	 * @see iaik.tss.api.tspi.TcITpm#stirRandom(iaik.tss.api.structs.TcBlobData)
	 */
	public void stirRandom(TcBlobData entropyData) throws TcTssException
	{
		checkContextOpenAndConnected();
		CheckPrecondition.notNull(entropyData, "entropyData");
		TcTspInternal.TspStirRandom_Internal(context_, entropyData);
	}


	/*
	 * (non-Javadoc)
	 *
	 * @see iaik.tss.api.tspi.TcITpm#takeOwnership(iaik.tss.api.tspi.TcIRsaKey,
	 *      iaik.tss.api.tspi.TcIRsaKey)
	 */
	public void takeOwnership(TcIRsaKey srk, TcIRsaKey pubEk) throws TcTssException
	{
		checkContextOpenAndConnected();
		CheckPrecondition.notNullAndInstanceOf(srk, "srk", TcRsaKey.class);
		context_.checkAssociation(srk, "srk");
		// note: pubEk can be null
		if (pubEk != null) {
			CheckPrecondition.isInstanceOf(pubEk, "pubEk", TcRsaKey.class);
			context_.checkAssociation(pubEk, "pubEk");
		}

		// The following code operates on the internal TPM key structure of of srk.
		// Synchronization ensures that nobody else has access to the key internals at the same time
		// (all public access methods of TcRcaKey are synchronized).
		synchronized (srk) {

			// check if the SRK object is valid
			TcITpmKey tpmSrk = ((TcRsaKey) srk).getInternalTpmKey();
			if (tpmSrk == null) {
				throw new TcTspException(TcTssErrors.TSS_E_BAD_PARAMETER,
						"The provided SRK object was not set up correctly.");
			}
			if (!(tpmSrk instanceof TcITpmKeyNew)) {
				throw new TcTspException(TcTssErrors.TSS_E_BAD_PARAMETER,
						"The provided SRK object must be a newly created key object not yet holding any key data.");
			}

			((TcPolicy) srk.getUsagePolicyObject()).getSecret();

			// get the public EK which is used to encrypt the owner and srk passwords
			TcTpmPubkey tpmPubEk = null;
			if (pubEk == null) {
				Object[] tpmOutData = TcTspInternal.TspReadPubek_Internal(context_, TcCrypto
						.createTcgNonce());
				tpmPubEk = (TcTpmPubkey) tpmOutData[0];
			} else {
				TcBlobData tpmPubEkBlob = ((TcRsaKey) pubEk)
						.getAttribKeyBlob(TcTssConstants.TSS_TSPATTRIB_KEYBLOB_BLOB);
				tpmPubEk = new TcTpmPubkey(tpmPubEkBlob);

				if (tpmPubEk.getAlgorithmParms() == null || tpmPubEk.getPubKey() == null) {
					throw new TcTspException(TcTssErrors.TSS_E_BAD_PARAMETER,
							"The provided public EK object was not set up correctly.");
				}
			}

			// encrypt the EK and SRK passwords
			TcBlobData encOwnerAuth = TcCrypto.pubEncryptRsaOaepSha1Mgf1(tpmPubEk, //
					usagePolicy_.getSecret());
			TcBlobData encSrkAuth = TcCrypto.pubEncryptRsaOaepSha1Mgf1(tpmPubEk, //
					((TcPolicy) srk.getUsagePolicyObject()).getSecret());

			// new OIAP session
			TcTcsAuth inAuth = TcTspInternal.TspOIAP_Internal(context_);

			// send call to TPM
			Object[] tpmOutData = TcTspInternal.TspTakeOwnership_Internal(context_,
					TcTpmConstants.TPM_PID_OWNER, encOwnerAuth, encSrkAuth, (TcITpmKeyNew) tpmSrk, inAuth,
					new TcTpmSecret(usagePolicy_.getSecret()));
			TcITpmKey tpmPubSrk = (TcITpmKey) tpmOutData[1];

			((TcRsaKey) srk).setInternalTpmKey(tpmPubSrk);

			//The TCS will take care of registering the SRK in system storage


		} // end of synchronized(srk)
	}

	/*
	 * (non-Javadoc)
	 *
	 * @see iaik.tss.impl.java.tsp.TcAuthObject#getPolicy(long)
	 */
	public synchronized TcIPolicy getPolicyObject(long policyType) throws TcTssException
	{
		if (policyType == TcTssConstants.TSS_POLICY_OPERATOR) {
			return operatorPolicy_;
		} else {
			return super.getPolicyObject(policyType);
		}
	}


	/*************************************************************************************************
	 * This method returns a policy object representing the operator policy currently assigned to the
	 * object. It is based on the getPolicy method of the TSS with TSS_POLICY_OPERATOR as parameter.
	 *
	 * Note: Policy objects are returned by reference. Keep that in mind when modifying a policy.
	 *
	 * @TSS_V1 73
	 *
	 * @TSS_1_2_EA 182
	 *
	 * @return Operator policy object.
	 *
	 * @throws TcTssException
	 */
	public synchronized TcIPolicy getOperatorPolicyObject() throws TcTssException
	{
		return getPolicyObject(TcTssConstants.TSS_POLICY_OPERATOR);
	}


	/*************************************************************************************************
	 * This method sets the operator policy object that is assigned to this key object. This
	 * functionality is used internally only and is therefore package protected.
	 *
	 * @param policy The policy object to be set.
	 */
	protected synchronized void setOperatorPolicy(TcIPolicy policy) throws TcTssException
	{
		checkContextOpen();
		CheckPrecondition.notNullAndInstanceOf(policy, "policy", TcPolicy.class);

		operatorPolicy_ = (TcPolicy) policy;
	}

	/*************************************************************************************************
	 * This method is a TSP level front end to the TCS getCredentials method. It calls down to the TCS
	 * to obtain the endorsement, platform and conformance certificates. Note that this TSP level
	 * method is not standardized by the TSS specification and therefore is not part {@link TcITpm}
	 * interface.
	 *
	 * Note that if a certificate is not available on the system, null is returned for this
	 * certificate.
	 *
	 * @return The return value array contains the following elements:
	 *         <ul>
	 *         <li> 0 ... endorsement credential (TcBlobData)
	 *         <li> 1 ... platform credential (TcBlobData)
	 *         <li> 2 ... conformance credential (TcBlobData)
	 *         </ul>
	 *
	 * @throws {@link TcTssException}
	 */
	public Object[] getCredentials() throws TcTssException
	{
		checkContextOpenAndConnected();

		Object[] credentials =  TcTspInternal.TspGetCredentials_Internal(context_);

		if (credentials[0] == null) {
			credentials[0] = getEndorsementCredentialAlternative();
		}

		return credentials;
	}


	/*************************************************************************************************
	 * This method is VENDOR SPECIFIC for Infineon 1.1 TPMs. It reads the EK certificate contained in
	 * such chips and returns it. If the TPM is not an IFX 1.1 TPM, a {@link TcTspException} will be
	 * thrown. This obviously is not available in all TSSs and therefore not standardized in the
	 * {@link TcITpm}.
	 *
	 * @return EK certificate blob read from the TPM chip.
	 *
	 * @throws {@link TcTssException}
	 */
	public TcBlobData readEkCertIfx11() throws TcTssException
	{
		checkContextOpenAndConnected();

		TcBlobData manufacturer = getCapability(TcTssConstants.TSS_TPMCAP_PROPERTY, //
				TcBlobData.newUINT32(TcTssConstants.TSS_TPMCAP_PROP_MANUFACTURER));

		if (!manufacturer.toStringASCII().equals("IFX\0")
				|| !getRealTpmVersion().equalsMinMaj(TcTssVersion.TPM_V1_1)) {
			throw new TcTspException(TcTssErrors.TSS_E_TPM_UNSUPPORTED_FEATURE,
					"This TPM is not an IFX 1.1 TPM and therefore the EK certificate "
							+ "can not be read using this function.");
		}

		return TcTspInternal.TspIfxReadTpm11Ek(context_);
	}


	/*************************************************************************************************
	 * This method allows developers to check if a given command ordinal is supported by the TPM the
	 * context is connected to. This is useful in cases where developers e.g. want to sued optional or
	 * commands that are not part of all versions of the TPM specification. The same functionality can
	 * be achieved using the getCapability functionality to check for supported ordinals. This method
	 * however, is simpler to use and additionally provides caching of the results. In cases where the
	 * same ordinal is queried more than once, this method avoids the calls to the TCS and TPM.
	 *
	 * @param ordinal The TPM command ordinal to be checked.
	 *
	 * @return Returns true if the ordinal is supported, false otherwise.
	 *
	 * @throws {@link TcTssException}
	 */
	public boolean isOrdinalSupported(long ordinal) throws TcTssException
	{
		Long ord = new Long(ordinal);

		synchronized (supportedOrdinals_) {
			if (supportedOrdinals_.containsKey(ord)) {
				Boolean isSppurted = (Boolean) supportedOrdinals_.get(ord);
				return isSppurted.booleanValue();
			} else {
				TcBlobData subCap = TcBlobData.newUINT32(ordinal);
				TcBlobData isSupportedBlob = getCapability(TcTssConstants.TSS_TPMCAP_ORD, subCap);
				boolean isSupported = new TcBasicTypeDecoder(isSupportedBlob).decodeBoolean();
				supportedOrdinals_.put(ord, new Boolean(isSupported));
				return isSupported;
			}
		}
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
		CheckPrecondition.notNullAndInstanceOf(newPolicy, "newPolicy", TcPolicy.class);
		if (parentObject != null) {
			throw new TcTspException(TcTssErrors.TSS_E_BAD_PARAMETER,
					"Parent must be null to change TPM authorization");
		}

		// // start OSAP session
		// Object[] osapData = createOsapSession(TcTpmConstants.TPM_ET_OWNER, 0,
		// getUsagePolicyObject(), newPolicy);
		// TcTcsAuth osapSession = (TcTcsAuth) osapData[0];
		// TcTpmEncauth newEncAuth = (TcTpmEncauth) osapData[1];
		// TcTpmSecret osapSecret = (TcTpmSecret) osapData[2];
		//
		// // call to TPM
		// TcTspInternal.TspChangeAuthOwner_Internal(context_, TcTpmConstants.TPM_PID_ADCP, newEncAuth,
		// TcTpmConstants.TPM_ET_OWNER, osapSession, osapSecret);

		genericChangeAuthOwner(TcTpmConstants.TPM_ET_OWNER, getUsagePolicyObject(), newPolicy);

		// assign TPM to new policy object
		newPolicy.assignToObject(this);
	}


	// ----------------------------------------------------------------------------------------------
	// TSS attribute getters and setter
	// ----------------------------------------------------------------------------------------------

	/*************************************************************************************************
	 * This method defines the mapping of attribute flags to getter methods.
	 */
	protected void initAttribGetters()
	{
		addGetterUINT32(TcTssConstants.TSS_TSPATTRIB_TPM_CALLBACK_COLLATEIDENTITY,
				"getAttribCallbackUINT32");
		addGetterUINT32(TcTssConstants.TSS_TSPATTRIB_TPM_CALLBACK_ACTIVATEIDENTITY,
				"getAttribCallbackUINT32");

		addGetterData(TcTssConstants.TSS_TSPATTRIB_TPM_CALLBACK_COLLATEIDENTITY, "getAttribCallback");
		addGetterData(TcTssConstants.TSS_TSPATTRIB_TPM_CALLBACK_ACTIVATEIDENTITY, "getAttribCallback");
	}


	/*************************************************************************************************
	 * This method defines the mapping of attribute flags to setter methods.
	 */
	protected void initAttribSetters()
	{
		addSetterUINT32(TcTssConstants.TSS_TSPATTRIB_TPM_CALLBACK_COLLATEIDENTITY,
				"setAttribCallbackUINT32");
		addSetterUINT32(TcTssConstants.TSS_TSPATTRIB_TPM_CALLBACK_ACTIVATEIDENTITY,
				"setAttribCallbackUINT32");

		addSetterData(TcTssConstants.TSS_TSPATTRIB_TPM_CALLBACK_COLLATEIDENTITY, "setAttribCallback");
		addSetterData(TcTssConstants.TSS_TSPATTRIB_TPM_CALLBACK_ACTIVATEIDENTITY, "setAttribCallback");
		addSetterData(TcTssConstants.TSS_TSPATTRIB_TPM_CREDENTIAL, "setAttribCredential");
	}


	/*************************************************************************************************
	 * The sole purpose of this method is to notify callers that TSS 1.1 style callback functions are
	 * not supported.
	 */
	public synchronized void setAttribCallbackUINT32(long subFlag, long attrib) throws TcTssException
	{
		throw new TcTspException(TcTssErrors.TSS_E_NOTIMPL,
				"TSS 1.1. callback functions are not supported.");
	}


	/*************************************************************************************************
	 * The sole purpose of this method is to notify callers that TSS 1.1 style callback functions are
	 * not supported.
	 */
	public synchronized long getAttribCallbackUINT32(long subFlag) throws TcTssException
	{
		throw new TcTspException(TcTssErrors.TSS_E_NOTIMPL,
				"TSS 1.1. callback functions are not supported.");
	}


	/*************************************************************************************************
	 * Not yet supported.
	 */
	public synchronized void setAttribCallback(long subFlag, TcBlobData attrib) throws TcTssException
	{
		throw new TcTspException(TcTssErrors.TSS_E_NOTIMPL,
				"TSS 1.2. callback functions not yet implemented.");
	}


	/*************************************************************************************************
	 * Not yet supported.
	 */
	public synchronized TcBlobData getAttribCallback(long subFlag) throws TcTssException
	{
		throw new TcTspException(TcTssErrors.TSS_E_NOTIMPL,
				"TSS 1.2. callback functions not yet implemented.");
	}


	/*************************************************************************************************
	 * This method can be used to set credentials (EK, Platform, ...) that should be used in the
	 * collateIdentity method. Credentials set via this method have precedence over credentials that
	 * are internally obtained by the TSS.
	 *
	 * @TSS_1_2_EA 240
	 *
	 * @param subFlag Sub flag indicating the attribute to set. Valid subFlags are:
	 *          <ul>
	 *          <li>{@link TcTssConstants#TSS_TPMATTRIB_EKCERT}
	 *          <li>{@link TcTssConstants#TSS_TPMATTRIB_TPM_CC}
	 *          <li>{@link TcTssConstants#TSS_TPMATTRIB_PLATFORM_CC}
	 *          <li>{@link TcTssConstants#TSS_TPMATTRIB_PLATFORMCERT}
	 *          </ul>
	 *
	 * @param credential The credential blob to set.
	 *
	 * @throws {@link TcTssException}
	 */
	public void setAttribCredential(long subFlag, TcBlobData credential) throws TcTssException
	{
		CheckPrecondition.notNull(credential, "credential");

		synchronized (credentials_) {
			if (subFlag == TcTssConstants.TSS_TPMATTRIB_EKCERT
					|| subFlag == TcTssConstants.TSS_TPMATTRIB_PLATFORM_CC
					|| subFlag == TcTssConstants.TSS_TPMATTRIB_PLATFORMCERT
					|| subFlag == TcTssConstants.TSS_TPMATTRIB_PLATFORM_CC) {
				credentials_.put(new Long(subFlag), credential);

			} else {
				throw new TcTspException(TcTssErrors.TSS_E_INVALID_ATTRIB_SUBFLAG);
			}
		}
	}


	/* (non-Javadoc)
	 * @see iaik.tc.tss.api.tspi.TcITpm#readCurrentTicks()
	 */
	public TcTpmCurrentTicks readCurrentTicks() throws TcTssException {

		TcTpmCurrentTicks currentTicks=TcTspInternal.TspReadCurrentTicks_Internal(context_);

		return currentTicks;
	}

	/* (non-Javadoc)
	 * @see iaik.tc.tss.api.tspi.TcITpm#readCurrentCounter()
	 */
	public TcTpmCounterValue readCurrentCounter() throws TcTssException {

		long counterId = getCapabilityUINT32(TcTssConstants.TSS_TPMCAP_PROPERTY, //
				TcBlobData.newUINT32(TcTssConstants.TSS_TPMCAP_PROP_ACTIVECOUNTER));

		if(counterId == 0xFFFFFFFFL)
			throw new TcTspException(TcTssErrors.TSS_E_NO_ACTIVE_COUNTER);

		TcTpmCounterValue counterValue = TcTspInternal.TspReadCounter_Internal(context_, counterId);

		return counterValue;
	}

	/* (non-Javadoc)
	 * @see iaik.tc.tss.api.tspi.TcITpm#OwnerGetSRKPubKey()
	 */
	public TcIRsaKey OwnerGetSRKPubKey() throws TcTssException
	{

		checkContextOpenAndConnected();
		// validation can be null (i.e. TSP does validation)

		TcTpmPubkey tpmPubSRK = null;
		//TcTssValidation outValidation = new TcTssValidation(); //Not needed

		TcTcsAuth inAuth1 = TcTspInternal.TspOIAP_Internal(context_);
		TcTpmSecret ownerAuth = new TcTpmSecret(usagePolicy_.getSecret());

		if (isOrdinalSupported(TcTpmOrdinals.TPM_ORD_OwnerReadInternalPub)) {
			// TPM 1.2
			Object[] tpmOutData = TcTspInternal.TspOwnerReadInternalPub_Internal(context_,
					TcTpmConstants.TPM_KH_SRK, inAuth1, ownerAuth);
			tpmPubSRK = (TcTpmPubkey) tpmOutData[1];

		} else {
			throw new TcTspException(TcTssErrors.TSS_E_TPM_UNSUPPORTED_FEATURE, "The public part of the SRK can only be extracted on 1.2 TPMs.");
		}

		TcIRsaKey pubSRK = context_.createRsaKeyObject(0);
		pubSRK.setAttribData(TcTssConstants.TSS_TSPATTRIB_KEY_BLOB,
				TcTssConstants.TSS_TSPATTRIB_KEYBLOB_PUBLIC_KEY, tpmPubSRK.getEncoded());

		return pubSRK;
	}

	/* (non-Javadoc)
	 * @see iaik.tc.tss.api.tspi.TcITpm#CMKApproveMA(iaik.tss.api.tspi.TcIMigData)
	 */
	public void CMKApproveMA(TcIMigData maAuthData) throws TcTssException
	{
		checkContextOpenAndConnected();
		CheckPrecondition.notNullAndInstanceOf(maAuthData, "maAuthData", TcMigData.class);

		TcTcsAuth inAuth1 = TcTspInternal.TspOIAP_Internal(context_);
		TcTpmSecret ownerAuth = new TcTpmSecret(usagePolicy_.getSecret());

		TcTpmDigest migrationAuthorityDigest = new TcTpmDigest(
				((TcMigData)maAuthData).getAttribAuthorityData(TcTssConstants.TSS_MIGATTRIB_AUTHORITY_DIGEST));

		Object[] tpmOutData = TcTspInternal.TspCmkApproveMA_Internal(context_, migrationAuthorityDigest, inAuth1, ownerAuth);

		TcTpmDigest msaHmac = (TcTpmDigest)tpmOutData[1];
		((TcMigData)maAuthData).setAttribAuthorityData(TcTssConstants.TSS_MIGATTRIB_AUTHORITY_APPROVAL_HMAC, msaHmac.getDigest());
	}

	/* (non-Javadoc)
	 * @see iaik.tc.tss.api.tspi.TcITpm#CMKCreateTicket(iaik.tss.api.tspi.TcIRsaKey,
	 *      iaik.tss.api.tspi.TcIMigData)
	 */
	public void CMKCreateTicket(TcIRsaKey verifyKey, TcIMigData sigData)
			throws TcTssException
	{
		checkContextOpenAndConnected();
		CheckPrecondition.notNullAndInstanceOf(verifyKey, "verifyKey", TcRsaKey.class);
		CheckPrecondition.notNullAndInstanceOf(sigData, "sigData", TcMigData.class);

		TcTcsAuth inAuth1 = TcTspInternal.TspOIAP_Internal(context_);
		TcTpmSecret ownerAuth = new TcTpmSecret(usagePolicy_.getSecret());

		TcTpmPubkey verificationKey = new TcTpmPubkey(verifyKey.getPubKey());

		TcTpmDigest signedData = ((TcMigData)sigData).getSigData();
		TcBlobData signatureValue = ((TcMigData)sigData).getSigValue();
		Object[] tpmOutData = TcTspInternal.TspCMK_CreateTicket_Internal(context_, verificationKey, signedData, signatureValue, inAuth1, ownerAuth);

		((TcMigData)sigData).setAttribTicketData(TcTssConstants.TSS_MIGATTRIB_TICKET_SIG_TICKET, ((TcTpmDigest)tpmOutData[1]).getDigest());
	}

	/* (non-Javadoc)
	 * @see iaik.tc.tss.api.tspi.TcITpm#CMKSetRestrictions(long)
	 */
	public void CMKSetRestrictions(long cmkDelegate) throws TcTssException
	{
		checkContextOpenAndConnected();

		TcTcsAuth inAuth1 = TcTspInternal.TspOIAP_Internal(context_);
		TcTpmSecret ownerAuth = new TcTpmSecret(usagePolicy_.getSecret());

		TcTspInternal.TspCmkSetRestrictions_Internal(context_, cmkDelegate, inAuth1, ownerAuth);
	}

	/* (non-Javadoc)
	 * @see iaik.tc.tss.api.tspi.TcITpm#setOperatorAuth(iaik.tss.api.tspi.TcIPolicy)
	 */
	public void setOperatorAuth(final TcIPolicy operatorPolicy) throws TcTssException
	{
		checkContextOpenAndConnected();
		CheckPrecondition.notNullAndInstanceOf(operatorPolicy, "operatorPolicy", TcPolicy.class);

		TcTpmSecret operatorAuth = new TcTpmSecret(((TcPolicy)operatorPolicy).getSecret());

		TcTspInternal.TspSetOperatorAuth_Internal(context_, operatorAuth);

		setOperatorPolicy(operatorPolicy);
	}

	/*
	 * helper method to try to obtain EK Cert from NV Ram with owner auth
	 * on failure it just returns null
	 */
	protected TcBlobData getEndorsementCredentialAlternative() {
		TcBlobData endorsementCredential = null;

		try {
			if (getRealTpmVersion().equalsMinMaj(TcTssVersion.TPM_V1_2)) {
				TcINvRam nvIndexEK = context_.getNvRamObject(TcTpmConstants.TPM_NV_INDEX_EKCert);
				if (getUsagePolicyObject() != null) {
					((TcIPolicy) getUsagePolicyObject()).assignToObject(nvIndexEK);
					long magicSmartRead = 0xFFFFFFFF;
					TcBlobData ekCertRaw = nvIndexEK.readValue(0, magicSmartRead);
					TcTcgPcclientStoredCert cert = new TcTcgPcclientStoredCert(ekCertRaw);
					if (cert.getTag() != TcPcclientConstants.TCG_TAG_PCCLIENT_STORED_CERT) {
						throw new TcTcsException(TcTcsErrors.TCS_E_INTERNAL_ERROR,
								"Unexpected certificate struct tag (expected: TCG_TAG_PCCLIENT_STORED_CERT).");
					}
					if (cert.getCertType() != TcPcclientConstants.TCG_FULL_CERT) {
						throw new TcTcsException(TcTcsErrors.TCS_E_INTERNAL_ERROR,
								"Unsupported certificate type. Only TCG_FULL_CERT is supported.");
					}
					TcTcgFullCert fullCert = new TcTcgFullCert(cert.getCert());
					if (fullCert.getTag() != TcPcclientConstants.TCG_TAG_PCCLIENT_FULL_CERT) {
						throw new TcTcsException(TcTcsErrors.TCS_E_INTERNAL_ERROR,
								"Unexpected certificate struct tag (expected: TCG_TAG_PCCLIENT_FULL_CERT).");
					}
					endorsementCredential = fullCert.getCert();
					if (endorsementCredential != null) {
						Log.info("obtained EK Cert from NV Ram using alternative method");
					}
				}
			}
		} catch (Exception e) {
			// silent catch
			// method either returns the EK Cert on success or null on failure
		}

		return endorsementCredential;
	}
}
