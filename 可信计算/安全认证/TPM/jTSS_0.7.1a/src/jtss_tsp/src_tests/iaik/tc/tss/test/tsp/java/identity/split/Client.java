/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.test.tsp.java.identity.split;


import iaik.tc.tss.api.constants.tsp.TcTssConstants;
import iaik.tc.tss.api.exceptions.common.TcTssException;
import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.tss.api.structs.tpm.TcTpmPubkey;
import iaik.tc.tss.api.structs.tsp.TcUuidFactory;
import iaik.tc.tss.api.tspi.TcIContext;
import iaik.tc.tss.api.tspi.TcIPolicy;
import iaik.tc.tss.api.tspi.TcIRsaKey;
import iaik.tc.tss.api.tspi.TcITpm;
import iaik.tc.tss.api.tspi.TcTssAbstractFactory;
import iaik.tc.tss.test.tsp.java.TestDefines;

public class Client {

	/**
	 * TSS context.
	 */
	protected TcIContext context_ = null;

	/**
	 * AIK key object.
	 */
	protected TcIRsaKey aikKey_ = null;


	/**
	 * Constructor.
	 */
	public Client(TcTssAbstractFactory tssFactory) throws TcTssException
	{
		context_ = tssFactory.newContextObject();
		context_.connect();
	}


	/*************************************************************************************************
	 * This method logically belongs to the client. It executes the CollateIdentityReq method of the
	 * TSS. Thereby, a new identity key is created.
	 */
	protected TcBlobData collateIdentityReq(TcTpmPubkey pubKeyPCA) throws TcTssException
	{
		// create a TcRsaKey object and assign it the public key of the CA
		// Note: Only the modulus is set - the public exponent is fixed.
		TcIRsaKey pubKeyPrivacyCa = context_.createRsaKeyObject(TcTssConstants.TSS_OBJECT_TYPE_RSAKEY
				| TcTssConstants.TSS_KEY_SIZE_2048 | TcTssConstants.TSS_KEY_TYPE_LEGACY);
		
		pubKeyPrivacyCa.setAttribData(TcTssConstants.TSS_TSPATTRIB_KEY_BLOB,
				TcTssConstants.TSS_TSPATTRIB_KEYBLOB_PUBLIC_KEY, pubKeyPCA.getEncoded());
		
		// create identity key template
		aikKey_ = context_.createRsaKeyObject(TcTssConstants.TSS_KEY_TYPE_IDENTITY
				| TcTssConstants.TSS_KEY_SIZE_2048 | TcTssConstants.TSS_KEY_AUTHORIZATION
				| TcTssConstants.TSS_KEY_VOLATILE | TcTssConstants.TSS_KEY_NOT_MIGRATABLE);

		// set usage secret for identity key
		TcIPolicy aikUsgPol = context_.createPolicyObject(TcTssConstants.TSS_POLICY_USAGE);
		aikUsgPol.setSecret(TcTssConstants.TSS_SECRET_MODE_PLAIN, TcBlobData.newString("aikSecret"));
		aikUsgPol.assignToObject(aikKey_);
		TcIPolicy aikMigPol = context_.createPolicyObject(TcTssConstants.TSS_POLICY_MIGRATION);
		aikMigPol.setSecret(TcTssConstants.TSS_SECRET_MODE_PLAIN, TcBlobData.newString("none"));
		aikMigPol.assignToObject(aikKey_);

		// get TPM object and set its policy
		TcITpm tpm = context_.getTpmObject();
		TestDefines.tpmPolicy.assignToObject(tpm);

		// allow certificate override
		overrideCertificates();

		// get SRK
		TcIRsaKey srk = context_.getKeyByUuid(TcTssConstants.TSS_PS_TYPE_SYSTEM,
				TcUuidFactory.getInstance().getUuidSRK());
		TestDefines.srkPolicy = context_.createPolicyObject(TcTssConstants.TSS_POLICY_USAGE);
		TestDefines.srkPolicy.setSecret(TestDefines.SRK_SECRET_MODE, TestDefines.srkSecret);
		TestDefines.srkPolicy.assignToObject(srk);

		// create RsaKey that belongs to the context
		TcIRsaKey pcaKeyPub = context_.createRsaKeyObject(TcTssConstants.TSS_KEY_EMPTY_KEY);
		TcBlobData keyBlob = pubKeyPrivacyCa.getAttribData(TcTssConstants.TSS_TSPATTRIB_KEY_BLOB,
				TcTssConstants.TSS_TSPATTRIB_KEYBLOB_BLOB);
		pcaKeyPub.setAttribData(TcTssConstants.TSS_TSPATTRIB_KEY_BLOB,
				TcTssConstants.TSS_TSPATTRIB_KEYBLOB_BLOB, keyBlob);

		// do the CollateIdentityReq call
		TcBlobData collIdReqBlob = tpm.collateIdentityRequest(srk, pcaKeyPub, getIdLabel(), aikKey_,
				Constants.SYM_ALGO);

		return collIdReqBlob;
	}


	/*************************************************************************************************
	 * This method allows to override the credentials that are used in the CollateIdentityReq call.
	 */
	public void overrideCertificates() throws TcTssException
	{
		//TcITpm tpm = context_.getTpmObject();

		// tpm.setAttribData(TcTssConstants.TSS_TSPATTRIB_TPM_CREDENTIAL,
		// TcTssConstants.TSS_TPMATTRIB_EKCERT, TcBlobData.newString("dummyEK"));

		// tpm.setAttribData(TcTssConstants.TSS_TSPATTRIB_TPM_CREDENTIAL,
		// TcTssConstants.TSS_TPMATTRIB_PLATFORM_CC, TcBlobData.newString("dummyCC"));

		// tpm.setAttribData(TcTssConstants.TSS_TSPATTRIB_TPM_CREDENTIAL,
		// TcTssConstants.TSS_TPMATTRIB_PLATFORMCERT, TcBlobData.newString("dummyPC"));
	}


	/*************************************************************************************************
	 * This method returns the Id Label to be used for the new AIK.
	 */
	public TcBlobData getIdLabel()
	{
		return TcBlobData.newString("keyLabelText");
	}


	/*************************************************************************************************
	 * This method is called on the client when the return blob from the PrivacyCA is received.
	 * 
	 * @param symCaAttestationEncrypted The symmetrically encrypted blob received from the Privacy CA.
	 * @param asymCaContentsEncrypted The asymmetrically encrypted blob received from the Privacy CA.
	 */
	protected TcBlobData activateIdentity(TcBlobData symCaAttestationEncrypted,
			TcBlobData asymCaContentsEncrypted) throws TcTssException
	{
		// get SRK
		TcIRsaKey srk = context_.getKeyByUuid(TcTssConstants.TSS_PS_TYPE_SYSTEM,
				TcUuidFactory.getInstance().getUuidSRK());
		TestDefines.srkPolicy = context_.createPolicyObject(TcTssConstants.TSS_POLICY_USAGE);
		TestDefines.srkPolicy.setSecret(TestDefines.SRK_SECRET_MODE, TestDefines.srkSecret);
		TestDefines.srkPolicy.assignToObject(srk);

		// load AIK and activate the identity
		aikKey_.loadKey(srk);
		TcBlobData aikCredFromPCA = context_.getTpmObject().activateIdentity(aikKey_,
				asymCaContentsEncrypted, symCaAttestationEncrypted);

		return aikCredFromPCA;
	}


	/*************************************************************************************************
	 * This method returns the TPM AIK key blob (containing the encrypted private part and the public
	 * part).
	 */
	public TcIRsaKey getAikKey()
	{
		return aikKey_;
	}
}
