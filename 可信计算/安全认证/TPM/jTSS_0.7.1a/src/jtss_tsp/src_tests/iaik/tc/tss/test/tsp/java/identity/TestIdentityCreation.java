/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.test.tsp.java.identity;


import iaik.tc.tss.api.constants.tpm.TcTpmConstants;
import iaik.tc.tss.api.constants.tpm.TcTpmOrdinals;
import iaik.tc.tss.api.constants.tsp.TcTssConstants;
import iaik.tc.tss.api.exceptions.common.TcTssException;
import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.tss.api.structs.tpm.TcTpmAsymCaContents;
import iaik.tc.tss.api.structs.tpm.TcTpmChosenIdHash;
import iaik.tc.tss.api.structs.tpm.TcTpmDigest;
import iaik.tc.tss.api.structs.tpm.TcTpmIdentityContents;
import iaik.tc.tss.api.structs.tpm.TcTpmIdentityProof;
import iaik.tc.tss.api.structs.tpm.TcTpmIdentityReq;
import iaik.tc.tss.api.structs.tpm.TcTpmKeyParms;
import iaik.tc.tss.api.structs.tpm.TcTpmPubkey;
import iaik.tc.tss.api.structs.tpm.TcTpmStructVer;
import iaik.tc.tss.api.structs.tpm.TcTpmSymCaAttestation;
import iaik.tc.tss.api.structs.tpm.TcTpmSymmetricKey;
import iaik.tc.tss.api.structs.tpm.TcTpmSymmetricKeyParms;
import iaik.tc.tss.api.tspi.TcIHash;
import iaik.tc.tss.api.tspi.TcIPolicy;
import iaik.tc.tss.api.tspi.TcIRsaKey;
import iaik.tc.tss.api.tspi.TcITpm;
import iaik.tc.tss.impl.csp.TcCrypto;
import iaik.tc.tss.test.tsp.java.TestCommon;
import iaik.tc.tss.test.tsp.java.TestDefines;
import iaik.tc.utils.logging.Log;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/***************************************************************************************************
 * This test-case reproduces the steps that are required to generate a TPM identity (AIK key-pair
 * plus AIK credential) using a Privacy CA. The main method of this test-case is the
 * testCreateIdentity method. From there, the client and server side actions are triggered. Methods
 * logically executed at the client are prefixed with "client" while those methods executed by the
 * Privacy CA are prefixed with "ca". Note that some aspects of AIK credential generation are not
 * addressed in this test case. This includes the transport of requests and responses using some
 * appropriate protocol. Furthermore, the platform, conformance and endorsement credentials are not
 * verified by the Privacy CA. This can be done by implementing the caVerifyCredentials method.
 * Finally, the AIK credential created by the Privacy CA only contains dummy content.
 */
public class TestIdentityCreation extends TestCommon {

	/**
	 * The RSA key pair of the Privacy CA. This object is logically NOT accessible to the client.
	 */
	protected PrivateKey privKeyPrivacyCa_ = null;

	/**
	 * The public key of the Privacy CA. This object is logically accessible to the client.
	 */
	private PublicKey pubKeyPrivacyCa_ = null;

	/**
	 * The AIK key pair generated by the client. The public key of the AIK is part of the AIK
	 * credential to be signed by the Privacy CA. This object is logically accessible only to the
	 * client.
	 */
	protected TcIRsaKey aikKey_ = null;

	/**
	 * This field holds the expected AIK credential (the credential issued by the Privacy CA). It is
	 * only used in this test case to verify that the credential finally received by the client
	 * matches the one issued by the CA.
	 */
	protected TcBlobData expectedAikCredential_ = null;

	/**
	 * Key length used for CA keys.
	 */
	private final int CA_KEY_LENGTH = 512; // TCG recommends 2048; smaller keys speed up testing

	/**
	 * Parameters for symmetric encryption algorithm.
	 */
	private long SYM_ALGO_TSS = TcTssConstants.TSS_ALG_AES; // AES, AES128, AES192, AES256, 3DES

	// note: for TrouSerS only use AES

	private long SYM_ALGO_TPM; // do not change manually

	private String SYM_ALGO_JAVA; // do not change manually

	private long SYM_KEY_LEN; // do not change manually

	private long SYM_BLOCK_SIZE; // do not change manually

	private long SYM_IV_LEN; // do not change manually

	/**
	 * Enable this flag to be compatibility with the TrouSerS 1.1 TSS. Note: Experimental. Use at your
	 * own risk.
	 */
	private boolean TROUSERS_COMPATIBILITY = false;


	protected void setUp() throws Exception
	{
		super.setUp();

		if (tcsManufactuerIs(TCS_MAN_IBM)) {
			TROUSERS_COMPATIBILITY = true;
		}

		switch ((int) SYM_ALGO_TSS) {
			case (int) TcTssConstants.TSS_ALG_3DES:
				SYM_ALGO_TPM = TcTpmConstants.TPM_ALG_3DES;
				SYM_ALGO_JAVA = "DESede";
				SYM_KEY_LEN = 192;
				SYM_BLOCK_SIZE = 64;
				SYM_IV_LEN = SYM_BLOCK_SIZE;
				break;

			case (int) TcTssConstants.TSS_ALG_AES128:
				// note: ALG_AES is the same as AES_128
				SYM_ALGO_TPM = TcTpmConstants.TPM_ALG_AES128;
				SYM_ALGO_JAVA = "AES";
				SYM_KEY_LEN = 128;
				SYM_BLOCK_SIZE = 128;
				SYM_IV_LEN = SYM_BLOCK_SIZE;
				break;

			case (int) TcTssConstants.TSS_ALG_AES192:
				SYM_ALGO_TPM = TcTpmConstants.TPM_ALG_AES192;
				SYM_ALGO_JAVA = "AES";
				SYM_KEY_LEN = 192;
				SYM_BLOCK_SIZE = 128;
				SYM_IV_LEN = SYM_BLOCK_SIZE;
				break;

			case (int) TcTssConstants.TSS_ALG_AES256:
				SYM_ALGO_TPM = TcTpmConstants.TPM_ALG_AES256;
				SYM_ALGO_JAVA = "AES";
				SYM_KEY_LEN = 256;
				SYM_BLOCK_SIZE = 128;
				SYM_IV_LEN = SYM_BLOCK_SIZE;
				break;

			default:
				break;
		}

	}


	/*************************************************************************************************
	 * This is the main test method of this test-case. It contains the high level steps required to
	 * create a TPM identity. These steps are: (1) client: do a CollateIdentityReq call; (2) client:
	 * send blob from CollateIdentityReq call to the privacy CA; (3) privacy CA: decrypt and verify
	 * the received blob; issue AIK credential and send it back to the client; (4) client: receive
	 * encrypted AIK credential from privacy CA and call the ActivateIdentity function.
	 */
	public void testCreateIdentity()
	{
		// STEP 0 (precondition): This step is not part of an actual identity request procedure. It is
		// assumed that the public key of the Privacy CA is available at the client side. It is beyond
		// the scope of this test case how the client obtains this key.
		// For this test, an RSA key pair is generated that is used as the Privacy CA's key pair.
		// The key pair is stored in the caKeyPair_ field and is logically only accessible by the CA.
		// The public key is stored in the publicCaKey_ field and is logically accessible by the client.

		try {
			createCaKeypairs();
		} catch (NoSuchAlgorithmException e) {
			Log.err(e);
			assertTrue("Unable to create Privacy CA key pair. "
					+ "RSA algorithm is unavailable (export restrictions?).", false);
		}

		// STEP 1 (client): The client does a CollateIdenityRequest.
		// This results in an encrypted blob from the TPM that (among other data) contains the
		// endorsement, platform and conformance credentials.
		// Note that the fields holding some of these credentials simply are null. This is because
		// there currently no hardware/platform manufacturer is shipping these credentials with
		// his platforms. The only exception is Infineon who puts the EK credentials on the their
		// TPM chips (vendor specific for 1.1, in NV storage for 1.2).

		TcBlobData collateIdentityReqBlob = null;
		try {
			collateIdentityReqBlob = clientCollateIdentityReq();
		} catch (TcTssException e) {
			e.printStackTrace();
			assertTrue("client: CollateIdentityRequest failed", false);
		}

		// STEP 2 (client): The blob from the CollateIdentityRequest is sent to the Privacy CA.
		// Note that neither the ASN.1 encoding of the message nor the message transport mechanism are
		// part of this test case.

		// STEP 3 (Privacy CA): The IdentityReq message is received by the Privacy CA.

		TcBlobData symCaAttestationEncrypted = null;
		TcBlobData asymCaContentsEncrypted = null;
		try {
			Object[] caBlobs = caMainRoutine(collateIdentityReqBlob);
			symCaAttestationEncrypted = (TcBlobData) caBlobs[0];
			asymCaContentsEncrypted = (TcBlobData) caBlobs[1];
		} catch (TcTssException e) {
			Log.err(e);
			assertTrue("privacy ca: general failure", false);
		}

		// STEP 4 (Privacy CA): Send encrypted sym and asym blobs from the Privacy CA to the client.
		// Note that neither the ASN.1 encoding of the message nor the message transport mechanism are
		// part of this test case.

		// STEP 5 (Client): The encrypted sym and asym blobs are received by the client. The new
		// identity is activated by the client.

		try {
			TcBlobData aikCredential = clientActivateIdentity(symCaAttestationEncrypted,
					asymCaContentsEncrypted);
			if (aikCredential.equals(expectedAikCredential_)) {
				Log.info("AIK credential successfully received and activated at the client");
			} else {
				Log.warn("AIK credential creation failed");
			}
		} catch (TcTssException e) {
			Log.err(e);
			assertTrue("client: activate identity failed", false);
		}
	}


	/*************************************************************************************************
	 * This method creates an RSA key pair that is used as the key pair of the Privacy CA.
	 *
	 * @return the public key of the CA. This key is required by the client for the CollateIdentity
	 *         request.
	 * @throws TcTssException
	 */
	protected void createCaKeypairs() throws NoSuchAlgorithmException
	{
		// note: The TPM specification defines the public exponent to be 2^16 + 1 = 65537
		// for RSA keys generated by the TPM. The key pair of the Privacy CA is not required to be
		// generated inside a TPM. Hence, a different public exponent might be used.
		// Note that the default public exponent used by Java defaults to the same value as used
		// by the TCG.

		KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
		generator.initialize(CA_KEY_LENGTH);

		KeyPair kpairPrivacyCa = generator.generateKeyPair();
		privKeyPrivacyCa_ = kpairPrivacyCa.getPrivate();
		pubKeyPrivacyCa_ = kpairPrivacyCa.getPublic();
	}


	// ----------------------------------------------------------------------------------------------
	// Client side methods
	// ----------------------------------------------------------------------------------------------

	/*************************************************************************************************
	 * This method is a client side helper function. It extracts the public Privacy CA key and wraps
	 * it into a TSS key object. This TSS key object is passed to the TSP as part of the
	 * CollateIdentityReq call.
	 */
	public TcIRsaKey getPrivacyCaPubKey() throws TcTssException
	{
		TcIRsaKey pubKeyPrivacyCa = context_.createRsaKeyObject(TcTssConstants.TSS_OBJECT_TYPE_RSAKEY
				| TcTssConstants.TSS_KEY_SIZE_2048 | TcTssConstants.TSS_KEY_TYPE_LEGACY);

		TcTpmPubkey pubKey = TcCrypto.pubJavaToTpmKey((RSAPublicKey)pubKeyPrivacyCa_);

		pubKeyPrivacyCa.setAttribData(TcTssConstants.TSS_TSPATTRIB_KEY_BLOB,
				TcTssConstants.TSS_TSPATTRIB_KEYBLOB_PUBLIC_KEY, pubKey.getEncoded());

		return pubKeyPrivacyCa;
	}


	/*************************************************************************************************
	 * This method logically belongs to the client. It executes the CollateIdentityReq method of the
	 * TSS. Thereby, a new identity key is created.
	 */
	protected TcBlobData clientCollateIdentityReq() throws TcTssException
	{
		// get TPM object and set its policy
		TcITpm tpm = context_.getTpmObject();
		TestDefines.tpmPolicy.assignToObject(tpm);

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

		// get the public key of the selected privacy CA (how to obtain this key is beyond the scope of
		// this test case)
		TcIRsaKey pubKeyPrivacyCa = getPrivacyCaPubKey();

		// do the CollateIdentityReq call
		TcBlobData collIdReqBlob = tpm.collateIdentityRequest(srk_, pubKeyPrivacyCa,
				clientGetIdLabel(), aikKey_, SYM_ALGO_TSS);

		return collIdReqBlob;
	}


	/*************************************************************************************************
	 * This method returns the Id Label to be used for the new AIK.
	 */
	public TcBlobData clientGetIdLabel()
	{
		return TcBlobData.newString("keyLabelText");
	}


	/*************************************************************************************************
	 * This method is called on the client when the return blob from the PrivacyCA is received.
	 *
	 * @param symCaAttestationEncrypted The symmetrically encrypted blob received from the Privacy CA.
	 * @param asymCaContentsEncrypted The asymmetrically encrypted blob received from the Privacy CA.
	 */
	protected TcBlobData clientActivateIdentity(TcBlobData symCaAttestationEncrypted,
			TcBlobData asymCaContentsEncrypted) throws TcTssException
	{
		aikKey_.loadKey(srk_);
		TcBlobData aikCredFromPCA = context_.getTpmObject().activateIdentity(aikKey_,
				asymCaContentsEncrypted, symCaAttestationEncrypted);

		return aikCredFromPCA;
	}


	// ----------------------------------------------------------------------------------------------
	// Privacy CA side methods
	// ----------------------------------------------------------------------------------------------

	/*************************************************************************************************
	 * This is the main method at the CA side which calls several sub methods. These sub methods
	 * decrypt the identity request blob from the client, verify the identity proof and the client
	 * credentials, issue an AIK credential and finally generate the response for the client.
	 *
	 * @param collateIdentityReqBlob The raw CollateIdentityReq data blob
	 * @return symmetrically and asymmetrically encrypted CA response blobs
	 * @throws Exception
	 */
	protected Object[] caMainRoutine(TcBlobData collateIdentityReqBlob) throws TcTssException
	{

		// step 1: decrypt and decode the collate identity request blob from the client

		TcTpmIdentityProof identityProof = caDecryptIdentityReqBlob(collateIdentityReqBlob);

		// step 2: verify the identity proof from the client

		try {
			caVerifyIdentityProof(identityProof);
		} catch (TcTssException e) {
			assertTrue("Verification of identity proof failed.", false);
		}
		// proof verification OK

		// step 3: verify the credentials (endorsement, platform, conformance) received from the client

		if (!caVerifyCredentials(identityProof)) {
			assertTrue("Verification of credentials failed.", false);
		}
		// certificate verification OK

		// step 4: issue the AIK credential

		TcBlobData aikCredential = null;
		try {
			aikCredential = caBuildAikCredential(identityProof);
		} catch (Exception e) {
			assertTrue("Creation of AIK credential failed.", false);
		}

		// step 5: build response for the client

		Object[] response = caBuildResponse(identityProof, aikCredential);

		// step 6: return response to the client

		return response;
	}


	/*************************************************************************************************
	 * This method takes the CollateIdentityReq blob from the client and decrypts the components: (1)
	 * The asymBlob containing the symmetric key encrypted with the CAs public RSA key. (2) The
	 * symBlob (containing an TPM_IDENTITY_PROOF instance) encrypted with the symmetric session key.
	 * Finally, the TPM_IDENTITY_PROOF instance is returned.
	 *
	 * @param collateIdentityReqBlob The raw CollateIdentityReq data blob.
	 * @return Instance of TPM_IDENTITY_PROOF contained in the CollateIdentityReq data blob.
	 */
	protected TcTpmIdentityProof caDecryptIdentityReqBlob(TcBlobData collateIdentityReqBlob)
		throws TcTssException
	{
		// step 1: decode the collate identity request blob
		TcTpmIdentityReq collateIdentityReq = new TcTpmIdentityReq(collateIdentityReqBlob);

		TcBlobData symBlobDecrypted = null;
		try {

			// step 2: decrypt the symmetric key (encrypted by the client with the public CA key)

			Cipher rsaDec = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			rsaDec.init(Cipher.DECRYPT_MODE, privKeyPrivacyCa_);
			TcTpmSymmetricKey symmetricKey = new TcTpmSymmetricKey( //
					TcBlobData.newByteArray(rsaDec.doFinal(collateIdentityReq.getAsymBlob().asByteArray())));

			// step 3: decrypt the symmetrically encrypted data

			byte[] iv = null;
			byte[] symBlob = null;
			if (TROUSERS_COMPATIBILITY) {
				// for TrouSerS the IV for CBC mode is prepend to the encrypted data
				iv = collateIdentityReq.getSymBlob().getRange(0, (int) SYM_IV_LEN / 8);

				// the symmetrically encrypted data blob starts after the IV
				symBlob = collateIdentityReq.getSymBlob().getRange((int) SYM_KEY_LEN / 8,
						collateIdentityReq.getSymBlob().getLength() - (int) SYM_KEY_LEN / 8);

			} else {

				// jTSS is a 1.2 stack that supports the TPM_SYMMETRIC_KEY_PARAMS structure
				TcTpmSymmetricKeyParms symKeyParams = new TcTpmSymmetricKeyParms(collateIdentityReq
						.getSymAlgorithm().getParms());
				iv = symKeyParams.getIV().asByteArray();

				symBlob = collateIdentityReq.getSymBlob().asByteArray();

			}

			IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

			Cipher aesDec = Cipher.getInstance(SYM_ALGO_JAVA + "/CBC/PKCS5Padding");
			SecretKeySpec skeySpec = new SecretKeySpec(symmetricKey.getData().asByteArray(),
					SYM_ALGO_JAVA);

			aesDec.init(Cipher.DECRYPT_MODE, skeySpec, ivParameterSpec);
			symBlobDecrypted = TcBlobData.newByteArray(aesDec.doFinal(symBlob));

		} catch (GeneralSecurityException e) {
			Log.err(e);
			assertTrue("Decrypting the CollateIdentityReq blob failed.", false);
		}

		// the decrypted data is of type TPM_IDENTITY_PROOF
		TcTpmIdentityProof identityProof = new TcTpmIdentityProof(symBlobDecrypted);

		return identityProof;
	}


	/*************************************************************************************************
	 * This method verifies the identity proof that was generated at the client side as part of the
	 * CollateIdentityReq method call.
	 */
	protected void caVerifyIdentityProof(TcTpmIdentityProof identityProof) throws TcTssException
	{
		// step 1: The identity key label and the public key of the CA are concatenated.
		// Then the sha1 hash of this data blob is computed.
		// This TPM_CHOSENID_HASH is part of the TPM_IDENTITY_CONTENTS structure.

		// Note from the TPM Spec:
		// "The reason for including the hash of the public key of the Privacy CA inside
		// identity-binding signature is to prevent a rogue obtaining attestation from multiple Privacy
		// CAs. The identity-binding signature creation is an atomic operation performed at the same
		// time as the key pair creation, and therefore the TPM cannot be coerced into creating a
		// version of the identity-binding signature with the same keys but a different Privacy CA
		// public key.

		TcBlobData caPublicKeyBlob = getPrivacyCaPubKey().getAttribData(
				TcTssConstants.TSS_TSPATTRIB_KEY_BLOB, TcTssConstants.TSS_TSPATTRIB_KEYBLOB_PUBLIC_KEY);
		TcTpmPubkey caPublicKey = new TcTpmPubkey(caPublicKeyBlob);

		TcBlobData chosenIdHashData = (TcBlobData) identityProof.getLabelArea().clone();
		chosenIdHashData.append(caPublicKey.getEncoded());

		TcTpmChosenIdHash chosenIdHash = new TcTpmChosenIdHash(chosenIdHashData.sha1());

		// step 2: create an TPM_IDENTITY_CONTENTS instance

		TcTpmIdentityContents identityContents = new TcTpmIdentityContents();
		// Note on StructVer: The PrivacyCA can not know which version string was used by the client
		// TPM to create the request blob (can be the real TPM version as on (all?) 1.1b TPMs or
		// fixed to 1.1.0.0. The jTSS sets the version reported by the TPM_CAP_VERSION into the
		// identityProof structure (this is either the real version on 1.1b or 1.1.0.0 on 1.2).
		// By using this version field, the PrivacyCA has a good chance to correctly verify the
		// request generated in the client TPM.
		identityContents.setVer((TcTpmStructVer)identityProof.getVersion());
		identityContents.setOrdinal(TcTpmOrdinals.TPM_ORD_MakeIdentity);
		identityContents.setLabelPrivCADigest(chosenIdHash);
		identityContents.setIdentityPubKey(identityProof.getIdentityKey());

		TcBlobData identityContentsHash = identityContents.getEncoded().sha1();

		// step 3: verify the identity proof

		// step 3a: wrap AIK

		TcIRsaKey aikKey = context_.createRsaKeyObject(TcTssConstants.TSS_KEY_TYPE_IDENTITY
				| TcTssConstants.TSS_KEY_SIZE_2048 | TcTssConstants.TSS_KEY_VOLATILE
				| TcTssConstants.TSS_KEY_AUTHORIZATION | TcTssConstants.TSS_KEY_NOT_MIGRATABLE);

		aikKey.setAttribData(TcTssConstants.TSS_TSPATTRIB_KEY_BLOB,
				TcTssConstants.TSS_TSPATTRIB_KEYBLOB_PUBLIC_KEY, identityProof.getIdentityKey()
						.getEncoded());

		// Note:
		// identityContentsHash is the expected hash value as generated in step 1 and 2.
		// identityProof.
		// IdentityBinding (from identityProof.getIdentityBinding()) contains the signed hash
		// value that was generated on the client inside the TPM as part of the
		// CollateIdentityReq call. This hash value was signed using the private part
		// of the new AIK on the client. The verifySignature method takes this signed hash,
		// decrypts it with the public aikKey and compares it to the value provided in
		// identityContentsHash.

		// step 3b: actual verification

		TcIHash hash = context_.createHashObject(TcTssConstants.TSS_HASH_SHA1);
		hash.setHashValue(identityContentsHash);
		hash.verifySignature(identityProof.getIdentityBinding(), aikKey);
	}


	/*************************************************************************************************
	 * This method is designed to verify the credentials supplied by the client. Only if all
	 * credentials could be verified to meet the TCG specs and the policies of the Privacy CA, this
	 * method succeeds.
	 *
	 * @return If the verification is successful true is returned, otherwise false.
	 */
	protected boolean caVerifyCredentials(TcTpmIdentityProof identityProof)
	{
		// step 1: verify conformance credential (identityProof.getConformanceCredential())
		// NOT IMPLEMENTED

		// step 2: verify platform credential (identityProof.getPlatformCredential())
		// NOT IMPLEMENTED

		// step 3: verify endorsement credential (identityProof.getEndorsementCredential())
		// NOT IMPLEMENTED

		return true;
	}


	/*************************************************************************************************
	 * This method constructs the AIK credential.
	 */
	protected TcBlobData caBuildAikCredential(TcTpmIdentityProof identityProof) throws Exception
	{
		// NOT IMPLEMENTED: build and sign the AIK credential
		// The TCcert library available from http://trustedjava.sf.net can be used for that purpose.
		// The Java TPM Tools available at the same location provide an implementation of the createAIK
		// cycle that combines this AIK creation code with the certificate creation code of TCcert.

		expectedAikCredential_ = TcBlobData
				.newString("This is the AIK dummy credential (not using TCcert).");
		return expectedAikCredential_;
	}


	/*************************************************************************************************
	 * This method builds the response the Privacy CA sends to the client. This response consists of
	 * two parts: (1) An asymmetrically encrypted part (encrypted with the public EK of the client's
	 * TPM). This part contains the symmetric session key and a hash of the new identity key. This
	 * hash is used by the client's TPM in the ActivateIdentity call to identify the key the AIK
	 * credential belongs to. (2) A symmetrically encrypted part that contains the new AIK credential.
	 */
	protected Object[] caBuildResponse(TcTpmIdentityProof identityProof, TcBlobData aikCredential)
		throws TcTssException
	{
		// step 1: create the symmetric CA blob (TPM_SYM_CA_ATTESTATION) containing the
		// AIK credential

		TcTpmSymmetricKeyParms symParams = new TcTpmSymmetricKeyParms();
		symParams.setKeyLength(SYM_KEY_LEN);
		symParams.setBlockSize(SYM_BLOCK_SIZE);
		symParams.setIV(context_.getTpmObject().getRandom(SYM_IV_LEN / 8));

		TcTpmKeyParms symCaAttestationKeyParms = new TcTpmKeyParms();
		symCaAttestationKeyParms.setAlgorithmID(SYM_ALGO_TPM);
		// TPM level structures are filled with TPM level constants
		symCaAttestationKeyParms.setEncScheme((int) TcTpmConstants.TPM_ES_SYM_CBC_PKCS5PAD);
		symCaAttestationKeyParms.setSigScheme((int) TcTpmConstants.TPM_SS_NONE);
		symCaAttestationKeyParms.setParms(symParams.getEncoded());

		TcTpmSymCaAttestation symCaAttestation = new TcTpmSymCaAttestation();
		symCaAttestation.setAlgorithm(symCaAttestationKeyParms);
		symCaAttestation.setCredential(aikCredential);

		// step 2: generate a symmetric session key

		TcTpmSymmetricKey symCaKey = new TcTpmSymmetricKey();
		symCaKey.setAlgId(symCaAttestationKeyParms.getAlgorithmID());
		symCaKey.setEncScheme((int) symCaAttestationKeyParms.getEncScheme());
		if (SYM_ALGO_TSS == TcTssConstants.TSS_ALG_3DES) {
			symCaKey.setData(TcCrypto.create3DESkey());
		} else {
			symCaKey.setData(TcCrypto.createAESkey((int) SYM_KEY_LEN));
		}

		// step 3: symmetric encryption

		TcBlobData symBlobEncrypted = null;
		if (TROUSERS_COMPATIBILITY) {
			// as a 1.1 stack, TrouSerS does not have the TPM_SYMMETRIC_PARAMS struct
			symCaAttestationKeyParms.setParms(null);

			// as a 1.1 stack TrouSerS does not know about TPM_ES_SYM_CBC_PKCS5PAD;
			// CBC mode is used implicitly
			symCaAttestationKeyParms.setEncScheme((int) TcTpmConstants.TPM_ES_NONE);
			symCaKey.setEncScheme((int) TcTpmConstants.TPM_ES_NONE);

			// only encrypt the AIK credential with the symmetric key (as defined by the TSS spec)
			TcBlobData encryptedCredential = TcCrypto.encryptSymmetricCbcPkcs5Pad(SYM_ALGO_JAVA, symCaKey
					.getData(), symParams.getIV(), symCaAttestation.getCredential());

			// TrouSerS: prepend the IV to the symmetrically encrypted blob
			encryptedCredential.prepend(symParams.getIV());
			symCaAttestation.setCredential(encryptedCredential);
			symBlobEncrypted = symCaAttestation.getEncoded();

		} else {
			// only encrypt the AIK credential with the symmetric key (as defined by the TSS spec)
			TcBlobData encryptedCredential = TcCrypto.encryptSymmetricCbcPkcs5Pad(SYM_ALGO_JAVA, symCaKey
					.getData(), symParams.getIV(), symCaAttestation.getCredential());

			// set the encrypted AIK credential
			symCaAttestation.setCredential(encryptedCredential);

			symBlobEncrypted = symCaAttestation.getEncoded();
		}

		// step 4: Create an instance of TPM_ASYM_CA_CONTENS to hold the symmetric key.
		// This blob is later encrypted with the public endorsement key of the client.

		TcTpmDigest identityKeyHash = new TcTpmDigest();
		identityKeyHash.setDigest(identityProof.getIdentityKey().getEncoded().sha1());

		TcTpmAsymCaContents asymCaContents = new TcTpmAsymCaContents();
		asymCaContents.setSessionKey(symCaKey);
		asymCaContents.setIdDigest(identityKeyHash);

		// step 5: Encrypt the TPM_ASYM_CA_CONTENTS instance with the public EK of the client's TPM

		// NOTE: The real Privacy CA can not access the public endorsement key of the client this way
		// (the Privacy CA and the client typically will not be located on the same machine).
		// The key has to be extracted from the endorsement credential provided by the client.

		// get public EK
		TcITpm tpm = context_.getTpmObject();
		TestDefines.tpmPolicy.assignToObject(tpm);
		TcIRsaKey pubEK = tpm.getPubEndorsementKeyOwner();
		TcTpmPubkey tpmPubEk = new TcTpmPubkey(pubEK.getAttribData(
				TcTssConstants.TSS_TSPATTRIB_KEY_BLOB, TcTssConstants.TSS_TSPATTRIB_KEYBLOB_PUBLIC_KEY));

		// encrypt the asymCaContents
		TcBlobData asymCaContentsEncrypted = TcCrypto.pubEncryptRsaOaepSha1Mgf1(tpmPubEk,
				asymCaContents.getEncoded());

		// return the blob
		// symCaAttestation.credential holds the symmetrically encrypted AIK credential (the rest of the
		// structure is not encrypted).
		// asymCaContentsEncrypted holds symmetric session key (plus some key info) encrypted with the
		// public EK of the client.
		// return new Object[] { symCaAttestation.getEncoded(), asymCaContentsEncrypted };
		return new Object[] { symBlobEncrypted, asymCaContentsEncrypted };
	}
}
