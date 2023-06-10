/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.test.tsp.java.keys;


import iaik.tc.tss.api.constants.tpm.TcTpmErrors;
import iaik.tc.tss.api.constants.tsp.TcTssConstants;
import iaik.tc.tss.api.exceptions.common.TcTssException;
import iaik.tc.tss.api.exceptions.tcs.TcTpmException;
import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.tss.api.structs.tpm.TcTpmCapVersionInfo;
import iaik.tc.tss.api.structs.tpm.TcTpmCertifyInfo;
import iaik.tc.tss.api.structs.tpm.TcTpmPubkey;
import iaik.tc.tss.api.structs.tsp.TcTssValidation;
import iaik.tc.tss.api.structs.tsp.TcTssVersion;
import iaik.tc.tss.api.tspi.TcIHash;
import iaik.tc.tss.api.tspi.TcIPcrComposite;
import iaik.tc.tss.api.tspi.TcIPolicy;
import iaik.tc.tss.api.tspi.TcIRsaKey;
import iaik.tc.tss.api.tspi.TcITpm;
import iaik.tc.tss.impl.csp.TcCrypto;
import iaik.tc.tss.test.tsp.java.TestCommon;
import iaik.tc.tss.test.tsp.java.TestDefines;
import iaik.tc.utils.logging.Log;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;


public class TestKeys extends TestCommon {

	/**
	 * This method creates a new TPM RSA key with the SRK as its parent.
	 * 
	 */
	public void testCreateKeyWithoutPcr()
	{
		try {
			TcIRsaKey key = context_.createRsaKeyObject(0);
			TestDefines.keyUsgPolicy.assignToObject(key);
			TestDefines.keyMigPolicy.assignToObject(key);
			key.createKey(srk_, null);

		} catch (TcTssException e) {
			if (PRINT_TRACE) {
				Log.err(e);
			}
			assertTrue("creating key failed", false);
		}
	}

	public void testGetKeyModulusExponent()
	{
		try {
			
		      TcIRsaKey someKey = context_.createRsaKeyObject( //
		                TcTssConstants.TSS_KEY_SIZE_2048 | //
		                TcTssConstants.TSS_KEY_TYPE_LEGACY | //
		                TcTssConstants.TSS_KEY_NOT_MIGRATABLE);
		       
		        // create a key usage policy for this key
		        TcIPolicy keyUsgPolicy = context_.createPolicyObject (TcTssConstants.TSS_POLICY_USAGE);
		        keyUsgPolicy.setSecret(TcTssConstants.TSS_SECRET_MODE_PLAIN, TcBlobData.newString("theAIKsecret"));
		        keyUsgPolicy.assignToObject(someKey);
		       
		        //create a key migration policy for this key
		        TcIPolicy keyMigPolicy = context_.createPolicyObject(TcTssConstants.TSS_POLICY_MIGRATION);
		        keyMigPolicy.setSecret(TcTssConstants.TSS_SECRET_MODE_PLAIN, TcBlobData.newString("theAIKsecret"));
		        keyMigPolicy.assignToObject(someKey);
		       
		        someKey.createKey(srk_, null);
		        someKey.loadKey(srk_);
		        
		        someKey.getAttribData(TcTssConstants.TSS_TSPATTRIB_RSAKEY_INFO, TcTssConstants.TSS_TSPATTRIB_KEYINFO_RSA_MODULUS);
		    
		        someKey.getAttribData(TcTssConstants.TSS_TSPATTRIB_RSAKEY_INFO, TcTssConstants.TSS_TSPATTRIB_KEYINFO_RSA_EXPONENT);
			
	
		} catch (TcTssException e) {
			if (PRINT_TRACE) {
				Log.err(e);
			}
			assertTrue("creating key failed", false);
		}
	}
	
	/**
	 * This method creates a new TPM RSA key with the SRK as its parent, which can be used as AIK.
	 * Was created in response to a ML problem report on 23 Aug 2007. The problem could NOT be reproduced.
	 */
	public void testCreateKeyWithoutPcrAsMailingListProblem()
	{
		try {
			
		      TcIRsaKey someKey = context_.createRsaKeyObject( //
		                TcTssConstants.TSS_KEY_SIZE_2048 | //
		                TcTssConstants.TSS_KEY_TYPE_SIGNING | //
		                TcTssConstants.TSS_KEY_NOT_MIGRATABLE);
		       
		        // create a key usage policy for this key
		        TcIPolicy keyUsgPolicy = context_.createPolicyObject (TcTssConstants.TSS_POLICY_USAGE);
		        keyUsgPolicy.setSecret(TcTssConstants.TSS_SECRET_MODE_PLAIN, TcBlobData.newString("theAIKsecret"));
		        keyUsgPolicy.assignToObject(someKey);
		       
		        //create a key migration policy for this key
		        TcIPolicy keyMigPolicy = context_.createPolicyObject(TcTssConstants.TSS_POLICY_MIGRATION);
		        keyMigPolicy.setSecret(TcTssConstants.TSS_SECRET_MODE_PLAIN, TcBlobData.newString("theAIKsecret"));
		        keyMigPolicy.assignToObject(someKey);
		       
		        someKey.createKey(srk_, null);
		        someKey.loadKey(srk_);
			
	
		} catch (TcTssException e) {
			if (PRINT_TRACE) {
				Log.err(e);
			}
			assertTrue("creating key failed", false);
		}
	}
	/**
	 * This test creates a storage key that is bound to a PCR. This PCR is then modified. In the next
	 * step another key is created with the previous key as the parent. Since the PCR has been
	 * changed, this method should fail.
	 * 
	 */
	public void testCreateKeyWithPcr()
	{
		try {
			if (tpmManufactuerIs(TPM_MAN_ETHZ)) {
				Log.info("Skipping test case creating PCR bound key on TPM emulator.");
				return;
			}
			
			if (getRealTpmVersion().equalsMinMaj(TcTssVersion.TPM_V1_2)) {
				// If running on 1.2 TPMs, ensure that 1.2 structures are used. Otherwise, associating a key
				// with a PCR state (i.e. setting PCRinfo) will fail (at least on IFX and STM 1.2 chips).
				// Note: The reason for failing is that the sizeOfSelect is set to to the actual size as
				// reported by the TPM. sizeOfSelect > 2, however is not accepted when used with 1.1
				// TPM_KEY structs.

				context_.setAttribUint32(TcTssConstants.TSS_TSPATTRIB_CONTEXT_VERSION_MODE, 0,
						TcTssConstants.TSS_TSPATTRIB_CONTEXT_VERSION_V1_2);
			}

			if (tcsManufactuerIs(TCS_MAN_IBM)) {
				Log.info("Creating keys with PCR selection currently does not work with IBM/TrouSerS.");
				return;
			}
			// TODO: the reason for this might be a wrong pcrSlectionSize (see Mail from Georg)

			final int PCR = 15;

			// create a storage key that is bound to a PCR state
			TcIRsaKey key1 = context_.createRsaKeyObject(TcTssConstants.TSS_KEY_TYPE_STORAGE);
			TestDefines.keyUsgPolicy.assignToObject(key1);
			TestDefines.keyMigPolicy.assignToObject(key1);
			TcIPcrComposite pcrComp = context_.createPcrCompositeObject(0);
			pcrComp.setPcrValue(PCR, context_.getTpmObject().pcrRead(PCR));
			key1.createKey(srk_, pcrComp);
			key1.loadKey(srk_);

			// now extend the PCR
			context_.getTpmObject().pcrExtend(PCR, TcBlobData.newString("foobar").sha1(), null);

			// create another key with the previous key as parent
			TcIRsaKey key2 = context_.createRsaKeyObject(TcTssConstants.TSS_KEY_TYPE_LEGACY);
			TestDefines.keyUsgPolicy.assignToObject(key2);
			TestDefines.keyMigPolicy.assignToObject(key2);
			try {
				key2.createKey(key1, null);
				// The createKey should fail because the PCR the parent is bound to was altered.
				// Consequently if the next line is reached that means that something went wrong
				assertTrue("CreateKey succeeded although the current PCR state is not the "
						+ "one the parent key is associated with.", false);
			} catch (TcTpmException e) {
				if (e.getErrCode() == TcTpmErrors.TPM_E_WRONGPCRVAL) {
					// expected behavior
				} else if (e.getErrCode() == TcTpmErrors.TPM_E_INVALID_PCR_INFO) {
					// expected behavior for Atmel Chips
					Log.info("TPM returned TPM_INVALID_PCR_INFO but should return TPM_E_WRONGPCRVAL (expected behavior on Atmel TPMv1.2)");
				} else {
					Log.debug("HERE");
					throw e;
				}
			}
		} catch (TcTssException e) {
			if (PRINT_TRACE) {
				Log.err(e);
			}
			assertTrue("testCreateKeyWithPcr failed", false);
		}
	}

	
	/*************************************************************************************************
	 * Tries to certify (sign) a public key.
	 */
	public void testCertifyKey()
	{
		try {
			
//			context_.setAttribUint32(TcTssConstants.TSS_TSPATTRIB_CONTEXT_VERSION_MODE, 0,
//					TcTssConstants.TSS_TSPATTRIB_CONTEXT_VERSION_V1_2);

//			TcIPcrComposite pcrComp = context_.createPcrCompositeObject(TcTssConstants.TSS_PCRS_STRUCT_INFO_LONG);
//			long pcrIdx = 1;
//			pcrComp.setPcrValue(pcrIdx, context_.getTpmObject().pcrRead(pcrIdx));
//			pcrComp.setPcrLocality(TcTpmConstants.TPM_LOC_ZERO);
			TcIPcrComposite pcrComp = null;
			
			
			TcIRsaKey storageKey = context_.createRsaKeyObject(TcTssConstants.TSS_KEY_TYPE_STORAGE
					| TcTssConstants.TSS_KEY_SIZE_2048 | TcTssConstants.TSS_KEY_AUTHORIZATION);
			TestDefines.keyUsgPolicy.assignToObject(storageKey);
			TestDefines.keyMigPolicy.assignToObject(storageKey);
			storageKey.createKey(srk_, pcrComp);
			storageKey.loadKey(srk_);

			TcIRsaKey certifyKey = context_.createRsaKeyObject(TcTssConstants.TSS_KEY_SIZE_2048
					| TcTssConstants.TSS_KEY_TYPE_SIGNING | TcTssConstants.TSS_KEY_MIGRATABLE |
					TcTssConstants.TSS_KEY_AUTHORIZATION);
			TestDefines.keyUsgPolicy.assignToObject(certifyKey);
			TestDefines.keyMigPolicy.assignToObject(certifyKey);
			certifyKey.createKey(srk_, pcrComp);
			certifyKey.loadKey(srk_);

			TcTssValidation validation = storageKey.certifyKey(certifyKey, null);
			
						
		} catch (Exception e) {
			if (PRINT_TRACE) {
				Log.err(e);
			}
			e.printStackTrace();
			assertTrue("certify key (without nonce) failed", false);
		}
	}

	public void testCertifyKeyAndValidate()
	{
		try {
			if (tpmManufactuerIs(TPM_MAN_IFX)) {
				TcITpm tpm = context_.getTpmObject();
				TcTpmCapVersionInfo versionInfo = new TcTpmCapVersionInfo(tpm.getCapability(TcTssConstants.TSS_TPMCAP_VERSION_VAL, null));
				if (versionInfo.getVersion().getRevMajor() <= 3 &&
						versionInfo.getVersion().getRevMinor() <= 16) {
					// IFX TPM's prior to revision 3.17 calculate the signature over
					// the entire TPM_STORE_PUBKEY structure instead of just the modulus,
					// therefore it can't be validated
					Log.info("skipping testCertifyKeyAndValidate() on IFX TPM's with revision < 3.17!");
					return;
				}
			}

			TcIPcrComposite pcrComp = null;


			TcIRsaKey storageKey = context_.createRsaKeyObject(TcTssConstants.TSS_KEY_TYPE_STORAGE
					| TcTssConstants.TSS_KEY_SIZE_2048 | TcTssConstants.TSS_KEY_AUTHORIZATION |
					TcTssConstants.TSS_KEY_MIGRATABLE);
			TestDefines.keyUsgPolicy.assignToObject(storageKey);
			TestDefines.keyMigPolicy.assignToObject(storageKey);
			storageKey.createKey(srk_, pcrComp);
			storageKey.loadKey(srk_);

			TcIRsaKey certifyKey = context_.createRsaKeyObject(TcTssConstants.TSS_KEY_SIZE_2048
					| TcTssConstants.TSS_KEY_TYPE_SIGNING | TcTssConstants.TSS_KEY_NOT_MIGRATABLE |
					TcTssConstants.TSS_KEY_AUTHORIZATION);
			TestDefines.keyUsgPolicy.assignToObject(certifyKey);
			TestDefines.keyMigPolicy.assignToObject(certifyKey);
			certifyKey.createKey(srk_, pcrComp);
			certifyKey.loadKey(srk_);

			TcTssValidation validationInput = new TcTssValidation();
			TcBlobData nonce = TcBlobData.newByteArray(new byte[20]);
			validationInput.setExternalData(nonce);

			TcTssValidation dataToValidate = storageKey.certifyKey(certifyKey, validationInput);


			//now validate

			//validate nonce
			if (!dataToValidate.getExternalData().equals(nonce)) {
				assertTrue("The nonce does not match the one in the provided validation data!", false);
			}

//			//just to test it via java public keys
//			RSAPublicKey certifiedKey = TcCrypto.pubTpmKeyToJava(
//					new TcTpmPubkey(storageKey.getPubKey()));
//			RSAPublicKey certifyingKey = TcCrypto.pubTpmKeyToJava(
//					new TcTpmPubkey(certifyKey.getPubKey()));
//
//
//			//check if if certifiedKey matches the information in plainData
//			TcTpmPubkey pubKey = TcCrypto.pubJavaToTpmKey(certifiedKey);
//			TcBlobData pubKeyAsBlob = pubKey.getPubKey().getKey();
//			TcBlobData pubKeyDigest = pubKeyAsBlob.sha1();

			//without java public keys
			TcTpmPubkey pubKey = new TcTpmPubkey(storageKey.getPubKey());
			TcBlobData pubKeyAsBlob = pubKey.getPubKey().getKey();
			TcBlobData pubKeyDigest = pubKeyAsBlob.sha1();

			//TODO check which TcTpmCertifyInfo to use depending on pcrs needed
			// for the keys that are used
			TcBlobData plainData = dataToValidate.getData();
			TcTpmCertifyInfo certifiedData =  new TcTpmCertifyInfo(plainData);
			TcBlobData certifiedDataPubKeyDigest = certifiedData.getPubKeyDigest().getDigest();
			if (!pubKeyDigest.equals(certifiedDataPubKeyDigest)) {
				assertTrue("Digest of the certified key does not match the one in the provided validation data!", false);
			}

			Signature sig = Signature.getInstance("SHA1withRSA");
//			sig.initVerify(certifyingKey);
			sig.initVerify(TcCrypto.pubTpmKeyToJava(
					new TcTpmPubkey(certifyKey.getPubKey())));
			sig.update(dataToValidate.getData().asByteArray());
			boolean valid = sig.verify(dataToValidate.getValidationData().asByteArray());

			assertTrue("Signature could not be verified!",valid);

		} catch (Exception e) {
			if (PRINT_TRACE) {
				Log.err(e);
			}
			e.printStackTrace();
			assertTrue("Certify key and validate failed!", false);
		}

	}

	
//	/*************************************************************************************************
//	 * Tries to certify (sign) a public key.
//	 */
//	public void testCertifyKeyAndValidate()
//	{
//		try {
//			
////			context_.setAttribUint32(TcTssConstants.TSS_TSPATTRIB_CONTEXT_VERSION_MODE, 0,
////					TcTssConstants.TSS_TSPATTRIB_CONTEXT_VERSION_V1_2);
//
////			TcIPcrComposite pcrComp = context_.createPcrCompositeObject(TcTssConstants.TSS_PCRS_STRUCT_INFO_LONG);
////			long pcrIdx = 1;
////			pcrComp.setPcrValue(pcrIdx, context_.getTpmObject().pcrRead(pcrIdx));
////			pcrComp.setPcrLocality(TcTpmConstants.TPM_LOC_ZERO);
//			TcIPcrComposite pcrComp = null;
//			
//			
//			TcIRsaKey storageKey = context_.createRsaKeyObject(TcTssConstants.TSS_KEY_TYPE_STORAGE
//					| TcTssConstants.TSS_KEY_SIZE_2048);
//			TestDefines.keyUsgPolicy.assignToObject(storageKey);
//			TestDefines.keyMigPolicy.assignToObject(storageKey);
//			storageKey.createKey(srk_, pcrComp);
//			storageKey.loadKey(srk_);
//
//			TcIRsaKey certifyKey = context_.createRsaKeyObject(TcTssConstants.TSS_KEY_SIZE_2048
//					| TcTssConstants.TSS_KEY_TYPE_SIGNING | TcTssConstants.TSS_KEY_MIGRATABLE);
//			TestDefines.keyUsgPolicy.assignToObject(certifyKey);
//			TestDefines.keyMigPolicy.assignToObject(certifyKey);
//			certifyKey.createKey(srk_, pcrComp);
//			certifyKey.loadKey(srk_);
//
//			TcBlobData nonceBlob = TcBlobData.newUINT32((long)Math.random()*Integer.MAX_VALUE).sha1();
//			TcTssValidation validationInput = new TcTssValidation();
//			validationInput.setExternalData(nonceBlob);
//			
//			TcTssValidation validation = storageKey.certifyKey(certifyKey, validationInput);
//			
//			assertTrue("Could not validate key certification.",certificateValidation(validation, certifyKey, storageKey, nonceBlob));
//						
//		} catch (Exception e) {
//			if (PRINT_TRACE) {
//				Log.err(e);
//			}
//			e.printStackTrace();
//			assertTrue("certify key (without nonce) failed", false);
//		}
//	}
//	
//	
//	// Thanks to Maksim Dajakov for this example
//	private boolean certificateValidation(TcTssValidation certifyValidationData, TcIRsaKey certifyKey, TcIRsaKey certifiedKey, TcBlobData nonceBlob){
//
//		boolean validationSuccesfull = true;
//
//		try {
//			
//			// First, recalculate the signature on the validationData 
//			
//			TcBlobData pubBlob = certifyKey.getAttribData(TcTssConstants.TSS_TSPATTRIB_KEY_BLOB, TcTssConstants.TSS_TSPATTRIB_KEYBLOB_PUBLIC_KEY);
//			TcTpmPubkey pubStruct = new TcTpmPubkey(pubBlob);
//			TcBlobData pubKeyBlob = pubStruct.getPubKey().getKey();
//
//			//Since we do not actually transfer the values use the local variables
//			TcBlobData plainData = certifyValidationData.getData();
//			TcBlobData certifySignature = certifyValidationData.getValidationData();
//
//			pubKeyBlob.prepend(TcBlobData.newBYTE(((byte) 0)));  // BigInteger requires a leading sign-byte
//			RSAPublicKeySpec pubEkSpec = new RSAPublicKeySpec(new BigInteger(pubKeyBlob.asByteArray()),new BigInteger("65537")); // 65537 is TPM default
//
//			RSAPublicKey pubKeyJava = (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(pubEkSpec);
//
//			TcTpmPubkey pubAikStruct = TcCrypto.pubJavaToTpmKey(pubKeyJava);
//			TcIRsaKey pubAik = context_.createRsaKeyObject(TcTssConstants.TSS_KEY_EMPTY_KEY);
//			pubAik.setAttribData(TcTssConstants.TSS_TSPATTRIB_KEY_BLOB, TcTssConstants.TSS_TSPATTRIB_KEYBLOB_PUBLIC_KEY, pubAikStruct.getEncoded());
//
//			pubAik.setAttribUint32(TcTssConstants.TSS_TSPATTRIB_KEY_INFO, TcTssConstants.TSS_TSPATTRIB_KEYINFO_ENCSCHEME, TcTssConstants.TSS_ES_NONE);
//			pubAik.setAttribUint32(TcTssConstants.TSS_TSPATTRIB_KEY_INFO, TcTssConstants.TSS_TSPATTRIB_KEYINFO_SIGSCHEME, TcTssConstants.TSS_SS_RSASSAPKCS1V15_SHA1);
//
//			TcIHash hash = context_.createHashObject(TcTssConstants.TSS_HASH_SHA1);
//
//			hash.setHashValue(plainData.sha1());
//			hash.verifySignature(certifySignature, pubAik);
//
//			
//			//Now verify the certification information
//			
//			 TcTpmCertifyInfo certifiedData =  new TcTpmCertifyInfo(plainData);
//
//			
//			 //Verify the bind public key digests
//			 		 
//			 			 
//			 TcBlobData CIKeyDigest = certifiedData.getPubKeyDigest().getDigest();
//			 System.out.println ("Ceritified data public key digest : "+ CIKeyDigest.toHexString());
//
//			 TcTpmPubkey certifiedPubKey = new TcTpmPubkey(certifiedKey.getPubKey());
//			 TcBlobData certifiedPubKeyDigest = certifiedPubKey.getPubKey().getKey().sha1();
//
//			 System.out.println ("CertifiedKey public key : "+ certifiedKey.getPubKey().toString());
//			 System.out.println ("CertifiedKey public key digest : "+ certifiedPubKeyDigest.toHexString());
//
//			 if (!CIKeyDigest.equals(certifiedPubKeyDigest)) validationSuccesfull = false;
//
//			 //Verify the nonce
//
//			 TcBlobData CInonce = certifiedData.getData().getNonce();
////			 System.out.println ("Ceritified nonce : "+ CInonce.toHexString());
//
//			 if (!CInonce.equals(nonceBlob)) validationSuccesfull = false;
//
//		} catch (TcTssException e) {
//
//			validationSuccesfull = false;
//
//			e.printStackTrace();
//			
//		} catch (InvalidKeySpecException e) {	//For the RSA key handling
//			e.printStackTrace();
//		} catch (NoSuchAlgorithmException e) {
//			e.printStackTrace();
//		}
//
//		return validationSuccesfull;
//	}

	/*************************************************************************************************
	 * Tries to load a key using the key blob.
	 */
	public void testLoadKeyByBlob()
	{
		try {
			TcIRsaKey key = context_.createRsaKeyObject(TcTssConstants.TSS_KEY_TYPE_LEGACY
					| TcTssConstants.TSS_KEY_VOLATILE | TcTssConstants.TSS_KEY_SIZE_2048);//  | TcTssConstants.TSS_KEY_STRUCT_KEY12);  
			key.setAttribUint32(TcTssConstants.TSS_TSPATTRIB_KEY_INFO,
					TcTssConstants.TSS_TSPATTRIB_KEYINFO_SIGSCHEME, TcTssConstants.TSS_SS_RSASSAPKCS1V15_DER);
			key.setAttribUint32(TcTssConstants.TSS_TSPATTRIB_KEY_INFO,
					TcTssConstants.TSS_TSPATTRIB_KEYINFO_ENCSCHEME, TcTssConstants.TSS_ES_RSAESPKCSV15);
			TestDefines.keyUsgPolicy.assignToObject(key);
			TestDefines.keyMigPolicy.assignToObject(key);
			key.createKey(srk_, null);
			key.loadKey(srk_);
			
			TcBlobData bd = key.getAttribData(TcTssConstants.TSS_TSPATTRIB_KEY_BLOB,
					TcTssConstants.TSS_TSPATTRIB_KEYBLOB_BLOB);
			
			context_.loadKeyByBlob(srk_, bd);
			key.unloadKey();
		} catch (TcTssException e) {
			if (PRINT_TRACE) {
				Log.err(e);
			}
			assertTrue("loading keyblob failed", false);
		}
	}
	
	
	/**
	 * Verify that the public key really belongs to the private key. Do this with 
	 * generating some random data, hash it and sign it. Then try to verify 
	 * with the given public key.
	 * Note: This code can be used to check if an arbitrary public key belongs to
	 * a private key stored by the TPM/KCM.
	 */
	public void testVerifySingingKey() {

		try {
			// create new signing key container
			TcIRsaKey signKey = context_.createRsaKeyObject( //
					TcTssConstants.TSS_KEY_SIZE_2048 | //
							TcTssConstants.TSS_KEY_TYPE_SIGNING | //
							TcTssConstants.TSS_KEY_MIGRATABLE |
							TcTssConstants.TSS_KEY_AUTHORIZATION);

			
			signKey.setAttribUint32(TcTssConstants.TSS_TSPATTRIB_KEY_INFO, TcTssConstants.TSS_TSPATTRIB_KEYINFO_SIGSCHEME, TcTssConstants.TSS_SS_RSASSAPKCS1V15_SHA1);
			
			
			// set secret for signing key
			TestDefines.keyUsgPolicy.assignToObject(signKey);
			TestDefines.keyMigPolicy.assignToObject(signKey);

			// create singing key and load it
			signKey.createKey(srk_, null);
			signKey.loadKey(srk_);

			// get public part of signKey
			TcTpmPubkey pubSignKey = new TcTpmPubkey(signKey.getAttribData(TcTssConstants.TSS_TSPATTRIB_KEY_BLOB,
					TcTssConstants.TSS_TSPATTRIB_KEYBLOB_PUBLIC_KEY));
			
			// convert public TPM key into java key
			PublicKey pubSignKeyJava = TcCrypto.pubTpmKeyToJava(pubSignKey);

			// generate random data and create hash object with it.
			TcBlobData random = context_.getTpmObject().getRandom(128);
			TcIHash hash = context_.createHashObject(TcTssConstants.TSS_HASH_SHA1);
			hash.updateHashValue(random);

			// sign the hash object with the private signing key (take place inside the TPM)
			TcBlobData signature = hash.sign(signKey);

			// try to verify signature (in Java) with the public key
			try {
				Signature sig = Signature.getInstance("SHA1withRSA");

				// assign public key
				sig.initVerify(pubSignKeyJava);
				
				// assign hash as data value
				sig.update(random.asByteArray());
				
				boolean verificationOk = sig.verify(signature.asByteArray());
				
				assertTrue("Verification of signature failed.", verificationOk);
			} catch (Exception e) {
				Log.err(e);
				assertTrue("unable to do verification of signature", false);
			}
		} catch (TcTssException e) {
			if (PRINT_TRACE) {
				Log.err(e);
			}
			assertTrue("unable to do verification of signature", false);
		}
	}


	public void testWrapKey() {

		try {


			TcIRsaKey rsaKey = context_.createRsaKeyObject( //
					TcTssConstants.TSS_KEY_SIZE_2048
					| TcTssConstants.TSS_KEY_TYPE_LEGACY
					| TcTssConstants.TSS_KEY_VOLATILE
					| TcTssConstants.TSS_KEY_MIGRATABLE
					| TcTssConstants.TSS_KEY_AUTHORIZATION);

			TestDefines.keyUsgPolicy.assignToObject(rsaKey);
			TestDefines.keyMigPolicy.assignToObject(rsaKey);

			KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
			generator.initialize(2048);
			KeyPair pair = generator.generateKeyPair();

			TcTpmPubkey pubKeyStruct = TcCrypto.pubJavaToTpmKey((RSAPublicKey)pair.getPublic());

			rsaKey.setAttribData(TcTssConstants.TSS_TSPATTRIB_KEY_BLOB,
					TcTssConstants.TSS_TSPATTRIB_KEYBLOB_PUBLIC_KEY,
					pubKeyStruct.getEncoded());

			rsaKey.setAttribUint32(TcTssConstants.TSS_TSPATTRIB_KEY_INFO,
					TcTssConstants.TSS_TSPATTRIB_KEYINFO_SIGSCHEME,
					TcTssConstants.TSS_SS_RSASSAPKCS1V15_SHA1);
			rsaKey.setAttribUint32(TcTssConstants.TSS_TSPATTRIB_KEY_INFO,
					TcTssConstants.TSS_TSPATTRIB_KEYINFO_ENCSCHEME,
					TcTssConstants.TSS_ES_RSAESOAEP_SHA1_MGF1);


			RSAPrivateCrtKey privKey = (RSAPrivateCrtKey) pair.getPrivate();
			TcBlobData privAsBlob = TcBlobData.newByteArray(TcCrypto.privJavaPrimePToByte(privKey));

			rsaKey.setAttribData(TcTssConstants.TSS_TSPATTRIB_KEY_BLOB,
					TcTssConstants.TSS_TSPATTRIB_KEYBLOB_PRIVATE_KEY,
					privAsBlob);

			//create a storage key
			TcIRsaKey storageKey = context_.createRsaKeyObject( //
					TcTssConstants.TSS_KEY_SIZE_2048
					| TcTssConstants.TSS_KEY_TYPE_STORAGE
					| TcTssConstants.TSS_KEY_VOLATILE
					| TcTssConstants.TSS_KEY_NOT_MIGRATABLE
					| TcTssConstants.TSS_KEY_AUTHORIZATION);
			TestDefines.keyUsgPolicy.assignToObject(storageKey);
			TestDefines.keyMigPolicy.assignToObject(storageKey);
			storageKey.createKey(srk_, null);
			storageKey.loadKey(srk_);

			rsaKey.wrapKey(storageKey, null);
			rsaKey.loadKey(storageKey);


		} catch (Exception e) {
			Log.err(e);
		}

	}
	
}
