/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.impl.csp;


import iaik.tc.tss.api.constants.tcs.TcTcsErrors;
import iaik.tc.tss.api.constants.tpm.TcTpmConstants;
import iaik.tc.tss.api.exceptions.common.TcTssException;
import iaik.tc.tss.api.exceptions.tcs.TcTcsException;
import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.tss.api.structs.tpm.TcTpmKeyParms;
import iaik.tc.tss.api.structs.tpm.TcTpmNonce;
import iaik.tc.tss.api.structs.tpm.TcTpmPubkey;
import iaik.tc.tss.api.structs.tpm.TcTpmRsaKeyParms;
import iaik.tc.tss.api.structs.tpm.TcTpmStorePubkey;
import iaik.tc.utils.misc.CheckPrecondition;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Random;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.SecretKeySpec;

/**
 * This class is the CSP (crypto service provider) of the TSS. That means that all cryptographic
 * functionality required by  the TSS is centralized in this class. The intention is to make
 * porting to different crypto libraries as simple as possible. 
 * 
 * * To allow compilation of the API definition (without implementation) (i.e. for Wrapper translation with GCJ),
 *  the TcCrypto class has been split in a basic part, and a full implementation that extends it. 
 * TcCrypto is not compatible with GCJ (without additional crypto libs).
 *
 */
public class TcCrypto extends TcBasicCrypto {


	/*************************************************************************************************
	 */
	public static TcBlobData pubEncryptRsaOaepSha1Mgf1(TcTpmPubkey pubKey, TcBlobData plainData)
		throws TcTcsException
	{
		if (!startupChecksOk_) {
			throw new IllegalStateException("Cryptographic checks have not been executed at startup!");
		}

		TcBlobData encData = null;

		RSAPublicKey pubKeyJava = pubTpmKeyToJava(pubKey);
		
		try {
			//System.setSecurityManager(null);
 

	       //   Class cls = Class.forName("iaik.security.provider.IAIK");

	          OAEPParameterSpec oaepSpec = new OAEPParameterSpec("SHA1", "MGF1", new MGF1ParameterSpec(
					"SHA1"), new PSource.PSpecified("TCPA".getBytes("ASCII")));
			Cipher rsaCa = Cipher.getInstance("RSA/ECB/OAEPWithSHA1AndMGF1Padding"); //FIXXME
			rsaCa.init(Cipher.ENCRYPT_MODE, pubKeyJava, oaepSpec);
			encData = TcBlobData.newByteArray(rsaCa.doFinal(plainData.asByteArray()));
		} catch (GeneralSecurityException e) {
			String msg = "GeneralSecurityException: " + e.getMessage();
			throw new TcTcsException(TcTcsErrors.TCS_E_INTERNAL_ERROR, msg);
		} catch (UnsupportedEncodingException e) {
			// can be ignored since startup checks were OK
		} catch (IllegalStateException e) {
			String msg = "IllegalStateException: " + e.getMessage();
			throw new TcTcsException(TcTcsErrors.TCS_E_INTERNAL_ERROR, msg);
		}

		return encData;
	}


	/*************************************************************************************************
	 */
	public static TcBlobData pubEncryptRsaEcbPkcs1Padding(TcTpmPubkey pubKey, TcBlobData plainData)
		throws TcTcsException
	{
		if (!startupChecksOk_) {
			throw new IllegalStateException("Cryptographic checks have not been executed at startup!");
		}

		TcBlobData encData = null;

		try {
			RSAPublicKey pubKeyJava = pubTpmKeyToJava(pubKey); 

			Cipher rsaCa = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			rsaCa.init(Cipher.ENCRYPT_MODE, pubKeyJava);
			encData = TcBlobData.newByteArray(rsaCa.doFinal(plainData.asByteArray()));
		} catch (GeneralSecurityException e) {
			String msg = "GeneralSecurityException: " + e.getMessage();
			throw new TcTcsException(TcTcsErrors.TCS_E_INTERNAL_ERROR, msg);
		} catch (IllegalStateException e) {
			String msg = "IllegalStateException: " + e.getMessage();
			throw new TcTcsException(TcTcsErrors.TCS_E_INTERNAL_ERROR, msg);
		}

		return encData;
	}


	/*************************************************************************************************
	 */
	public static TcBlobData decryptRsaEcbPkcs1Padding(TcTpmPubkey pubKey, TcBlobData inputData)
		throws TcTcsException
	{
		if (!startupChecksOk_) {
			throw new IllegalStateException("Cryptographic checks have not been executed at startup!");
		}

		TcBlobData retVal = null;

		try {
			RSAPublicKey pubKeyJava = pubTpmKeyToJava(pubKey); 

			Cipher rsaCa = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			rsaCa.init(Cipher.DECRYPT_MODE, pubKeyJava);
			retVal = TcBlobData.newByteArray(rsaCa.doFinal(inputData.asByteArray()));
		} catch (GeneralSecurityException e) {
			String msg = "GeneralSecurityException: " + e.getMessage();
			throw new TcTcsException(TcTcsErrors.TCS_E_INTERNAL_ERROR, msg);
		} catch (IllegalStateException e) {
			String msg = "IllegalStateException: " + e.getMessage();
			throw new TcTcsException(TcTcsErrors.TCS_E_INTERNAL_ERROR, msg);
		}

		return retVal;
	}


	/*************************************************************************************************
	 * This method encrypts or decrypts the given data blob using the given symKey and the IV. The
	 * mode of operation is fixed to CBC and the padding is set to PKCS5.
	 */
	protected static TcBlobData symmetricCbcPkcs5Pad(String algo, int mode, TcBlobData symKey,
			TcBlobData iv, TcBlobData inputData) throws TcTcsException
	{
		if (!startupChecksOk_) {
			throw new IllegalStateException("Cryptographic checks have not been executed at startup!");
		}
		CheckPrecondition.notNull(algo, "algo");
		if (algo != "AES" && algo != "DESede") {
			throw new TcTcsException(TcTcsErrors.TCS_E_BAD_PARAMETER,
					"Illegal symmetric algorithm (only AES and DESede (3DES) are supported).");
		}
		if (mode != Cipher.ENCRYPT_MODE && mode != Cipher.DECRYPT_MODE) {
			throw new TcTcsException(TcTcsErrors.TCS_E_BAD_PARAMETER,
					"Illegal mode for symmetric algorithm.");
		}
		CheckPrecondition.notNull(inputData, "inputData");
		CheckPrecondition.notNull(symKey, "symKey");
		CheckPrecondition.notNull(iv, "iv");

		TcBlobData retVal = null;

		try {
			Cipher aesCa = Cipher.getInstance(algo + "/CBC/PKCS5Padding");
			SecretKeySpec keySpec = new SecretKeySpec(symKey.asByteArray(), algo);
			IvParameterSpec ivParameterSpec = new IvParameterSpec(iv.asByteArray());
			aesCa.init(mode, keySpec, ivParameterSpec);
			retVal = TcBlobData.newByteArray((aesCa.doFinal(inputData.asByteArray())));
		} catch (NoSuchAlgorithmException e) {
			// can be ignored since startup checks were OK
		} catch (NoSuchPaddingException e) {
			// can be ignored since startup checks were OK
		} catch (Exception e) {
			e.printStackTrace();
			throw new TcTcsException(TcTcsErrors.TCS_E_INTERNAL_ERROR, e.getMessage());
		}

		return retVal;
	}


	/*************************************************************************************************
	 * This method encrypts the given data blob using the given symKey and the IV. The mode of
	 * operation is fixed to CBC and the padding is set to PKCS5.
	 */
	public static TcBlobData encryptSymmetricCbcPkcs5Pad(String algo, TcBlobData symKey,
			TcBlobData iv, TcBlobData plainData) throws TcTcsException
	{
		return symmetricCbcPkcs5Pad(algo, Cipher.ENCRYPT_MODE, symKey, iv, plainData);

	}


	/*************************************************************************************************
	 * This method decrypts the given data blob using the given symKey and the IV. The mode of
	 * operation is fixed to CBC and the padding is set to PKCS5.
	 */
	public static TcBlobData decryptSymmetricCbcPkcs5Pad(String algo, TcBlobData symKey,
			TcBlobData iv, TcBlobData encData) throws TcTcsException
	{
		return symmetricCbcPkcs5Pad(algo, Cipher.DECRYPT_MODE, symKey, iv, encData);
	}


	/*************************************************************************************************
	 * This method calls the JCE to create a new 3DES key. The key is returned as a blob object.
	 */
	public static TcBlobData create3DESkey()
	{
		if (!startupChecksOk_) {
			throw new IllegalStateException("Cryptographic checks have not been executed at startup!");
		}

		TcBlobData retVal = null;

		try {
			KeyGenerator desEdeGen = KeyGenerator.getInstance("DESede");
			SecretKey desEdeKey = desEdeGen.generateKey();

			SecretKeyFactory desEdeFactory = SecretKeyFactory.getInstance("DESede");
			DESedeKeySpec desEdeSpec = (DESedeKeySpec) desEdeFactory.getKeySpec(desEdeKey,
					DESedeKeySpec.class);
			byte[] rawDesEdeKey = desEdeSpec.getKey();

			retVal = TcBlobData.newByteArray(rawDesEdeKey);
		} catch (NoSuchAlgorithmException e) {
			// can be ignored since startup checks were successful
		} catch (InvalidKeySpecException e) {
			// can be ignored since startup checks were successful
		}

		return retVal;
	}


	/*************************************************************************************************
	 * This method calls the JCE to create a new AES key. The key is returned as a blob object.
	 * 
	 * @param keysize Key size in bits.
	 */
	public static TcBlobData createAESkey(int keysize) throws TcTssException
	{
		if (!startupChecksOk_) {
			throw new IllegalStateException("Cryptographic checks have not been executed at startup!");
		}

		if (keysize != 128 && keysize != 192 && keysize != 256) {
			throw new TcTcsException(TcTcsErrors.TCS_E_BAD_PARAMETER, "Illegal AES key size.");
		}

		TcBlobData retVal = null;

		try {
			KeyGenerator aesGen = KeyGenerator.getInstance("AES");
			aesGen.init(keysize);
			SecretKey aesKey = aesGen.generateKey();

			if (!aesKey.getFormat().equals("RAW")) {
				throw new TcTcsException(TcTcsErrors.TCS_E_INTERNAL_ERROR,
						"Unable to get RAW AES key. Wrong key format.");
			}

			return TcBlobData.newByteArray(aesKey.getEncoded());

		} catch (NoSuchAlgorithmException e) {
			// can be ignored since startup checks were successful
		}

		return retVal;
	}


	/*************************************************************************************************
	 * This method returns numBytes bytes of random data.
	 * 
	 * @return numBytes bytes of random data.
	 */
	public static TcBlobData getRandom(int numBytes)
	{
		Random rnd = new Random();
		byte[] bytes = new byte[numBytes];
		rnd.nextBytes(bytes);
		return TcBlobData.newByteArray(bytes);
	}


	/*************************************************************************************************
	 * This method returns TPM_SHA1BASED_NONCE_LEN bytes of random data.
	 * 
	 * @return numBytes bytes of random data.
	 */
	public static TcTpmNonce createTcgNonce()
	{
		return new TcTpmNonce(getRandom((int) TcTpmConstants.TPM_SHA1BASED_NONCE_LEN));
	}


	/*************************************************************************************************
	 * This method takes a Java RSA public key object and converts it into a TPM public key structure. 
	 */
	public static TcTpmPubkey pubJavaToTpmKey(RSAPublicKey publickey)
	{
		// length of pubkey in bytes
		int pubKeyLen = (publickey.getModulus().toByteArray().length);

		byte[] signedModuls = (publickey).getModulus().toByteArray();

		// Note:
		// The byte array returned by BigInteger.toByteArray()
		// always contains one leading sign bit.
		// Thus, assuming the modulus of an RSA key is always positive,
		// one gets an extra 0x00 byte, a leading sign byte, for moduli
		// which have no space left for this bit.
		// This leading extra byte is removed if present.

		if (signedModuls[0]==0) {
			pubKeyLen -= 1;
		}

		byte[] modulus = new byte[pubKeyLen];
		System.arraycopy(signedModuls, signedModuls.length - (pubKeyLen), modulus, 0, pubKeyLen);

		TcTpmStorePubkey storePubKey = new TcTpmStorePubkey();
		storePubKey.setKey(TcBlobData.newByteArray(modulus));
		storePubKey.setKeyLength(modulus.length);

		// RSA key parameters
		TcTpmRsaKeyParms rsaKeyParms = new TcTpmRsaKeyParms();
		rsaKeyParms.setKeyLength(pubKeyLen*8);
		rsaKeyParms.setNumPrimes(2);

		// key parameters
		// note: this is a TPM level structure; therefore use TPM level constants
		TcTpmKeyParms keyParms = new TcTpmKeyParms();
		keyParms.setAlgorithmID(TcTpmConstants.TPM_ALG_RSA);
		keyParms.setEncScheme((int) TcTpmConstants.TPM_ES_RSAESPKCSv15);
		keyParms.setSigScheme((int) TcTpmConstants.TPM_SS_NONE);
		keyParms.setParms(rsaKeyParms.getEncoded());

		TcTpmPubkey pubKey = new TcTpmPubkey();
		pubKey.setPubKey(storePubKey);
		pubKey.setAlgorithmParms(keyParms);

		return pubKey;
	}


	/*************************************************************************************************
	 * This method takes a TPM public key structure and converts it into a Java RSA public key object. 
	 */
	public static RSAPublicKey pubTpmKeyToJava(TcTpmPubkey pubKey)
	{
		if (!startupChecksOk_) {
			throw new IllegalStateException("Cryptographic checks have not been executed at startup!");
		}

		TcBlobData pubKeyBlob = (TcBlobData)pubKey.getPubKey().getKey().clone();

		// BigInteger requires a leading sign-byte
		pubKeyBlob.prepend(TcBlobData.newBYTE(((byte) 0)));
		RSAPublicKeySpec pubEkSpec = new RSAPublicKeySpec(new BigInteger(pubKeyBlob.asByteArray()),
				new BigInteger("65537"));

		RSAPublicKey pubKeyJava = null;

		try {
			pubKeyJava = (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(pubEkSpec);

		} catch (InvalidKeySpecException e) {
			// can be ignored since startup checks were successful
		} catch (NoSuchAlgorithmException e) {
			// can be ignored since startup checks were successful
		}

		return pubKeyJava;
	}


	/*************************************************************************************************
	 * This method takes a Java RSA private key object and extracts the prime factor P as a byte
	 * array.
	 */
	public static byte[] privJavaPrimePToByte(RSAPrivateCrtKey privateKey) {
		int privKeyLen = (privateKey.getPrimeP().toByteArray().length);

		byte[] signedP = (privateKey).getPrimeP().toByteArray();

		// Note:
		// The byte array returned by BigInteger.toByteArray()
		// always contains one leading sign bit.
		// Thus, assuming the modulus of an RSA key is always positive,
		// one gets an extra 0x00 byte, a leading sign byte, for moduli
		// which have no space left for this bit.
		// This leading extra byte is removed if present.

		if (signedP[0]==0) {
			privKeyLen -= 1;
		}

		byte[] p = new byte[privKeyLen];
		System.arraycopy(signedP, signedP.length - (privKeyLen), p, 0, privKeyLen);

		return p;

	}

}