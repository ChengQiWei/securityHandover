/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.impl.csp;



import iaik.tc.utils.misc.CheckPrecondition;
import iaik.tc.utils.misc.Utils;

import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * This class is the CSP (crypto service provider) of the TSS. That means that all cryptographic
 * functionality required by  the TSS is centralized in this class. The intention is to make
 * porting to different crypto libraries as simple as possible. 
 * 
 * To allow compilation of the API definition (without implementation) (i.e. for Wrapper translation with GCJ),
 *  the TcCrypto class has been split in a basic part, and a full implementation that extends it. 
 * TcBasicCrypto is compatible with GCJ.
 * 
 */
public class TcBasicCrypto {

	protected static boolean startupChecksOk_ = false;

	// while there is no daemon startup function yet, we're calling the check from the static block
	// TODO (CSP): remove this as soon as TCS is a real daemon
	static {
		checkCryptoAvailability();
	}


	public static boolean checkCryptoAvailability()
	{
		// TODO (csp): add checks for all required JCE crypto functions
		// This functions should be called at startup of the TCS (or loading of the TSP)
		// to ensure that all required crypto capabilities are provided by the JCE. If not,
		// the TCS (or TSP) is to be terminated. This reliefs us from catching
		// NoSuchAlgorithmException all over the place (if the startup checks succeed, we
		// can safely assume the availability of the required algorithms later on).

		startupChecksOk_ = true;
		return startupChecksOk_;
	}


	/*************************************************************************************************
	 * This method computes the sha1 hash of the provided byte array.
	 */
	public static byte[] sha1(final byte[] input)
	{
		if (!startupChecksOk_) {
			throw new IllegalStateException("Cryptographic checks have not been executed at startup!");
		}

		byte[] digest = null;
		try {
			MessageDigest md = MessageDigest.getInstance("SHA-1");
			md.update(input);
			digest = md.digest();
		} catch (NoSuchAlgorithmException e) {
			// can be ignored since startup checks were OK
		}
		return digest;
	}


	/*************************************************************************************************
	 */
	public static byte[] hmacSha1(byte[] data, byte[] key)
	{
		if (!startupChecksOk_) {
			throw new IllegalStateException("Cryptographic checks have not been executed at startup!");
		}

		byte[] retVal = null;

		try {
			SecretKey secKey = new SecretKeySpec(key, "HmacSha1");
			Mac mac = Mac.getInstance("HmacSha1");
			mac.init(secKey);
			mac.update(data);
			retVal = mac.doFinal();
		} catch (InvalidKeyException e) {
			String msg = "Invalid HmacSha1 key." + Utils.getNL() + "InvalidKeyException: "
					+ e.getMessage();
			throw new IllegalArgumentException(msg);
		} catch (NoSuchAlgorithmException e) {
			// can be ignored since startup checks were OK
		}

		return retVal;
	}


	/*************************************************************************************************
	 */
	public static byte[] xor(byte[] data, byte[] key)
	{
		CheckPrecondition.equal(data.length, 20, "data.length");
		CheckPrecondition.equal(key.length, 20, "key.length");

		byte[] retVal = new byte[data.length];
		System.arraycopy(data, 0, retVal, 0, data.length);

		for (int i = 0; i < retVal.length; i++) {
			retVal[i] ^= key[i];
		}

		return retVal;
	}


}