/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.impl.java.tsp;


import iaik.tc.tss.api.constants.tpm.TcTpmConstants;
import iaik.tc.tss.api.constants.tsp.TcTssConstants;
import iaik.tc.tss.api.constants.tsp.TcTssErrors;
import iaik.tc.tss.api.exceptions.common.TcTssException;
import iaik.tc.tss.api.exceptions.tsp.TcTspException;
import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.tss.api.structs.tcs.TcTcsAuth;
import iaik.tc.tss.api.structs.tpm.TcTpmDigest;
import iaik.tc.tss.api.structs.tpm.TcTpmEncauth;
import iaik.tc.tss.api.structs.tpm.TcTpmNonce;
import iaik.tc.tss.api.structs.tpm.TcTpmSecret;
import iaik.tc.tss.api.structs.tsp.TcTssValidation;
import iaik.tc.tss.api.tspi.TcIContext;
import iaik.tc.tss.api.tspi.TcIPolicy;
import iaik.tc.tss.api.tspi.TcIWorkingObject;
import iaik.tc.tss.impl.csp.TcCrypto;
import iaik.tc.tss.impl.java.tsp.internal.TcTspInternal;

public abstract class TcWorkingObject extends TcAttributes implements TcIWorkingObject {

	/**
	 * Reference to context the object belongs to.
	 */
	protected TcContext context_ = null;


	/*************************************************************************************************
	 */
	protected TcWorkingObject()
	{
		super();
	}


	/*************************************************************************************************
	 */
	protected TcWorkingObject(TcIContext context) throws TcTssException
	{
		super();
		context_ = (TcContext) context;
	}


	/*************************************************************************************************
	 * This method is used to validate the checksum returned by some TPM functions. For some functions
	 * a nonce (antiReplay) is generated that is sent to the TPM as part of the TPM function call. The
	 * TPM appends the nonce to the outgoing data and then hashes the data. This has is returned by
	 * the TPM in the checksum parameter. This method takes the data returned by the TPM as well as
	 * the nonce generated in the TSP and then computes the expected hash. This expected hash is
	 * compared to the checksum received from the TPM
	 * 
	 * @param data The data received from the TPM.
	 * @param antiReplay The nonce that was sent to the TPM.
	 * @param checksum The checksum received from the TPM.
	 * 
	 * @throws @link {@link TcTssException}
	 */
	protected void validateChecksum(final TcTssValidation validationData, final TcTpmDigest checksum)
		throws TcTssException
	{
		TcBlobData expextedHash = validationData.getData();
		if (!checksum.getEncoded().equals(expextedHash.sha1())) {
			throw new TcTspException(TcTssErrors.TSS_E_TSP_AUTHFAIL,
					"Validation error: Checksum returned by the TPM does not match the expected checksum.");
		}
	}

	
	/*************************************************************************************************
	 * Internal method that checks if the context is open. If not, an exception is thrown.
	 * Use this method if you want to ensure that the context object has been properly created and
	 * not yet closed by a CloseContext method call.
	 * Since it is not checked or the context is connected to the TCS, this method is to be used 
	 * in methods where no TPM access is required.
	 */
	protected synchronized void checkContextOpen() throws TcTspException
	{
		if (context_ == null) {
			throw new TcTspException(TcTssErrors.TSS_E_INVALID_OBJ_ACCESS,
					"The context object has been closed.");
		}
	}


	/*************************************************************************************************
	 * This method is called by methods using the context to make sure that the context is not closed 
	 * and properly connected to the TCS.
	 */
	protected synchronized void checkContextOpenAndConnected() throws TcTssException
	{
		checkContextOpen();
		if (!context_.isConnected()) {
			throw new TcTspException(TcTssErrors.TSS_E_NO_CONNECTION, "The context is not connected.");
		}
	}

	
	/*************************************************************************************************
	 * Internal method that checks if the given key handle is a {@link TcTssConstants#NULL_HKEY}. If
	 * yes, a {@link TcTspException} is thrown.
	 */
	protected void checkKeyHandleNotNull(long keyHandle, String keyName) throws TcTssException
	{
		if (keyHandle == TcTssConstants.NULL_HKEY) {
			throw new TcTspException(TcTssErrors.TSS_E_KEY_NOT_LOADED,
					keyName + " is not loaded or key handle is invalid.");
		}
	}
	

	/*************************************************************************************************
	 * Internal helper method that start a new OSAP session, computes the shared session secret and
	 * encrypts the entitySecret (as specified in the policy object) using the shared secret.
	 * 
	 * @return Return values:
	 *         <ul>
	 *         <li> 0 ... OSAP session (TcTcsAuth)
	 *         <li> 1 ... encrypted entity auth (TcTpmEncAuth)
	 *         <li> 2 ... shared secret (TcTpmSecret)
	 *         </ul>
	 */
	protected synchronized Object[] createOsapSession(int entityType, long entityValue,
			TcIPolicy parentPolicy, TcIPolicy entityPolicy) throws TcTssException
	{
		// TODO: policy.getSecret can be null

		if (parentPolicy == null || ((TcPolicy) parentPolicy).getSecret() == null) {
			return new Object[] { null, null, null };
		}
		if (entityPolicy == null || ((TcPolicy) entityPolicy).getSecret() == null) {
			return new Object[] { null, null, null };
		}

		// TODO: currently only XOR encryption is supported; depending on what (1.2) TPMs offer
		// also other symmetric algorithms can be used for OSAP sessions
		entityType |= TcTpmConstants.TPM_ET_XOR;
		
		// get secret from parent policy
		TcBlobData parentSercret = ((TcPolicy) parentPolicy).getSecret();

		// start new OSAP session
		TcTpmNonce nonceOddOSAP = TcCrypto.createTcgNonce();
		Object[] tpmOutData = TcTspInternal.TspOSAP_Internal(context_, entityType, entityValue,
				nonceOddOSAP);
		TcTcsAuth osapAuth = (TcTcsAuth) tpmOutData[0];
		TcTpmNonce nonceEvenOSAP = (TcTpmNonce) tpmOutData[1];

		// compute the ADIP shared secret
		TcBlobData sharedSecret = (TcBlobData) nonceEvenOSAP.getNonce().clone();
		sharedSecret.append(nonceOddOSAP.getNonce());
		// HMAC key is usage secret of data parent key
		sharedSecret = sharedSecret.hmacSha1(parentSercret);

		// generate new nonce odd
		TcTpmNonce nonceOdd = TcCrypto.createTcgNonce();
		osapAuth.setNonceOdd(nonceOdd);

		// XOR key for encrypting secret
		TcBlobData xorKeyData = (TcBlobData) sharedSecret.clone();
		xorKeyData.append(osapAuth.getNonceEven().getNonce());
		xorKeyData = xorKeyData.sha1();

		// XOR encrypt the entity secret
		TcBlobData entitySercret = ((TcPolicy) entityPolicy).getSecret();
		TcTpmEncauth encIdentityAuth = new TcTpmEncauth(entitySercret.xor(xorKeyData));

		return new Object[] { osapAuth, encIdentityAuth, new TcTpmSecret(sharedSecret) };
	}
	

	/************************************************************************************************
	 * This method is called as part of the {@link TcIContext#closeObject(TcIWorkingObject)} method
	 * call. It does object specific close operations. 
	 */
	protected synchronized void closeObject() throws TcTssException
	{
		context_ = null;
	}

	
	/************************************************************************************************
	 * This method closes the object in case the garbage collector re-claims the object and the
	 * object has not been closed yet.
	 */
	protected void finalize() throws Throwable
	{
		if (context_ != null) {
			context_.closeObject(this);
		}
	}
}
