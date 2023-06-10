/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.impl.java.tsp.internal;


import iaik.tc.tss.api.constants.tsp.TcTssErrors;
import iaik.tc.tss.api.exceptions.tsp.TcTspException;
import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.tss.api.structs.tcs.TcTcsAuth;
import iaik.tc.tss.api.structs.tpm.TcTpmDigest;
import iaik.tc.utils.misc.CheckPrecondition;

public class TcTspCommon {

	/*************************************************************************************************
	 * Convenience method converting an UINT32 into a TcBlobData.
	 */
	protected static TcBlobData blobUINT32(long data)
	{
		return TcBlobData.newUINT32(data);
	}


	/*************************************************************************************************
	 * Convenience method converting an UINT16 into a TcBlobData.
	 */
	protected static TcBlobData blobUINT16(int data)
	{
		return TcBlobData.newUINT16(data);
	}


	/*************************************************************************************************
	 * Convenience method converting a byte into a TcBlobData.
	 */
	protected static TcBlobData blobBYTE(short data)
	{
		return TcBlobData.newBYTE(data);
	}


	/*************************************************************************************************
	 * Convenience method converting a byte[] into a TcBlobData.
	 */
	protected static TcBlobData blobByteArray(byte[] data)
	{
		return TcBlobData.newByteArray(data);
	}


	/*************************************************************************************************
	 * Convenience method converting a byte into a TcBlobData.
	 */
	protected static TcBlobData blobBOOL(boolean data)
	{
		return TcBlobData.newBOOL(data);
	}


	/*************************************************************************************************
	 * This method computes the ingoing TPM authorization data. First the, xS elements are
	 * concatenated and SHA1 hashed forming the 1Hx element. The 1Hx to 4hx elements are then
	 * concatenated. This concatenated data is HMACed with authHash as the HMAC key.
	 * 
	 * @param blob1H Array of 1S to nS elements. These are concatenated and hashed into 1H.
	 * @param blob2H The 2H parameter.
	 * @param blob3H The 3H parameter.
	 * @param blob4H The 4H parameter.
	 * 
	 * @param authHash The HMAC key for the HmacSha1 operation performed on the concatenation of 1H to
	 *          4H.
	 * 
	 * @return Returns the HMACed authorization data.
	 */
	protected static TcBlobData computeAuthData(final TcBlobData[] blob1H, final TcBlobData blob2H,
			final TcBlobData blob3H, final TcBlobData blob4H, final TcBlobData authHash)
	{
		CheckPrecondition.notNull(blob1H, "blob1H");
		CheckPrecondition.gtZero(blob1H.length, "blob1H.length");
		CheckPrecondition.notNull(blob2H, "blob2H");
		CheckPrecondition.notNull(blob3H, "blob3H");
		CheckPrecondition.notNull(blob4H, "blob4H");
		CheckPrecondition.notNull(authHash, "authHash");

		TcBlobData combinedBlob1H = TcBlobData.newBlobData(blob1H[0]);
		for (int i = 1; i < blob1H.length; i++) {
			combinedBlob1H.append(blob1H[i]);
		}

		TcBlobData authData = combinedBlob1H.sha1();
		authData.append(blob2H);
		authData.append(blob3H);
		authData.append(blob4H);
		TcBlobData retVal = authData.hmacSha1(authHash);
		return retVal;
	}


	/*************************************************************************************************
	 * This method is an alternative method to compute the authorization data. The only difference is
	 * that the parameters 2H, 3H and 4H are not passed explicitly but implicitly as a TcTpmAuth
	 * instance.
	 */
	protected static TcBlobData computeAuthData(final TcBlobData[] blob1H, final TcTcsAuth blob2to4H,
			final TcBlobData authHash)
	{
		return computeAuthData(blob1H, blob2to4H.getNonceEven().getEncoded(), blob2to4H.getNonceOdd()
				.getEncoded(), blobBOOL(blob2to4H.getContAuthSession()), authHash);
	}


	/*************************************************************************************************
	 * This method computes the expected outgoing authorization value and compares it to the one
	 * actually received from the TPM. Computation is similar to the the computation of the ingoing
	 * authorization values. First, 1S to nS are concatenated and hashed into 1H. Then 1H to 4H are
	 * concatenated. This data is then HMACed (hmacSha1) using hmacKey as the key. The result of the
	 * hmacSha1 operation is then compared to the authorization data received from the TPM.
	 * 
	 * @param blob1H Array of 1S to nS elements. These are concatenated and hashed into 1H.
	 * @param inAuthValues Contains the ingoing nonce odd that was sent to the TPM.
	 * @param outAuthValues Contains the new nonceEven received from the TPM and the
	 *          continueAuthSession flag. Moreover, the outgoing authorization data to be validated is
	 *          held by this parameter.
	 * @param hmacKey The key for the hmacSha1 operation.
	 * 
	 * @throws TcTspException This exception is thrown if the validation of the outgoing authorization
	 *           data fails. Otherwise this method return without further return values.
	 */
	protected static void validateRespAuth(final TcBlobData[] blob1H, final TcTcsAuth inAuthValues,
			final TcTcsAuth outAuthValues, final TcBlobData hmacKey) throws TcTspException
	{
		// compute expected auth data in result blob
		TcBlobData resAuthDataExpected = computeAuthData(blob1H, // 1Hx
				outAuthValues.getNonceEven().getEncoded(), // 2Hx
				inAuthValues.getNonceOdd().getEncoded(), // 3Hx
				TcBlobData.newBOOL(outAuthValues.getContAuthSession()), // 4Hx
				hmacKey); // HMAC key

		// check if the expected auth data matches the one received from the TPM
		boolean isequal = outAuthValues.getHmac().getDigest().equals(resAuthDataExpected); 
		if (!isequal) {
			throw new TcTspException(TcTssErrors.TSS_E_TSP_AUTHFAIL);
		}
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
	 * @throws TcTspException This exception is thrown if the comparison of the expected hash and the
	 *           checksum received from the TPM fails.
	 */
	protected static void validateChecksum(final TcBlobData data, final TcBlobData antiReplay,
			final TcTpmDigest checksum) throws TcTspException
	{
		TcBlobData expextedHash = (TcBlobData) data.clone();
		expextedHash.append(antiReplay);
		if (!checksum.getEncoded().equals(expextedHash.sha1())) {
			throw new TcTspException(TcTssErrors.TSS_E_TSP_AUTHFAIL,
					"Checksum returned by the TPM does not match the expected checksum.");
		}
	}
}
