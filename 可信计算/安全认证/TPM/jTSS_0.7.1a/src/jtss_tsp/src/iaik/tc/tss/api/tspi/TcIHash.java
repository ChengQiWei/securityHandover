/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.api.tspi;


import iaik.tc.tss.api.constants.tsp.TcTssConstants;
import iaik.tc.tss.api.exceptions.common.TcTssException;
import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.tss.api.structs.tpm.TcTpmDigest;
import iaik.tc.tss.api.structs.tsp.TcTssValidation;

/**
 * A hash value represents a unique value corresponding to a particular set of bytes. This class
 * provides a cryptographically secure way to use these functions for digital signature operations.
 */
public interface TcIHash extends TcIWorkingObject, TcIAttributes {

	/*************************************************************************************************
	 * This method signs the hash data of the object with the provided signing key.
	 * 
	 * The data to be signed must be set previously by calling
	 * 
	 * @link {@link TcIHash#setHashValue(TcBlobData)} or {@link TcIHash#updateHashValue(TcBlobData)}.
	 * 
	 * @TSS_V1 162
	 * 
	 * @TSS_1_2_EA 354
	 * 
	 * @param key Key object which should be used for the signature.
	 * 
	 * @return The resulting signature data.
	 * 
	 * 
	 */
	public TcBlobData sign(final TcIRsaKey key) throws TcTssException;


	/*************************************************************************************************
	 * This method verifies the hash value of the hash object with a given signature. If no exception
	 * is thrown, the signature verification could be done successfully.
	 * 
	 * @TSS_V1 164
	 * 
	 * @TSS_1_2_EA 355
	 * 
	 * @param signature The signature to be verified.
	 * @param key The key which should be used for the signature verification.
	 * 
	 * 
	 */
	public void verifySignature(final TcBlobData signature, final TcIRsaKey key)
		throws TcTssException;


	/*************************************************************************************************
	 * This method sets the hash value of the hash object.
	 * 
	 * @TSS_V1 165
	 * 
	 * @TSS_1_2_EA 356
	 * 
	 * @param hashValue The hash value to be set.
	 * 
	 * 
	 */
	public void setHashValue(final TcBlobData hashValue) throws TcTssException;


	/*************************************************************************************************
	 * This method returns the hash value of the hash object.
	 * 
	 * @TSS_V1 166
	 * 
	 * @TSS_1_2_EA 357
	 * 
	 * @return Blob containing the hash data.
	 * 
	 * 
	 */
	public TcBlobData getHashValue() throws TcTssException;


	/*************************************************************************************************
	 * This method updates the hash object with new data. This method can only be called if the hash
	 * object was initialized as a with the {@link TcTssConstants#TSS_HASH_SHA1} init flag.
	 * 
	 * Update means that that the provided data is appended to an internal buffer that already holds
	 * the data from previous update operations. The SHA1 hash of this internal buffer can be obtained
	 * using the {@link TcIHash#getHashValue()} method. Calling updateHashValue(a) and
	 * updateHashValue(b) is equivalent to updateHashValue(a + b).
	 * 
	 * @TSS_V1 167
	 * 
	 * @TSS_1_2_EA 358
	 * 
	 * @param data Blob containing the data to be updated.
	 * 
	 * 
	 */
	public void updateHashValue(final TcBlobData data) throws TcTssException;


	/** This method is similar to a time stamp: it associates a tick value with a blob,
	 *  indicating that the blob existed at some point earlier than the time corresponding to
	 *   the tick value. 
	 * 
	 * @TSS_1_2_EA 374
	 * 
	 * @param key Key to sign the time stamp
	 * @param validationData holds a nonce incorporated in stamping in the externalData_ field
	 * @return  Object array of
	 *          [0] validationData additionally externalData_ it now holds the signature in the field validationData_ 
	 *          [1] currentTicks at the time of stamping
	 * 
	 */
	public Object[] tickStampBlob(final TcIRsaKey key, final TcTssValidation validationData)
	throws TcTssException;

}