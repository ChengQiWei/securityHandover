/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.impl.java.tcs.pbg;


import iaik.tc.tss.api.constants.tpm.TcTpmConstants;
import iaik.tc.tss.api.constants.tpm.TcTpmOrdinals;
import iaik.tc.tss.api.exceptions.tcs.TcTddlException;
import iaik.tc.tss.api.exceptions.tcs.TcTpmException;
import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.tss.api.structs.tpm.TcTpmGenericReturnBlob;
import iaik.tc.tss.api.structs.tpm.TcTpmNonce;
import iaik.tc.tss.impl.java.tddl.TcIStreamDest;

public class TcTpmCmdAuthorization extends TcTpmCmdCommon {

	/*************************************************************************************************
	 * The TPM_OIAP command allows the creation of an authorization session handle and the tracking of
	 * the handle by the TPM. The TPM generates the handle and nonce.
	 * 
	 * @param dest The destination where the byte stream is written to.
	 * 
	 * @return The returned Object[] holds the following elements:
	 *         <ul>
	 *         <li> 0 ... TPM return code (Long)
	 *         <li> 1 ... Handle that TPM creates that points to the authorization state. (long)
	 *         <li> 2 ... Nonce generated by TPM (new nonce even). (TcTpmNonce)
	 *         </ul>
	 * 
	 * @throws  TcTpmException This exception indicates that a TPM error has occurred. The specific
	 *           error code id held by the exception.
	 * 
	 * @TPM_V2_R101 169
	 */
	public static Object[] TpmOIAP(TcIStreamDest dest) throws TcTddlException, TcTpmException
	{
		TcBlobData inBlob = blobUINT16(TcTpmConstants.TPM_TAG_RQU_COMMAND);
		inBlob.append(blobUINT32(0)); // paramSize is set later
		inBlob.append(blobUINT32(TcTpmOrdinals.TPM_ORD_OIAP));

		// all params filled in - set the length of the blob
		setParamSize(inBlob);

		// send byte stream
		TcBlobData tpmOutBlob = dest.transmitData(inBlob);
		TcTpmGenericReturnBlob outBlob = new TcTpmGenericReturnBlob(tpmOutBlob);

		// check TPM return code: if call was not successful, an exception is thrown
		handleRetCode(outBlob);

		// decode output values
		Long authHandle = new Long(outBlob.decodeUINT32());
		TcTpmNonce nonceEven = new TcTpmNonce(outBlob);

		return new Object[] { outBlob.getRetCodeAsLong(), authHandle, nonceEven } ;
	}


	/*************************************************************************************************
	 * 
	 * 
	 * @param dest The destination where the byte stream is written to.
	 * @param entityType The type of entity in use
	 * @param entityValue The selection value based on entityType, e.g. a keyHandle #
	 * 
	 * @return The returned Object[] holds the following elements:
	 *         <ul>
	 *         <li> 0 ... TPM return code (Long)
	 *         <li> 1 ... Handle that TPM creates that points to the authorization state. (long)
	 *         <li> 2 ... Nonce generated by TPM and associated with session. (TcTpmNonce)
	 *         <li> 3 ... Nonce generated by TPM and associated with shared secret. (TcTpmNonce)
	 *         </ul>
	 * 
	 * @throws  TcTpmException This exception indicates that a TPM error has occurred. The specific
	 *           error code id held by the exception.
	 * 
	 * @TPM_V2_R101 173
	 */
	public static Object[] TpmOSAP(TcIStreamDest dest, int entityType, long entityValue,
			TcTpmNonce nonceOddOSAP) throws TcTddlException, TcTpmException
	{

		TcBlobData inBlob = blobUINT16(TcTpmConstants.TPM_TAG_RQU_COMMAND);
		inBlob.append(blobUINT32(0)); // paramSize is set later
		inBlob.append(blobUINT32(TcTpmOrdinals.TPM_ORD_OSAP));
		inBlob.append(blobUINT16(entityType));
		inBlob.append(blobUINT32(entityValue));
		inBlob.append(nonceOddOSAP.getEncoded());

		// all parameters filled in - set the length of the blob
		setParamSize(inBlob);

		// send byte stream
		TcBlobData tpmOutBlob = dest.transmitData(inBlob);
		TcTpmGenericReturnBlob outBlob = new TcTpmGenericReturnBlob(tpmOutBlob);

		// check TPM return code: if call was not successful, an exception is thrown
		handleRetCode(outBlob);

		// decode output values
		long authHandle = outBlob.decodeUINT32();
		TcTpmNonce nonceEven = new TcTpmNonce(outBlob);
		TcTpmNonce nonceEvenOSAP = new TcTpmNonce(outBlob);

		return new Object[] { outBlob.getRetCodeAsLong(), new Long(authHandle), nonceEven,
				nonceEvenOSAP };
	}


	/*************************************************************************************************
	 * 
	 * 
	 * @param dest The destination where the byte stream is written to.
	 * @param entityType The type of delegation information to use
	 * @param keyHandle Key for which delegated authority corresponds, or 0 if delegated
	 *          owneractivity. Only relevant if entityValue equals TcTpmDelegateKeyBlob
	 * @param entityValue TcTpmDelegateKeyBlob or TcTpmDelegateOwnerBlob or index MUST not be empty If
	 *          entityType is TPM_ET_DEL_ROW thenentityValue is a long
	 * 
	 * @return The returned Object[] holds the following elements:
	 *         <ul>
	 *         <li> 0 ... TPM return code (Long)
	 *         <li> 1 ... Handle that TPM creates that points to the authorization state. (long)
	 *         <li> 2 ... Nonce generated by TPM and associated with session. (TcTpmNonce)
	 *         <li> 3 ... Nonce generated by TPM and associated with shared secret. (TcTpmNonce)
	 *         </ul>
	 * 
	 * @throws  TcTpmException This exception indicates that a TPM error has occurred. The specific
	 *           error code id held by the exception.
	 * 
	 * @TPM_V2_R101 178
	 */
	public static Object[] TpmDSAP(TcIStreamDest dest, int entityType, long keyHandle,
			TcTpmNonce nonceOddDSAP, TcBlobData entityValue) throws TcTddlException, TcTpmException
	{

		TcBlobData inBlob = blobUINT16(TcTpmConstants.TPM_TAG_RQU_COMMAND);
		inBlob.append(blobUINT32(0)); // paramSize is set later
		inBlob.append(blobUINT32(TcTpmOrdinals.TPM_ORD_DSAP));
		inBlob.append(blobUINT16(entityType));
		inBlob.append(blobUINT32(keyHandle));
		inBlob.append(nonceOddDSAP.getEncoded());
		inBlob.append(blobUINT32(entityValue.getLengthAsLong()));
		inBlob.append(entityValue);

		// all parameters filled in - set the length of the blob
		setParamSize(inBlob);

		// send byte stream
		TcBlobData tpmOutBlob = dest.transmitData(inBlob);
		TcTpmGenericReturnBlob outBlob = new TcTpmGenericReturnBlob(tpmOutBlob);

		// check TPM return code: if call was not successful, an exception is thrown
		handleRetCode(outBlob);

		// decode output values
		long authHandle = outBlob.decodeUINT32();
		TcTpmNonce nonceEven = new TcTpmNonce(outBlob);
		TcTpmNonce nonceEvenDSAP = new TcTpmNonce(outBlob);

		return new Object[] { outBlob.getRetCodeAsLong(), new Long(authHandle), nonceEven,
				nonceEvenDSAP };
	}


	/*************************************************************************************************
	 * 
	 * 
	 * @param dest The destination where the byte stream is written to.
	 * @param entityType The type of entity in use
	 * @param entityValue The selection value based on entityType
	 * 
	 * @return The returned Object[] holds the following elements:
	 *         <ul>
	 *         <li> 0 ... TPM return code (Long)
	 *         </ul>
	 * 
	 * @throws  TcTpmException This exception indicates that a TPM error has occurred. The specific
	 *           error code id held by the exception.
	 * 
	 * @TPM_V2_R101 182
	 */
	public static Object[] TpmSetOwnerPointer(TcIStreamDest dest, int entityType, long entityValue)
		throws TcTddlException, TcTpmException
	{

		TcBlobData inBlob = blobUINT16(TcTpmConstants.TPM_TAG_RQU_COMMAND);
		inBlob.append(blobUINT32(0)); // paramSize is set later
		inBlob.append(blobUINT32(TcTpmOrdinals.TPM_ORD_SetOwnerPointer));
		inBlob.append(blobUINT16(entityType));
		inBlob.append(blobUINT32(entityValue));

		// all parameters filled in - set the length of the blob
		setParamSize(inBlob);

		// send byte stream
		TcBlobData tpmOutBlob = dest.transmitData(inBlob);
		TcTpmGenericReturnBlob outBlob = new TcTpmGenericReturnBlob(tpmOutBlob);

		// check TPM return code: if call was not successful, an exception is thrown
		handleRetCode(outBlob);

		return new Object[] { outBlob.getRetCodeAsLong(), };
	}

}
