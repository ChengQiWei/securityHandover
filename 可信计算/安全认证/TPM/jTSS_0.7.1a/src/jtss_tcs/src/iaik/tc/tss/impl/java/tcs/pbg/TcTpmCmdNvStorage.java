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
import iaik.tc.tss.api.structs.tcs.TcTcsAuth;
import iaik.tc.tss.api.structs.tpm.TcTpmAuthdata;
import iaik.tc.tss.api.structs.tpm.TcTpmEncauth;
import iaik.tc.tss.api.structs.tpm.TcTpmGenericReturnBlob;
import iaik.tc.tss.api.structs.tpm.TcTpmNonce;
import iaik.tc.tss.api.structs.tpm.TcTpmNvDataPublic;
import iaik.tc.tss.impl.java.tddl.TcIStreamDest;

public class TcTpmCmdNvStorage extends TcTpmCmdCommon {

	/*************************************************************************************************
	 *
	 *
	 * @param dest The destination where the byte stream is written to.
	 * @param inAuth1 Authorization values for first authorization session.
	 * @param pubInfo The public parameters of the NV area
	 * @param encAuth The encrypted AuthData, only valid if the attributes require subsequent
	 *          authorization
	 *
	 * @return The returned Object[] holds the following elements:
	 *         <ul>
	 *         <li> 0 ... TPM return code (Long)
	 *         <li> 1 ... outgoing authorization for session containing new nonceEven (TcTpmAuth)
	 *         </ul>
	 *
	 * @throws TcTpmException This exception indicates that a TPM error has occurred. The specific
	 *           error code id held by the exception.
	 *
	 * @TPM_V2_R101 205
	 */
	public static Object[] TpmNvDefineSpace(TcIStreamDest dest, TcTpmNvDataPublic pubInfo,
			TcTpmEncauth encAuth, TcTcsAuth inAuth1) throws TcTddlException, TcTpmException
	{

		boolean auth = true;
		if (inAuth1 == null) {
			auth = false;
		}

		TcBlobData inBlob = null;
		if (auth) {
			inBlob = blobUINT16(TcTpmConstants.TPM_TAG_RQU_AUTH1_COMMAND);
		} else {
			inBlob = blobUINT16(TcTpmConstants.TPM_TAG_RQU_COMMAND);
		}

		inBlob.append(blobUINT32(0)); // paramSize is set later
		inBlob.append(blobUINT32(TcTpmOrdinals.TPM_ORD_NV_DefineSpace));
		inBlob.append(pubInfo.getEncoded());
		inBlob.append(encAuth.getEncoded());

		if (auth) {
			inBlob.append(blobUINT32(inAuth1.getAuthHandle()));
			inBlob.append(inAuth1.getNonceOdd().getEncoded());
			inBlob.append(blobBOOL(inAuth1.getContAuthSession()));
			inBlob.append(inAuth1.getHmac().getEncoded());
		}

		// all parameters filled in - set the length of the blob
		setParamSize(inBlob);

		// send byte stream
		TcBlobData tpmOutBlob = dest.transmitData(inBlob);
		TcTpmGenericReturnBlob outBlob = new TcTpmGenericReturnBlob(tpmOutBlob);

		// check TPM return code: if call was not successful, an exception is thrown
		try {
			handleRetCode(outBlob);
		} catch (TcTpmException e) {
			if (auth) {
				invalidataAuthSession(inAuth1);
			}
			throw e;
		}

		TcTcsAuth outAuth1 = null;
		if (auth) {
			// decode 1st output auth
			outAuth1 = new TcTcsAuth();
			outAuth1.setAuthHandle(inAuth1.getAuthHandle());
			outAuth1.setNonceOdd(inAuth1.getNonceOdd());
			outAuth1.setNonceEven(new TcTpmNonce(outBlob)); // new nonce even from TPM
			outAuth1.setContAuthSession(outBlob.decodeBoolean());
			outAuth1.setHmac(new TcTpmAuthdata(outBlob));
			trackAuthSession(inAuth1, outAuth1);
		}

		return new Object[] { outBlob.getRetCodeAsLong(), outAuth1 };
	}


	/*************************************************************************************************
	 *
	 *
	 * @param dest The destination where the byte stream is written to.
	 * @param inAuth1 Authorization values for first authorization session.
	 * @param nvIndex The index of the area to set
	 * @param offset The offset into the NV Area
	 * @param data The data to set the area to
	 *
	 * @return The returned Object[] holds the following elements:
	 *         <ul>
	 *         <li> 0 ... TPM return code (Long)
	 *         <li> 1 ... outgoing authorization for session containing new nonceEven (TcTpmAuth)
	 *         </ul>
	 *
	 * @throws TcTpmException This exception indicates that a TPM error has occurred. The specific
	 *           error code id held by the exception.
	 *
	 * @TPM_V2_R101 209
	 */
	public static Object[] TpmNvWriteValue(TcIStreamDest dest, long nvIndex, long offset,
			TcBlobData data, TcTcsAuth inAuth1) throws TcTddlException, TcTpmException
	{

		TcBlobData inBlob = blobUINT16(TcTpmConstants.TPM_TAG_RQU_AUTH1_COMMAND);
		inBlob.append(blobUINT32(0)); // paramSize is set later
		inBlob.append(blobUINT32(TcTpmOrdinals.TPM_ORD_NV_WriteValue));
		inBlob.append(blobUINT32(nvIndex));
		inBlob.append(blobUINT32(offset));
		inBlob.append(blobUINT32(data.getLengthAsLong()));
		inBlob.append(data);
		inBlob.append(blobUINT32(inAuth1.getAuthHandle()));
		inBlob.append(inAuth1.getNonceOdd().getEncoded());
		inBlob.append(blobBOOL(inAuth1.getContAuthSession()));
		inBlob.append(inAuth1.getHmac().getEncoded());

		// all parameters filled in - set the length of the blob
		setParamSize(inBlob);

		// send byte stream
		TcBlobData tpmOutBlob = dest.transmitData(inBlob);
		TcTpmGenericReturnBlob outBlob = new TcTpmGenericReturnBlob(tpmOutBlob);

		// check TPM return code: if call was not successful, an exception is thrown
		try {
			handleRetCode(outBlob);
		} catch (TcTpmException e) {
			invalidataAuthSession(inAuth1);
			throw e;
		}

		// decode 1st output auth
		TcTcsAuth outAuth1 = new TcTcsAuth();
		outAuth1.setAuthHandle(inAuth1.getAuthHandle());
		outAuth1.setNonceOdd(inAuth1.getNonceOdd());
		outAuth1.setNonceEven(new TcTpmNonce(outBlob)); // new nonce even from TPM
		outAuth1.setContAuthSession(outBlob.decodeBoolean());
		outAuth1.setHmac(new TcTpmAuthdata(outBlob));
		trackAuthSession(inAuth1, outAuth1);

		return new Object[] { outBlob.getRetCodeAsLong(), outAuth1, };
	}


	/*************************************************************************************************
	 *
	 *
	 * @param dest The destination where the byte stream is written to.
	 * @param inAuth1 Authorization values for first authorization session.
	 * @param nvIndex The index of the area to set
	 * @param offset The offset into the chunk
	 * @param data The data to set the area to
	 *
	 * @return The returned Object[] holds the following elements:
	 *         <ul>
	 *         <li> 0 ... TPM return code (Long)
	 *         <li> 1 ... outgoing authorization for session containing new nonceEven (TcTpmAuth)
	 *         </ul>
	 *
	 * @throws TcTpmException This exception indicates that a TPM error has occurred. The specific
	 *           error code id held by the exception.
	 *
	 * @TPM_V2_R101 212
	 */
	public static Object[] TpmNvWriteValueAuth(TcIStreamDest dest, long nvIndex, long offset,
			TcBlobData data, TcTcsAuth inAuth1) throws TcTddlException, TcTpmException
	{

		TcBlobData inBlob = blobUINT16(TcTpmConstants.TPM_TAG_RQU_AUTH1_COMMAND);
		inBlob.append(blobUINT32(0)); // paramSize is set later
		inBlob.append(blobUINT32(TcTpmOrdinals.TPM_ORD_NV_WriteValueAuth));
		inBlob.append(blobUINT32(nvIndex));
		inBlob.append(blobUINT32(offset));
		inBlob.append(blobUINT32(data.getLengthAsLong()));
		inBlob.append(data);
		inBlob.append(blobUINT32(inAuth1.getAuthHandle()));
		inBlob.append(inAuth1.getNonceOdd().getEncoded());
		inBlob.append(blobBOOL(inAuth1.getContAuthSession()));
		inBlob.append(inAuth1.getHmac().getEncoded());

		// all parameters filled in - set the length of the blob
		setParamSize(inBlob);

		// send byte stream
		TcBlobData tpmOutBlob = dest.transmitData(inBlob);
		TcTpmGenericReturnBlob outBlob = new TcTpmGenericReturnBlob(tpmOutBlob);

		// check TPM return code: if call was not successful, an exception is thrown
		try {
			handleRetCode(outBlob);
		} catch (TcTpmException e) {
			invalidataAuthSession(inAuth1);
			throw e;
		}

		// decode 1st output auth
		TcTcsAuth outAuth1 = new TcTcsAuth();
		outAuth1.setAuthHandle(inAuth1.getAuthHandle());
		outAuth1.setNonceOdd(inAuth1.getNonceOdd());
		outAuth1.setNonceEven(new TcTpmNonce(outBlob)); // new nonce even from TPM
		outAuth1.setContAuthSession(outBlob.decodeBoolean());
		outAuth1.setHmac(new TcTpmAuthdata(outBlob));
		trackAuthSession(inAuth1, outAuth1);

		return new Object[] { outBlob.getRetCodeAsLong(), outAuth1, };
	}


	/*************************************************************************************************
	 *
	 *
	 * @param dest The destination where the byte stream is written to.
	 * @param inAuth1 Authorization values for first authorization session.
	 * @param nvIndex The index of the area to set
	 * @param offset The offset into the area
	 * @param dataSz The size of the data area
	 *
	 * @return The returned Object[] holds the following elements:
	 *         <ul>
	 *         <li> 0 ... TPM return code (Long)
	 *         <li> 1 ... outgoing authorization for session containing new nonceEven (TcTpmAuth)
	 *         <li> 2 ... The data to set the area to (TcBlobData)
	 *         </ul>
	 *
	 * @throws TcTpmException This exception indicates that a TPM error has occurred. The specific
	 *           error code id held by the exception.
	 *
	 * @TPM_V2_R101 214
	 */
	public static Object[] TpmNvReadValue(TcIStreamDest dest, long nvIndex, long offset, long dataSz,
			TcTcsAuth inAuth1) throws TcTddlException, TcTpmException
	{

		TcBlobData inBlob = null;
		if (inAuth1 != null) {
			inBlob = blobUINT16(TcTpmConstants.TPM_TAG_RQU_AUTH1_COMMAND);
		} else {
			inBlob = blobUINT16(TcTpmConstants.TPM_TAG_RQU_COMMAND);
		}
		inBlob.append(blobUINT32(0)); // paramSize is set later
		inBlob.append(blobUINT32(TcTpmOrdinals.TPM_ORD_NV_ReadValue));
		inBlob.append(blobUINT32(nvIndex));
		inBlob.append(blobUINT32(offset));
		inBlob.append(blobUINT32(dataSz));
		if (inAuth1 != null) {
			inBlob.append(blobUINT32(inAuth1.getAuthHandle()));
			inBlob.append(inAuth1.getNonceOdd().getEncoded());
			inBlob.append(blobBOOL(inAuth1.getContAuthSession()));
			inBlob.append(inAuth1.getHmac().getEncoded());
		}

		// all parameters filled in - set the length of the blob
		setParamSize(inBlob);

		// send byte stream
		TcBlobData tpmOutBlob = dest.transmitData(inBlob);
		TcTpmGenericReturnBlob outBlob = new TcTpmGenericReturnBlob(tpmOutBlob);

		// check TPM return code: if call was not successful, an exception is thrown
		try {
			handleRetCode(outBlob);
		} catch (TcTpmException e) {
			invalidataAuthSession(inAuth1);
			throw e;
		}

		// decode output values
		long dataSize = outBlob.decodeUINT32();
		TcBlobData data = outBlob.decodeBytes(dataSize);

		// decode 1st output auth
		TcTcsAuth outAuth1 = null;
		if (inAuth1 != null) {
			outAuth1 = new TcTcsAuth();
			outAuth1.setAuthHandle(inAuth1.getAuthHandle());
			outAuth1.setNonceOdd(inAuth1.getNonceOdd());
			outAuth1.setNonceEven(new TcTpmNonce(outBlob)); // new nonce even from TPM
			outAuth1.setContAuthSession(outBlob.decodeBoolean());
			outAuth1.setHmac(new TcTpmAuthdata(outBlob));
			trackAuthSession(inAuth1, outAuth1);
		}

		return new Object[] { outBlob.getRetCodeAsLong(), outAuth1, data };
	}


	/*************************************************************************************************
	 *
	 *
	 * @param dest The destination where the byte stream is written to.
	 * @param inAuth1 Authorization values for first authorization session.
	 * @param nvIndex The index of the area to set
	 * @param offset The offset from the data area
	 * @param dataSz The size of the data area
	 *
	 * @return The returned Object[] holds the following elements:
	 *         <ul>
	 *         <li> 0 ... TPM return code (Long)
	 *         <li> 1 ... outgoing authorization for session containing new nonceEven (TcTpmAuth)
	 *         <li> 2 ... The data (TcBlobData)
	 *         </ul>
	 *
	 * @throws TcTpmException This exception indicates that a TPM error has occurred. The specific
	 *           error code id held by the exception.
	 *
	 * @TPM_V2_R101 216
	 */
	public static Object[] TpmNvReadValueAuth(TcIStreamDest dest, long nvIndex, long offset,
			long dataSz, TcTcsAuth inAuth1) throws TcTddlException, TcTpmException
	{

		TcBlobData inBlob = blobUINT16(TcTpmConstants.TPM_TAG_RQU_AUTH1_COMMAND);
		inBlob.append(blobUINT32(0)); // paramSize is set later
		inBlob.append(blobUINT32(TcTpmOrdinals.TPM_ORD_NV_ReadValueAuth));
		inBlob.append(blobUINT32(nvIndex));
		inBlob.append(blobUINT32(offset));
		inBlob.append(blobUINT32(dataSz));
		inBlob.append(blobUINT32(inAuth1.getAuthHandle()));
		inBlob.append(inAuth1.getNonceOdd().getEncoded());
		inBlob.append(blobBOOL(inAuth1.getContAuthSession()));
		inBlob.append(inAuth1.getHmac().getEncoded());

		// all parameters filled in - set the length of the blob
		setParamSize(inBlob);

		// send byte stream
		TcBlobData tpmOutBlob = dest.transmitData(inBlob);
		TcTpmGenericReturnBlob outBlob = new TcTpmGenericReturnBlob(tpmOutBlob);

		// check TPM return code: if call was not successful, an exception is thrown
		try {
			handleRetCode(outBlob);
		} catch (TcTpmException e) {
			invalidataAuthSession(inAuth1);
			throw e;
		}

		// decode output values
		long dataSize = outBlob.decodeUINT32();
		TcBlobData data = outBlob.decodeBytes(dataSize);

		// decode 1st output auth
		TcTcsAuth outAuth1 = new TcTcsAuth();
		outAuth1.setAuthHandle(inAuth1.getAuthHandle());
		outAuth1.setNonceOdd(inAuth1.getNonceOdd());
		outAuth1.setNonceEven(new TcTpmNonce(outBlob)); // new nonce even from TPM
		outAuth1.setContAuthSession(outBlob.decodeBoolean());
		outAuth1.setHmac(new TcTpmAuthdata(outBlob));
		trackAuthSession(inAuth1, outAuth1);

		return new Object[] { outBlob.getRetCodeAsLong(), outAuth1, data };
	}
}
