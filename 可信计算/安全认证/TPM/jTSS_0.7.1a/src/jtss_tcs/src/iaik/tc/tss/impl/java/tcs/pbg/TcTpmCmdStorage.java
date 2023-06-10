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
import iaik.tc.tss.api.structs.tpm.TcITpmKey;
import iaik.tc.tss.api.structs.tpm.TcITpmKeyNew;
import iaik.tc.tss.api.structs.tpm.TcITpmPcrInfo;
import iaik.tc.tss.api.structs.tpm.TcITpmStoredData;
import iaik.tc.tss.api.structs.tpm.TcTpmAuthdata;
import iaik.tc.tss.api.structs.tpm.TcTpmEncauth;
import iaik.tc.tss.api.structs.tpm.TcTpmGenericReturnBlob;
import iaik.tc.tss.api.structs.tpm.TcTpmKey;
import iaik.tc.tss.api.structs.tpm.TcTpmKey12;
import iaik.tc.tss.api.structs.tpm.TcTpmKey12New;
import iaik.tc.tss.api.structs.tpm.TcTpmKeyNew;
import iaik.tc.tss.api.structs.tpm.TcTpmNonce;
import iaik.tc.tss.api.structs.tpm.TcTpmPcrInfoLong;
import iaik.tc.tss.api.structs.tpm.TcTpmPubkey;
import iaik.tc.tss.api.structs.tpm.TcTpmStoredData;
import iaik.tc.tss.api.structs.tpm.TcTpmStoredData12;
import iaik.tc.tss.impl.java.tddl.TcIStreamDest;

public class TcTpmCmdStorage extends TcTpmCmdCommon {

	/*************************************************************************************************
	 * 
	 * 
	 * @param dest The destination where the byte stream is written to.
	 * @param inAuth1 Authorization values for first authorization session.
	 * @param keyHandle Handle of a loaded key that can perform seal operations.
	 * @param encAuth The encrypted AuthData for the sealed data.
	 * @param pcrInfo The PCR selection information. The caller MAY use TcTpmPcrInfoLong.
	 * @param inData The data to be sealed to the platform and any specified PCRs
	 * 
	 * @return The returned Object[] holds the following elements:
	 *         <ul>
	 *         <li> 0 ... TPM return code (Long)
	 *         <li> 1 ... outgoing authorization for session containing new nonceEven (TcTpmAuth)
	 *         <li> 2 ... Encrypted, integrity-protected data object that is the result of the
	 *         TPM_Seal operation. (TcTpmStoredData)
	 *         </ul>
	 * 
	 * @throws  TcTpmException This exception indicates that a TPM error has occurred. The specific
	 *           error code id held by the exception.
	 * 
	 * @TPM_V2_R101 59
	 */
	public static Object[] TpmSeal(TcIStreamDest dest, long keyHandle, TcTpmEncauth encAuth,
			TcITpmPcrInfo pcrInfo, TcBlobData inData, TcTcsAuth inAuth1) throws TcTddlException, TcTpmException
	{

		TcBlobData inBlob = blobUINT16(TcTpmConstants.TPM_TAG_RQU_AUTH1_COMMAND);
		inBlob.append(blobUINT32(0)); // paramSize is set later
		inBlob.append(blobUINT32(TcTpmOrdinals.TPM_ORD_Seal));
		inBlob.append(blobUINT32(keyHandle));
		inBlob.append(encAuth.getEncoded());
		if (pcrInfo == null) {
			inBlob.append(blobUINT32(0));
		} else {
			inBlob.append(blobUINT32(pcrInfo.getEncoded().getLengthAsLong()));
			inBlob.append(pcrInfo.getEncoded());
		}
		inBlob.append(blobUINT32(inData.getLengthAsLong()));
		inBlob.append(inData);
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
		TcBlobData storedData2Tag = TcBlobData.newByteArray(new byte[] { 0x00, TcTpmConstants.TPM_TAG_STORED_DATA12 });
		TcBlobData tag = TcBlobData.newByteArray(tpmOutBlob.getRange(10, 2));
		Object sealedData = null;
		if (tag.equals(storedData2Tag)) {
			sealedData = new TcTpmStoredData12(outBlob);
		} else {
			sealedData = new TcTpmStoredData(outBlob);
		}

		// decode 1st output auth
		TcTcsAuth outAuth1 = new TcTcsAuth();
		outAuth1.setAuthHandle(inAuth1.getAuthHandle());
		outAuth1.setNonceOdd(inAuth1.getNonceOdd());
		outAuth1.setNonceEven(new TcTpmNonce(outBlob)); // new nonce even from TPM
		outAuth1.setContAuthSession(outBlob.decodeBoolean());
		outAuth1.setHmac(new TcTpmAuthdata(outBlob));
		trackAuthSession(inAuth1, outAuth1);

		return new Object[] { outBlob.getRetCodeAsLong(), outAuth1, sealedData };
	}


	/*************************************************************************************************
	 * 
	 * 
	 * @param dest The destination where the byte stream is written to.
	 * @param inAuth1 Authorization values for first authorization session.
	 * @param inAuth2 Authorization values for second authorization session.
	 * @param parentHandle Handle of a loaded key that can unseal the data.
	 * @param inData The encrypted data generated by TPM_Seal.
	 * 
	 * @return The returned Object[] holds the following elements:
	 *         <ul>
	 *         <li> 0 ... TPM return code (Long)
	 *         <li> 1 ... outgoing authorization for 1st session containing new nonceEven (TcTpmAuth)
	 *         <li> 2 ... outgoing authorization for 2nd session containing new nonceEven (TcTpmAuth)
	 *         <li> 3 ... Decrypted data that had been sealed (TcBlobData)
	 *         </ul>
	 * 
	 * @throws  TcTpmException This exception indicates that a TPM error has occurred. The specific
	 *           error code id held by the exception.
	 * 
	 * @TPM_V2_R101 63
	 */
	public static Object[] TpmUnseal(TcIStreamDest dest, long parentHandle, TcITpmStoredData inData,
			TcTcsAuth inAuth1, TcTcsAuth inAuth2) throws TcTddlException, TcTpmException
	{

		TcBlobData inBlob = blobUINT16(TcTpmConstants.TPM_TAG_RQU_AUTH2_COMMAND);
		inBlob.append(blobUINT32(0)); // paramSize is set later
		inBlob.append(blobUINT32(TcTpmOrdinals.TPM_ORD_Unseal));
		inBlob.append(blobUINT32(parentHandle));
		inBlob.append(inData.getEncoded());
		inBlob.append(blobUINT32(inAuth1.getAuthHandle()));
		inBlob.append(inAuth1.getNonceOdd().getEncoded());
		inBlob.append(blobBOOL(inAuth1.getContAuthSession()));
		inBlob.append(inAuth1.getHmac().getEncoded());
		inBlob.append(blobUINT32(inAuth2.getAuthHandle()));
		inBlob.append(inAuth2.getNonceOdd().getEncoded());
		inBlob.append(blobBOOL(inAuth2.getContAuthSession()));
		inBlob.append(inAuth2.getHmac().getEncoded());

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
			invalidataAuthSession(inAuth2);
			throw e;
		}

		// decode output values
		long secretSize = outBlob.decodeUINT32();
		TcBlobData secret = outBlob.decodeBytes(secretSize);

		// decode 1st output auth
		TcTcsAuth outAuth1 = new TcTcsAuth();
		outAuth1.setAuthHandle(inAuth1.getAuthHandle());
		outAuth1.setNonceOdd(inAuth1.getNonceOdd());
		outAuth1.setNonceEven(new TcTpmNonce(outBlob)); // new nonce even from TPM
		outAuth1.setContAuthSession(outBlob.decodeBoolean());
		outAuth1.setHmac(new TcTpmAuthdata(outBlob));
		trackAuthSession(inAuth1, outAuth1);

		// decode 2nd output auth
		TcTcsAuth outAuth2 = new TcTcsAuth();
		outAuth2.setAuthHandle(inAuth2.getAuthHandle());
		outAuth2.setNonceOdd(inAuth2.getNonceOdd());
		outAuth2.setNonceEven(new TcTpmNonce(outBlob)); // new nonce even from TPM
		outAuth2.setContAuthSession(outBlob.decodeBoolean());
		outAuth2.setHmac(new TcTpmAuthdata(outBlob));
		trackAuthSession(inAuth2, outAuth2);

		return new Object[] { outBlob.getRetCodeAsLong(), outAuth1, outAuth2, secret };
	}


	/*************************************************************************************************
	 * 
	 * 
	 * @param dest The destination where the byte stream is written to.
	 * @param inAuth1 Authorization values for first authorization session.
	 * @param keyHandle The keyHandle identifier of a loaded key that can perform UnBindoperations.
	 * @param inData Encrypted blob to be decrypted
	 * 
	 * @return The returned Object[] holds the following elements:
	 *         <ul>
	 *         <li> 0 ... TPM return code (Long)
	 *         <li> 1 ... outgoing authorization for session containing new nonceEven (TcTpmAuth)
	 *         <li> 2 ... The resulting decrypted data. (TcBlobData)
	 *         </ul>
	 * 
	 * @throws  TcTpmException This exception indicates that a TPM error has occurred. The specific
	 *           error code id held by the exception.
	 * 
	 * @TPM_V2_R101 67
	 */
	public static Object[] TpmUnBind(TcIStreamDest dest, long keyHandle, TcBlobData inData,
			TcTcsAuth inAuth1) throws TcTddlException, TcTpmException
	{

		TcBlobData inBlob = blobUINT16(TcTpmConstants.TPM_TAG_RQU_AUTH1_COMMAND);
		inBlob.append(blobUINT32(0)); // paramSize is set later
		inBlob.append(blobUINT32(TcTpmOrdinals.TPM_ORD_UnBind));
		inBlob.append(blobUINT32(keyHandle));
		inBlob.append(blobUINT32(inData.getLengthAsLong()));
		inBlob.append(inData);
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
		long outDataSize = outBlob.decodeUINT32();
		TcBlobData outData = outBlob.decodeBytes(outDataSize);

		// decode 1st output auth
		TcTcsAuth outAuth1 = new TcTcsAuth();
		outAuth1.setAuthHandle(inAuth1.getAuthHandle());
		outAuth1.setNonceOdd(inAuth1.getNonceOdd());
		outAuth1.setNonceEven(new TcTpmNonce(outBlob)); // new nonce even from TPM
		outAuth1.setContAuthSession(outBlob.decodeBoolean());
		outAuth1.setHmac(new TcTpmAuthdata(outBlob));
		trackAuthSession(inAuth1, outAuth1);

		return new Object[] { outBlob.getRetCodeAsLong(), outAuth1, outData };
	}


	/*************************************************************************************************
	 * 
	 * 
	 * @param dest The destination where the byte stream is written to.
	 * @param inAuth1 Authorization values for first authorization session.
	 * @param parentHandle Handle of a loaded key that can perform key wrapping.
	 * @param dataUsageAuth Encrypted usage AuthData for thesealed data.
	 * @param dataMigrationAuth Encrypted migration AuthData forthe sealed data.
	 * @param keyInfo Information about key to be created, pubkey.keyLength and keyInfo.encData
	 *          elements are 0. This structure may be TcTpmKey or TcTpmKey12.
	 * 
	 * @return The returned Object[] holds the following elements:
	 *         <ul>
	 *         <li> 0 ... TPM return code (Long)
	 *         <li> 1 ... outgoing authorization for session containing new nonceEven (TcTpmAuth)
	 *         <li> 2 ... The TcTpmKey or TcTpmKey12 object which includes the public and encrypted
	 *         private key.
	 *         </ul>
	 * 
	 * @throws  TcTpmException This exception indicates that a TPM error has occurred. The specific
	 *           error code id held by the exception.
	 * 
	 * @TPM_V2_R101 70
	 */
	public static Object[] TpmCreateWrapKey(TcIStreamDest dest, long parentHandle,
			TcTpmEncauth dataUsageAuth, TcTpmEncauth dataMigrationAuth, TcITpmKeyNew keyInfo,
			TcTcsAuth inAuth1) throws TcTddlException, TcTpmException
	{
		TcBlobData inBlob = blobUINT16(TcTpmConstants.TPM_TAG_RQU_AUTH1_COMMAND);
		inBlob.append(blobUINT32(0)); // paramSize is set later
		inBlob.append(blobUINT32(TcTpmOrdinals.TPM_ORD_CreateWrapKey));
		inBlob.append(blobUINT32(parentHandle));
		inBlob.append(dataUsageAuth.getEncoded());
		inBlob.append(dataMigrationAuth.getEncoded());
		inBlob.append(keyInfo.getEncoded());
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
		TcITpmKey wrappedKey = null;
		if (keyInfo instanceof TcTpmKeyNew) {
			wrappedKey = new TcTpmKey(outBlob);
		} else if (keyInfo instanceof TcTpmKey12New) {
			wrappedKey = new TcTpmKey12(outBlob);
		} else {
			throw new IllegalArgumentException("keyInfo must be of type TcTpmKeyNew or TcTpmKey12New.");
		}

		// decode 1st output auth
		TcTcsAuth outAuth1 = new TcTcsAuth();
		outAuth1.setAuthHandle(inAuth1.getAuthHandle());
		outAuth1.setNonceOdd(inAuth1.getNonceOdd());
		outAuth1.setNonceEven(new TcTpmNonce(outBlob)); // new nonce even from TPM
		outAuth1.setContAuthSession(outBlob.decodeBoolean());
		outAuth1.setHmac(new TcTpmAuthdata(outBlob));
		trackAuthSession(inAuth1, outAuth1);

		return new Object[] { outBlob.getRetCodeAsLong(), outAuth1, wrappedKey };
	}


	/*************************************************************************************************
	 * 
	 * 
	 * @param dest The destination where the byte stream is written to.
	 * @param inAuth1 Authorization values for first authorization session.
	 * @param parentHandle TPM handle of parent key.
	 * @param inKey Incoming key object, both encrypted private and clear public portions. This may be
	 *          of type TcTpmKey or TcTpmKey12.
	 * 
	 * @return The returned Object[] holds the following elements:
	 *         <ul>
	 *         <li> 0 ... TPM return code (Long)
	 *         <li> 1 ... outgoing authorization for session containing new nonceEven (TcTpmAuth)
	 *         <li> 2 ... Internal TPM handle where decrypted key was loaded. (long)
	 *         </ul>
	 * 
	 * @throws  TcTpmException This exception indicates that a TPM error has occurred. The specific
	 *           error code id held by the exception.
	 * 
	 * @TPM_V2_R101 73
	 */
	public static Object[] TpmLoadKey2(TcIStreamDest dest, long parentHandle, TcITpmKey inKey,
			TcTcsAuth inAuth1) throws TcTddlException, TcTpmException
	{

		TcBlobData inBlob = blobUINT16(TcTpmConstants.TPM_TAG_RQU_AUTH1_COMMAND);
		inBlob.append(blobUINT32(0)); // paramSize is set later
		inBlob.append(blobUINT32(TcTpmOrdinals.TPM_ORD_LoadKey2));
		inBlob.append(blobUINT32(parentHandle));
		inBlob.append(inKey.getEncoded());
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
		long inkeyHandle = outBlob.decodeUINT32();

		// decode 1st output auth
		TcTcsAuth outAuth1 = new TcTcsAuth();
		outAuth1.setAuthHandle(inAuth1.getAuthHandle());
		outAuth1.setNonceOdd(inAuth1.getNonceOdd());
		outAuth1.setNonceEven(new TcTpmNonce(outBlob)); // new nonce even from TPM
		outAuth1.setContAuthSession(outBlob.decodeBoolean());
		outAuth1.setHmac(new TcTpmAuthdata(outBlob));
		trackAuthSession(inAuth1, outAuth1);

		return new Object[] { outBlob.getRetCodeAsLong(), outAuth1, new Long(inkeyHandle) };
	}


	/*************************************************************************************************
	 * 
	 * 
	 * @param dest The destination where the byte stream is written to.
	 * @param inAuth1 Authorization values for first authorization session.
	 * @param keyHandle TPM handle of key.
	 * 
	 * @return The returned Object[] holds the following elements:
	 *         <ul>
	 *         <li> 0 ... TPM return code (Long)
	 *         <li> 1 ... outgoing authorization for session containing new nonceEven (TcTpmAuth)
	 *         <li> 2 ... Public portion of key in keyHandle. (TcTpmPubkey)
	 *         </ul>
	 * 
	 * @throws  TcTpmException This exception indicates that a TPM error has occurred. The specific
	 *           error code id held by the exception.
	 * 
	 * @TPM_V2_R101 79
	 */
	public static Object[] TpmGetPubKey(TcIStreamDest dest, long keyHandle, TcTcsAuth inAuth1)
		throws TcTddlException, TcTpmException
	{

		TcBlobData inBlob = blobUINT16(TcTpmConstants.TPM_TAG_RQU_AUTH1_COMMAND);
		inBlob.append(blobUINT32(0)); // paramSize is set later
		inBlob.append(blobUINT32(TcTpmOrdinals.TPM_ORD_GetPubKey));
		inBlob.append(blobUINT32(keyHandle));
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
		TcTpmPubkey pubKey = new TcTpmPubkey(outBlob);

		// decode 1st output auth
		TcTcsAuth outAuth1 = new TcTcsAuth();
		outAuth1.setAuthHandle(inAuth1.getAuthHandle());
		outAuth1.setNonceOdd(inAuth1.getNonceOdd());
		outAuth1.setNonceEven(new TcTpmNonce(outBlob)); // new nonce even from TPM
		outAuth1.setContAuthSession(outBlob.decodeBoolean());
		outAuth1.setHmac(new TcTpmAuthdata(outBlob));
		trackAuthSession(inAuth1, outAuth1);

		return new Object[] { outBlob.getRetCodeAsLong(), outAuth1, pubKey };
	}


	/*************************************************************************************************
	 * 
	 * 
	 * @param dest The destination where the byte stream is written to.
	 * @param inAuth1 Authorization values for first authorization session.
	 * @param keyHandle Handle of a loaded key that can perform seal operations.
	 * @param encAuth The encrypted AuthData for the sealed data.
	 * @param pcrInfo MUST use TcTpmPcrInfoLong.
	 * @param inData The data to be sealed to the platform and any specified PCRs
	 * 
	 * @return The returned Object[] holds the following elements:
	 *         <ul>
	 *         <li> 0 ... TPM return code (Long)
	 *         <li> 1 ... outgoing authorization for session containing new nonceEven (TcTpmAuth)
	 *         <li> 2 ... Encrypted, integrity-protected data object that is the result of the
	 *         TPM_Sealx operation. (TcTpmStoredData)
	 *         </ul>
	 * 
	 * @throws  TcTpmException This exception indicates that a TPM error has occurred. The specific
	 *           error code id held by the exception.
	 * 
	 * @TPM_V2_R101 82
	 */
	public static Object[] TpmSealx(TcIStreamDest dest, long keyHandle, TcTpmEncauth encAuth,
			TcTpmPcrInfoLong pcrInfo, TcBlobData inData, TcTcsAuth inAuth1) throws TcTddlException, TcTpmException
	{

		TcBlobData inBlob = blobUINT16(TcTpmConstants.TPM_TAG_RQU_AUTH1_COMMAND);
		inBlob.append(blobUINT32(0)); // paramSize is set later
		inBlob.append(blobUINT32(TcTpmOrdinals.TPM_ORD_Sealx));
		inBlob.append(blobUINT32(keyHandle));
		inBlob.append(encAuth.getEncoded());
		inBlob.append(blobUINT32(pcrInfo.getEncoded().getLengthAsLong()));
		inBlob.append(pcrInfo.getEncoded());
		inBlob.append(blobUINT32(inData.getLengthAsLong()));
		inBlob.append(inData);
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
		TcTpmStoredData sealedData = new TcTpmStoredData(outBlob);

		// decode 1st output auth
		TcTcsAuth outAuth1 = new TcTcsAuth();
		outAuth1.setAuthHandle(inAuth1.getAuthHandle());
		outAuth1.setNonceOdd(inAuth1.getNonceOdd());
		outAuth1.setNonceEven(new TcTpmNonce(outBlob)); // new nonce even from TPM
		outAuth1.setContAuthSession(outBlob.decodeBoolean());
		outAuth1.setHmac(new TcTpmAuthdata(outBlob));
		trackAuthSession(inAuth1, outAuth1);

		return new Object[] { outBlob.getRetCodeAsLong(), outAuth1, sealedData };
	}

}
