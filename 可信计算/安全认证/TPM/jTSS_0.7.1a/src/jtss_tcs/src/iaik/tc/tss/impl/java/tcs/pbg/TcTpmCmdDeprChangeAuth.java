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
import iaik.tc.tss.api.structs.tpm.TcTpmAuthdata;
import iaik.tc.tss.api.structs.tpm.TcTpmCertifyInfo;
import iaik.tc.tss.api.structs.tpm.TcTpmDigest;
import iaik.tc.tss.api.structs.tpm.TcTpmGenericReturnBlob;
import iaik.tc.tss.api.structs.tpm.TcTpmKey;
import iaik.tc.tss.api.structs.tpm.TcTpmKeyParms;
import iaik.tc.tss.api.structs.tpm.TcTpmNonce;
import iaik.tc.tss.impl.java.tddl.TcIStreamDest;

public class TcTpmCmdDeprChangeAuth extends TcTpmCmdCommon {

	/*************************************************************************************************
	 * 
	 * 
	 * @param dest The destination where the byte stream is written to.
	 * @param inAuth1 Authorization values for first authorization session.
	 * @param idHandle The keyHandle identifier of a loaded identity ID key
	 * @param antiReplay The nonce to be inserted into the certifyInfo structure
	 * @param tempKey Structure contains all parameters of ephemeral key.
	 * 
	 * @return The returned Object[] holds the following elements:
	 *         <ul>
	 *         <li> 0 ... TPM return code (Long)
	 *         <li> 1 ... outgoing authorization for session containing new nonceEven (TcTpmAuth)
	 *         <li> 2 ... The certifyInfo structure that is to be signed. (TcTpmCertifyInfo)
	 *         <li> 3 ... The signature of the certifyInfo parameter. (TcBlobData)
	 *         <li> 4 ... The keyHandle identifier to be used by ChangeAuthAsymFinish for the
	 *         ephemeral key (long)
	 *         <li> 5 ... Structure containing all parameters and public part of ephemeral key.
	 *         TcTpmKey.encSize is set to 0. (TcTpmKey)
	 *         </ul>
	 * 
	 * @throws  TcTpmException This exception indicates that a TPM error has occurred. The specific
	 *           error code id held by the exception.
	 * 
	 * @TPM_V2_R101 298
	 */
	public static Object[] TpmChangeAuthAsymStart(TcIStreamDest dest, long idHandle,
			TcTpmNonce antiReplay, TcTpmKeyParms tempKey, TcTcsAuth inAuth1) throws TcTddlException, TcTpmException
	{

		TcBlobData inBlob = blobUINT16(TcTpmConstants.TPM_TAG_RQU_AUTH1_COMMAND);
		inBlob.append(blobUINT32(0)); // paramSize is set later
		inBlob.append(blobUINT32(TcTpmOrdinals.TPM_ORD_ChangeAuthAsymStart));
		inBlob.append(blobUINT32(idHandle));
		inBlob.append(antiReplay.getEncoded());
		inBlob.append(tempKey.getEncoded());
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
		TcTpmCertifyInfo certifyInfo = new TcTpmCertifyInfo(outBlob);
		long sigSize = outBlob.decodeUINT32();
		TcBlobData sig = outBlob.decodeBytes(sigSize);
		long ephHandle = outBlob.decodeUINT32();
		TcITpmKey tempKeyOut = new TcTpmKey(outBlob);

		// decode 1st output auth
		TcTcsAuth outAuth1 = new TcTcsAuth();
		outAuth1.setAuthHandle(inAuth1.getAuthHandle());
		outAuth1.setNonceOdd(inAuth1.getNonceOdd());
		outAuth1.setNonceEven(new TcTpmNonce(outBlob)); // new nonce even from TPM
		outAuth1.setContAuthSession(outBlob.decodeBoolean());
		outAuth1.setHmac(new TcTpmAuthdata(outBlob));
		trackAuthSession(inAuth1, outAuth1);

		return new Object[] { outBlob.getRetCodeAsLong(), outAuth1, certifyInfo, sig,
				new Long(ephHandle), tempKeyOut };
	}


	/*************************************************************************************************
	 * 
	 * 
	 * @param dest The destination where the byte stream is written to.
	 * @param inAuth1 Authorization values for first authorization session.
	 * @param parentHandle The keyHandle of the parent key for the input data
	 * @param ephHandle The keyHandle identifier for the ephemeral key
	 * @param entityType The type of entity to be modified
	 * @param newAuthLink HMAC calculation that links the old and new AuthData values together
	 * @param encNewAuth New AuthData encrypted with ephemeral key.
	 * @param encData The encrypted entity that is to bemodified.
	 * 
	 * @return The returned Object[] holds the following elements:
	 *         <ul>
	 *         <li> 0 ... TPM return code (Long)
	 *         <li> 1 ... outgoing authorization for session containing new nonceEven (TcTpmAuth)
	 *         <li> 2 ... The modified, encrypted entity. (TcBlobData)
	 *         <li> 3 ... A nonce value from the TPM RNG to add entropy to the changeProof value
	 *         (TcTpmNonce)
	 *         <li> 4 ... Proof that AuthData has changed. (TcTpmDigest)
	 *         </ul>
	 * 
	 * @throws  TcTpmException This exception indicates that a TPM error has occurred. The specific
	 *           error code id held by the exception.
	 * 
	 * @TPM_V2_R101 301
	 */
	public static Object[] TpmChangeAuthAsymFinish(TcIStreamDest dest, long parentHandle,
			long ephHandle, int entityType, TcTpmDigest newAuthLink, TcBlobData encNewAuth,
			TcBlobData encData, TcTcsAuth inAuth1) throws TcTddlException, TcTpmException
	{

		TcBlobData inBlob = blobUINT16(TcTpmConstants.TPM_TAG_RQU_AUTH1_COMMAND);
		inBlob.append(blobUINT32(0)); // paramSize is set later
		inBlob.append(blobUINT32(TcTpmOrdinals.TPM_ORD_ChangeAuthAsymFinish));
		inBlob.append(blobUINT32(parentHandle));
		inBlob.append(blobUINT32(ephHandle));
		inBlob.append(blobUINT16(entityType));
		inBlob.append(newAuthLink.getEncoded());
		inBlob.append(blobUINT32(encNewAuth.getLengthAsLong()));
		inBlob.append(encNewAuth);
		inBlob.append(blobUINT32(encData.getLengthAsLong()));
		inBlob.append(encData);
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
		TcTpmNonce saltNonce = new TcTpmNonce(outBlob);
		TcTpmDigest changeProof = new TcTpmDigest(outBlob);

		// decode 1st output auth
		TcTcsAuth outAuth1 = new TcTcsAuth();
		outAuth1.setAuthHandle(inAuth1.getAuthHandle());
		outAuth1.setNonceOdd(inAuth1.getNonceOdd());
		outAuth1.setNonceEven(new TcTpmNonce(outBlob)); // new nonce even from TPM
		outAuth1.setContAuthSession(outBlob.decodeBoolean());
		outAuth1.setHmac(new TcTpmAuthdata(outBlob));
		trackAuthSession(inAuth1, outAuth1);

		return new Object[] { outBlob.getRetCodeAsLong(), outAuth1, outData, saltNonce, changeProof };
	}

}
