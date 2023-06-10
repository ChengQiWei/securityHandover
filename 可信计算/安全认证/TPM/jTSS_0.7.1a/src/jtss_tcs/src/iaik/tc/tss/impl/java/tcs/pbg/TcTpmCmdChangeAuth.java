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
import iaik.tc.tss.impl.java.tddl.TcIStreamDest;

public class TcTpmCmdChangeAuth extends TcTpmCmdCommon {

	/*************************************************************************************************
	 * 
	 * 
	 * @param dest The destination where the byte stream is written to.
	 * @param inAuth1 Authorization values for first authorization session.
	 * @param inAuth2 Authorization values for second authorization session.
	 * @param parentHandle Handle of the parent key to the entity.
	 * @param protocolID The protocol in use.
	 * @param newAuth The encrypted new AuthData for the entity
	 * @param entityType The type of entity to be modified
	 * @param encData The encrypted entity that is to be modified.
	 * 
	 * @return The returned Object[] holds the following elements:
	 *         <ul>
	 *         <li> 0 ... TPM return code (Long)
	 *         <li> 1 ... outgoing authorization for 1st session containing new nonceEven (TcTpmAuth)
	 *         <li> 2 ... outgoing authorization for 2nd session containing new nonceEven (TcTpmAuth)
	 *         <li> 3 ... The modified, encrypted entity. (TcBlobData)
	 *         </ul>
	 * 
	 * @throws  TcTpmException This exception indicates that a TPM error has occurred. The specific
	 *           error code id held by the exception.
	 * 
	 * @TPM_V2_R101 165
	 */
	public static Object[] TpmChangeAuth(TcIStreamDest dest, long parentHandle, int protocolID,
			TcTpmEncauth newAuth, int entityType, TcBlobData encData, TcTcsAuth inAuth1, TcTcsAuth inAuth2)
		throws TcTddlException, TcTpmException
	{

		TcBlobData inBlob = blobUINT16(TcTpmConstants.TPM_TAG_RQU_AUTH2_COMMAND);
		inBlob.append(blobUINT32(0)); // paramSize is set later
		inBlob.append(blobUINT32(TcTpmOrdinals.TPM_ORD_ChangeAuth));
		inBlob.append(blobUINT32(parentHandle));
		inBlob.append(blobUINT16(protocolID));
		inBlob.append(newAuth.getEncoded());
		inBlob.append(blobUINT16(entityType));
		inBlob.append(blobUINT32(encData.getLengthAsLong()));
		inBlob.append(encData);
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

		// decode 2nd output auth
		TcTcsAuth outAuth2 = new TcTcsAuth();
		outAuth2.setAuthHandle(inAuth2.getAuthHandle());
		outAuth2.setNonceOdd(inAuth2.getNonceOdd());
		outAuth2.setNonceEven(new TcTpmNonce(outBlob)); // new nonce even from TPM
		outAuth2.setContAuthSession(outBlob.decodeBoolean());
		outAuth2.setHmac(new TcTpmAuthdata(outBlob));
		trackAuthSession(inAuth2, outAuth2);

		return new Object[] { outBlob.getRetCodeAsLong(), outAuth1, outAuth2, outData };
	}


	/*************************************************************************************************
	 * 
	 * 
	 * @param dest The destination where the byte stream is written to.
	 * @param inAuth1 Authorization values for first authorization session.
	 * @param protocolID The protocol in use.
	 * @param newAuth The encrypted new AuthData for theentity
	 * @param entityType The type of entity to be modified
	 * 
	 * @return The returned Object[] holds the following elements:
	 *         <ul>
	 *         <li> 0 ... TPM return code (Long)
	 *         <li> 1 ... outgoing authorization for session containing new nonceEven (TcTpmAuth)
	 *         </ul>
	 * 
	 * @throws  TcTpmException This exception indicates that a TPM error has occurred. The specific
	 *           error code id held by the exception.
	 * 
	 * @TPM_V2_R101 168
	 */
	public static Object[] TpmChangeAuthOwner(TcIStreamDest dest, int protocolID,
			TcTpmEncauth newAuth, int entityType, TcTcsAuth inAuth1) throws TcTddlException, TcTpmException
	{

		TcBlobData inBlob = blobUINT16(TcTpmConstants.TPM_TAG_RQU_AUTH1_COMMAND);
		inBlob.append(blobUINT32(0)); // paramSize is set later
		inBlob.append(blobUINT32(TcTpmOrdinals.TPM_ORD_ChangeAuthOwner));
		inBlob.append(blobUINT16(protocolID));
		inBlob.append(newAuth.getEncoded());
		inBlob.append(blobUINT16(entityType));
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
}
