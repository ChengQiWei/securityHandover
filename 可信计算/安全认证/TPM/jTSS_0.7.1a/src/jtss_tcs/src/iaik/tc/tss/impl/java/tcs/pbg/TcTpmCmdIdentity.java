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
import iaik.tc.tss.api.structs.tpm.TcTpmAuthdata;
import iaik.tc.tss.api.structs.tpm.TcTpmDigest;
import iaik.tc.tss.api.structs.tpm.TcTpmEncauth;
import iaik.tc.tss.api.structs.tpm.TcTpmGenericReturnBlob;
import iaik.tc.tss.api.structs.tpm.TcTpmKey;
import iaik.tc.tss.api.structs.tpm.TcTpmKey12;
import iaik.tc.tss.api.structs.tpm.TcTpmKey12New;
import iaik.tc.tss.api.structs.tpm.TcTpmKeyNew;
import iaik.tc.tss.api.structs.tpm.TcTpmNonce;
import iaik.tc.tss.api.structs.tpm.TcTpmSymmetricKey;
import iaik.tc.tss.impl.java.tddl.TcIStreamDest;

public class TcTpmCmdIdentity extends TcTpmCmdCommon {

	/*************************************************************************************************
	 * 
	 * 
	 * @param dest The destination where the byte stream is written to.
	 * @param inAuth1 Authorization values for first authorization session.
	 * @param inAuth2 Authorization values for second authorization session.
	 * @param identityAuth Encrypted usage AuthData for the new identity
	 * @param labelPrivCADigest The digest of the identity label and privacy CA chosen for the AIK
	 * @param idKeyParams Structure containing all parameters of new identity key. pubKey.keyLength &
	 *          idKeyParams.encData are both 0. This may be an instance of TcTpmKeyNew or TcTpmKey12New.
	 * 
	 * @return The returned Object[] holds the following elements:
	 *         <ul>
	 *         <li> 0 ... TPM return code (Long)
	 *         <li> 1 ... outgoing authorization for 1st session containing new nonceEven (TcTpmAuth)
	 *         <li> 2 ... outgoing authorization for 2nd session containing new nonceEven (TcTpmAuth)
	 *         <li> 3 ... The newly created identity key. (TcTpmKey or TcTpmKey12)
	 *         <li> 4 ... Signature of TcTpmIdentityContents using idKey.private. (TcBlobData)
	 *         </ul>
	 * 
	 * @throws  TcTpmException This exception indicates that a TPM error has occurred. The specific
	 *           error code id held by the exception.
	 * 
	 * @TPM_V2_R101 147
	 */
	public static Object[] TpmMakeIdentity(TcIStreamDest dest, TcTpmEncauth identityAuth,
			TcTpmDigest labelPrivCADigest, TcITpmKeyNew idKeyParams, TcTcsAuth inAuth1, TcTcsAuth inAuth2)
		throws TcTddlException, TcTpmException
	{
		TcBlobData inBlob = blobUINT16(TcTpmConstants.TPM_TAG_RQU_AUTH2_COMMAND);
		inBlob.append(blobUINT32(0)); // paramSize is set later
		inBlob.append(blobUINT32(TcTpmOrdinals.TPM_ORD_MakeIdentity));
		inBlob.append(identityAuth.getEncoded());
		inBlob.append(labelPrivCADigest.getEncoded());
		inBlob.append(idKeyParams.getEncoded());
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
		TcITpmKey idKey = null;
		if (idKeyParams instanceof TcTpmKeyNew) {
			idKey = new TcTpmKey(outBlob); 
		} else if (idKeyParams instanceof TcTpmKey12New) {
			idKey = new TcTpmKey12(outBlob); 
		} else {
			throw new IllegalArgumentException("idKeyParams must be of type TcTpmKeyNew or TcTpmKey12New.");
		}
			
		long identityBindingSize = outBlob.decodeUINT32();
		TcBlobData identityBinding = outBlob.decodeBytes(identityBindingSize);

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

		return new Object[] { outBlob.getRetCodeAsLong(), outAuth1, outAuth2, idKey, identityBinding };
	}


	/*************************************************************************************************
	 * 
	 * 
	 * @param dest The destination where the byte stream is written to.
	 * @param inAuth1 Authorization values for first authorization session.
	 * @param inAuth2 Authorization values for second authorization session.
	 * @param idKeyHandle Identity key to be activated
	 * @param blob The encrypted ASYM_CA_CONTENTS orTcTpmEkBlob
	 * 
	 * @return The returned Object[] holds the following elements:
	 *         <ul>
	 *         <li> 0 ... TPM return code (Long)
	 *         <li> 1 ... outgoing authorization for 1st session containing new nonceEven (TcTpmAuth)
	 *         <li> 2 ... outgoing authorization for 2nd session containing new nonceEven (TcTpmAuth)
	 *         <li> 3 ... The decrypted symmetric key. (TcTpmSymmetricKey)
	 *         </ul>
	 * 
	 * @throws  TcTpmException This exception indicates that a TPM error has occurred. The specific
	 *           error code id held by the exception.
	 * 
	 * @TPM_V2_R101 151
	 */
	public static Object[] TpmActivateIdentity(TcIStreamDest dest, long idKeyHandle, TcBlobData blob,
			TcTcsAuth inAuth1, TcTcsAuth inAuth2) throws TcTddlException, TcTpmException
	{

		TcBlobData inBlob = blobUINT16(TcTpmConstants.TPM_TAG_RQU_AUTH2_COMMAND);
		inBlob.append(blobUINT32(0)); // paramSize is set later
		inBlob.append(blobUINT32(TcTpmOrdinals.TPM_ORD_ActivateIdentity));
		inBlob.append(blobUINT32(idKeyHandle));
		inBlob.append(blobUINT32(blob.getLengthAsLong()));
		inBlob.append(blob);
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
		TcTpmSymmetricKey symmetricKey = new TcTpmSymmetricKey(outBlob);

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

		return new Object[] { outBlob.getRetCodeAsLong(), outAuth1, outAuth2, symmetricKey };
	}
}
