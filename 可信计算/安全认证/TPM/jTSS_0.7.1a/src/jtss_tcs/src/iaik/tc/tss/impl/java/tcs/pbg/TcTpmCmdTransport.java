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
import iaik.tc.tss.api.structs.tpm.TcTpmCurrentTicks;
import iaik.tc.tss.api.structs.tpm.TcTpmGenericReturnBlob;
import iaik.tc.tss.api.structs.tpm.TcTpmNonce;
import iaik.tc.tss.api.structs.tpm.TcTpmTransportPublic;
import iaik.tc.tss.impl.java.tddl.TcIStreamDest;

public class TcTpmCmdTransport extends TcTpmCmdCommon {

	/*************************************************************************************************
	 * 
	 * 
	 * @param dest The destination where the byte stream is written to.
	 * @param inAuth1 Authorization values for first authorization session.
	 * @param encHandle The handle to the key that encrypted the blob
	 * @param transPublic The public information describing the transport session
	 * @param secret The encrypted secret area
	 * 
	 * @return The returned Object[] holds the following elements:
	 *         <ul>
	 *         <li> 0 ... TPM return code (Long)
	 *         <li> 1 ... outgoing authorization for session containing new nonceEven (TcTpmAuth)
	 *         <li> 2 ... The handle for the transport session (long)
	 *         <li> 3 ... The locality that called this command (long)
	 *         <li> 4 ... The current tick count (TcTpmCurrentTicks)
	 *         <li> 5 ... The even nonce in use for subsequent execute transport (TcTpmNonce)
	 *         </ul>
	 * 
	 * @throws  TcTpmException This exception indicates that a TPM error has occurred. The specific
	 *           error code id held by the exception.
	 * 
	 * @TPM_V2_R101 233
	 */
	public static Object[] TpmEstablishTransport(TcIStreamDest dest, long encHandle,
			TcTpmTransportPublic transPublic, TcBlobData secret, TcTcsAuth inAuth1)
		throws TcTddlException, TcTpmException
	{

		TcBlobData inBlob = null;
		if (encHandle == TcTpmConstants.TPM_KH_TRANSPORT) {
			inBlob = blobUINT16(TcTpmConstants.TPM_TAG_RQU_COMMAND);
		} else {
			inBlob = blobUINT16(TcTpmConstants.TPM_TAG_RQU_AUTH1_COMMAND);
		}
		inBlob.append(blobUINT32(0)); // paramSize is set later
		inBlob.append(blobUINT32(TcTpmOrdinals.TPM_ORD_EstablishTransport));
		inBlob.append(blobUINT32(encHandle));
		inBlob.append(transPublic.getEncoded());
		inBlob.append(blobUINT32(secret.getLengthAsLong()));
		inBlob.append(secret);
		if (encHandle != TcTpmConstants.TPM_KH_TRANSPORT) {
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
		long transHandle = outBlob.decodeUINT32();
		long locality = outBlob.decodeUINT32();
		TcTpmCurrentTicks currentTicks = new TcTpmCurrentTicks(outBlob);
		TcTpmNonce transNonceEven = new TcTpmNonce(outBlob);

		// decode 1st output auth
		TcTcsAuth outAuth1 = new TcTcsAuth();
		if (encHandle != TcTpmConstants.TPM_KH_TRANSPORT) {
			outAuth1.setAuthHandle(inAuth1.getAuthHandle());
			outAuth1.setNonceOdd(inAuth1.getNonceOdd());
			outAuth1.setNonceEven(new TcTpmNonce(outBlob)); // new nonce even from TPM
			outAuth1.setContAuthSession(outBlob.decodeBoolean());
			outAuth1.setHmac(new TcTpmAuthdata(outBlob));
		trackAuthSession(inAuth1, outAuth1);
		}

		return new Object[] { outBlob.getRetCodeAsLong(), outAuth1, new Long(transHandle),
				new Long(locality), currentTicks, transNonceEven };
	}


	/*************************************************************************************************
	 * 
	 * 
	 * @param dest The destination where the byte stream is written to.
	 * @param inAuth1 Authorization values for first authorization session.
	 * @param wrappedCmd The wrapped command
	 * @param transHandle The transport session handle
	 * 
	 * @return The returned Object[] holds the following elements:
	 *         <ul>
	 *         <li> 0 ... TPM return code (Long)
	 *         <li> 1 ... outgoing authorization for session containing new nonceEven (TcTpmAuth)
	 *         <li> 2 ... The current ticks when the command was executed (long)
	 *         <li> 3 ... The locality that called this command (long)
	 *         <li> 4 ... The wrapped response (TcBlobData)
	 *         </ul>
	 * 
	 * @throws  TcTpmException This exception indicates that a TPM error has occurred. The specific
	 *           error code id held by the exception.
	 * 
	 * @TPM_V2_R101 237
	 */
	public static Object[] TpmExecuteTransport(TcIStreamDest dest, TcBlobData wrappedCmd,
			long transHandle, TcTcsAuth inAuth1) throws TcTddlException, TcTpmException
	{

		TcBlobData inBlob = blobUINT16(TcTpmConstants.TPM_TAG_RQU_AUTH1_COMMAND);
		inBlob.append(blobUINT32(0)); // paramSize is set later
		inBlob.append(blobUINT32(TcTpmOrdinals.TPM_ORD_ExecuteTransport));
		inBlob.append(blobUINT32(wrappedCmd.getLengthAsLong()));
		inBlob.append(wrappedCmd);
		inBlob.append(blobUINT32(transHandle));
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
		long currentTicks = outBlob.decodeUINT32();
		long locality = outBlob.decodeUINT32();
		long wrappedRspSize = outBlob.decodeUINT32();
		TcBlobData wrappedRsp = outBlob.decodeBytes(wrappedRspSize);

		// decode 1st output auth
		TcTcsAuth outAuth1 = new TcTcsAuth();
		outAuth1.setAuthHandle(inAuth1.getAuthHandle());
		outAuth1.setNonceOdd(inAuth1.getNonceOdd());
		outAuth1.setNonceEven(new TcTpmNonce(outBlob)); // new nonce even from TPM
		outAuth1.setContAuthSession(outBlob.decodeBoolean());
		outAuth1.setHmac(new TcTpmAuthdata(outBlob));
		trackAuthSession(inAuth1, outAuth1);

		return new Object[] { outBlob.getRetCodeAsLong(), outAuth1, new Long(currentTicks),
				new Long(locality), wrappedRsp };
	}


	/*************************************************************************************************
	 * 
	 * 
	 * @param dest The destination where the byte stream is written to.
	 * @param inAuth1 Authorization values for first authorization session.
	 * @param inAuth2 Authorization values for second authorization session.
	 * @param keyHandle Handle of a loaded key that will perform the signing
	 * @param antiReplay Value provided by caller for anti-replay protection
	 * @param transHandle The transport session handle
	 * 
	 * @return The returned Object[] holds the following elements:
	 *         <ul>
	 *         <li> 0 ... TPM return code (Long)
	 *         <li> 1 ... outgoing authorization for 1st session containing new nonceEven (TcTpmAuth)
	 *         <li> 2 ... outgoing authorization for 2nd session containing new nonceEven (TcTpmAuth)
	 *         <li> 3 ... The locality that called this command (long)
	 *         <li> 4 ... The current ticks when the commandexecuted (TcTpmCurrentTicks)
	 *         <li> 5 ... The signature of the digest (TcBlobData)
	 *         </ul>
	 * 
	 * @throws  TcTpmException This exception indicates that a TPM error has occurred. The specific
	 *           error code id held by the exception.
	 * 
	 * @TPM_V2_R101 244
	 */
	public static Object[] TpmReleaseTransportSigned(TcIStreamDest dest, long keyHandle,
			TcTpmNonce antiReplay, long transHandle, TcTcsAuth inAuth1, TcTcsAuth inAuth2)
		throws TcTddlException, TcTpmException
	{

		TcBlobData inBlob = blobUINT16(TcTpmConstants.TPM_TAG_RQU_AUTH2_COMMAND);
		inBlob.append(blobUINT32(0)); // paramSize is set later
		inBlob.append(blobUINT32(TcTpmOrdinals.TPM_ORD_ReleaseTransportSigned));
		inBlob.append(blobUINT32(keyHandle));
		inBlob.append(antiReplay.getEncoded());
		inBlob.append(blobUINT32(inAuth1.getAuthHandle()));
		inBlob.append(inAuth1.getNonceOdd().getEncoded());
		inBlob.append(blobBOOL(inAuth1.getContAuthSession()));
		inBlob.append(inAuth1.getHmac().getEncoded());
		inBlob.append(blobUINT32(transHandle));
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
		long locality = outBlob.decodeUINT32();
		TcTpmCurrentTicks currentTicks = new TcTpmCurrentTicks(outBlob);
		long signSize = outBlob.decodeUINT32();
		TcBlobData signature = outBlob.decodeBytes(signSize);

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

		return new Object[] { outBlob.getRetCodeAsLong(), outAuth1, outAuth2, new Long(locality),
				currentTicks, signature };
	}
}
