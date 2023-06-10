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
import iaik.tc.tss.api.structs.tpm.TcTpmGenericReturnBlob;
import iaik.tc.tss.api.structs.tpm.TcTpmKey;
import iaik.tc.tss.api.structs.tpm.TcTpmKey12;
import iaik.tc.tss.api.structs.tpm.TcTpmKey12New;
import iaik.tc.tss.api.structs.tpm.TcTpmKeyNew;
import iaik.tc.tss.api.structs.tpm.TcTpmNonce;
import iaik.tc.tss.impl.java.tddl.TcIStreamDest;

public class TcTpmCmdAdminOwnership extends TcTpmCmdCommon {

	/*************************************************************************************************
	 * This command inserts the TPM ownership value into the TPM. There must be no mechanism to
	 * recover this owner secret from the TPM. Recovery would mean removing the old value and setting
	 * a new one. To take ownership, the TPM must be enabled, activated and the
	 * pFlags.OwnershipDisabled flag must be FALSE.
	 * 
	 * @param dest The destination where the byte stream is written to.
	 * @param inAuth1 Authorization values for first authorization session.
	 * @param protocolID The ownership protocol in use.
	 * @param encOwnerAuth The owner AuthData encrypted with PUBEK
	 * @param encSrkAuth The SRK AuthData encrypted with PUBEK
	 * @param srkParams Structure containing all parameters of new SRK. pubKey.keyLength & encSize are
	 *          both 0. This structure may be TcTpmKey or TcTpmKey12.
	 * 
	 * @return The returned Object[] holds the following elements:
	 *         <ul>
	 *         <li> 0 ... TPM return code (Long)
	 *         <li> 1 ... outgoing authorization for session containing new nonceEven (TcTpmAuth)
	 *         <li> 2 ... Structure containing all parameters of new SRK. srkPub.encData is set to 0.
	 *         </ul>
	 * 
	 * @throws  TcTpmException This exception indicates that a TPM error has occurred. The specific
	 *           error code id held by the exception.
	 * 
	 * @TPM_V2_R101 23
	 */
	public static Object[] TpmTakeOwnership(TcIStreamDest dest, int protocolID,
			TcBlobData encOwnerAuth, TcBlobData encSrkAuth, TcITpmKeyNew srkParams, TcTcsAuth inAuth1)
		throws TcTddlException, TcTpmException
	{

		TcBlobData inBlob = blobUINT16(TcTpmConstants.TPM_TAG_RQU_AUTH1_COMMAND);
		inBlob.append(blobUINT32(0)); // paramSize is set later
		inBlob.append(blobUINT32(TcTpmOrdinals.TPM_ORD_TakeOwnership));
		inBlob.append(blobUINT16(protocolID));
		inBlob.append(blobUINT32(encOwnerAuth.getLengthAsLong()));
		inBlob.append(encOwnerAuth);
		inBlob.append(blobUINT32(encSrkAuth.getLengthAsLong()));
		inBlob.append(encSrkAuth);
		inBlob.append(srkParams.getEncoded());
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
		TcITpmKey srkPub = null;
		if (srkParams instanceof TcTpmKeyNew) {
			srkPub = new TcTpmKey(outBlob); 
		} else if (srkParams instanceof TcTpmKey12New) {
			srkPub = new TcTpmKey12(outBlob); 
		} else {
			throw new IllegalArgumentException("srkParams must be of type TcTpmKeyNew or TcTpmKey12New.");
		}

		// decode 1st output auth
		TcTcsAuth outAuth1 = new TcTcsAuth();
		outAuth1.setAuthHandle(inAuth1.getAuthHandle());
		outAuth1.setNonceOdd(inAuth1.getNonceOdd());
		outAuth1.setNonceEven(new TcTpmNonce(outBlob)); // new nonce even from TPM
		outAuth1.setContAuthSession(outBlob.decodeBoolean());
		outAuth1.setHmac(new TcTpmAuthdata(outBlob));
		trackAuthSession(inAuth1, outAuth1);

		return new Object[] { outBlob.getRetCodeAsLong(), outAuth1, srkPub };
	}


	/*************************************************************************************************
	 * The TPM_OwnerClear command performs the clear operation under owner authentication. This
	 * command is available until the owner executes the TpmDisableOwnerClear, at which time any
	 * further invocation of this command returns TPM_CLEAR_DISABLED.
	 * 
	 * @param dest The destination where the byte stream is written to.
	 * @param inAuth1 Authorization values for first authorization session.
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
	 * @TPM_V2_R101 26
	 */
	public static Object[] TpmOwnerClear(TcIStreamDest dest, TcTcsAuth inAuth1)
		throws TcTddlException, TcTpmException
	{

		TcBlobData inBlob = blobUINT16(TcTpmConstants.TPM_TAG_RQU_AUTH1_COMMAND);
		inBlob.append(blobUINT32(0)); // paramSize is set later
		inBlob.append(blobUINT32(TcTpmOrdinals.TPM_ORD_OwnerClear));
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
	 * The TpmForceClear command performs the clear operation under physical presence. This command is
	 * available until the execution of the TpmDisableForceClear, at which time any further invocation
	 * of this command returns TPM_CLEAR_DISABLED.
	 * 
	 * @param dest The destination where the byte stream is written to.
	 * 
	 * @return The returned Object[] holds the following elements:
	 *         <ul>
	 *         <li> 0 ... TPM return code (Long)
	 *         </ul>
	 * 
	 * @throws  TcTpmException This exception indicates that a TPM error has occurred. The specific
	 *           error code id held by the exception.
	 * 
	 * @TPM_V2_R101 29
	 */
	public static Object[] TpmForceClear(TcIStreamDest dest) throws TcTddlException, TcTpmException
	{

		TcBlobData inBlob = blobUINT16(TcTpmConstants.TPM_TAG_RQU_COMMAND);
		inBlob.append(blobUINT32(0)); // paramSize is set later
		inBlob.append(blobUINT32(TcTpmOrdinals.TPM_ORD_ForceClear));

		// all parameters filled in - set the length of the blob
		setParamSize(inBlob);

		// send byte stream
		TcBlobData tpmOutBlob = dest.transmitData(inBlob);
		TcTpmGenericReturnBlob outBlob = new TcTpmGenericReturnBlob(tpmOutBlob);

		// check TPM return code: if call was not successful, an exception is thrown
		handleRetCode(outBlob);

		return new Object[] { outBlob.getRetCodeAsLong(), };
	}


	/*************************************************************************************************
	 * The TpmDisableOwnerClear command disables the ability to execute the TpmOwnerClear command
	 * permanently. Once invoked the only method of clearing the TPM will require physical access to
	 * the TPM. After the execution of TPM_ForceClear, ownerClear is re-enabled and must be explicitly
	 * disabled again by the new TPM Owner.
	 * 
	 * @param dest The destination where the byte stream is written to.
	 * @param inAuth1 Authorization values for first authorization session.
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
	 * @TPM_V2_R101 30
	 */
	public static Object[] TpmDisableOwnerClear(TcIStreamDest dest, TcTcsAuth inAuth1)
		throws TcTddlException, TcTpmException
	{

		TcBlobData inBlob = blobUINT16(TcTpmConstants.TPM_TAG_RQU_AUTH1_COMMAND);
		inBlob.append(blobUINT32(0)); // paramSize is set later
		inBlob.append(blobUINT32(TcTpmOrdinals.TPM_ORD_DisableOwnerClear));
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
	 * The TPM_DisableForceClear command disables the execution of the TPM_ForceClear command until
	 * the next startup cycle. Once this command is executed, the TPM_ForceClear is disabled until
	 * another startup cycle is run.
	 * 
	 * @param dest The destination where the byte stream is written to.
	 * 
	 * @return The returned Object[] holds the following elements:
	 *         <ul>
	 *         <li> 0 ... TPM return code (Long)
	 *         </ul>
	 * 
	 * @throws  TcTpmException This exception indicates that a TPM error has occurred. The specific
	 *           error code id held by the exception.
	 * 
	 * @TPM_V2_R101 31
	 */
	public static Object[] TpmDisableForceClear(TcIStreamDest dest) throws TcTddlException, TcTpmException
	{

		TcBlobData inBlob = blobUINT16(TcTpmConstants.TPM_TAG_RQU_COMMAND);
		inBlob.append(blobUINT32(0)); // paramSize is set later
		inBlob.append(blobUINT32(TcTpmOrdinals.TPM_ORD_DisableForceClear));

		// all parameters filled in - set the length of the blob
		setParamSize(inBlob);

		// send byte stream
		TcBlobData tpmOutBlob = dest.transmitData(inBlob);
		TcTpmGenericReturnBlob outBlob = new TcTpmGenericReturnBlob(tpmOutBlob);

		// check TPM return code: if call was not successful, an exception is thrown
		handleRetCode(outBlob);

		return new Object[] { outBlob.getRetCodeAsLong(), };
	}


	/*************************************************************************************************
	 * Some TPM operations require the indication of a human's physical presence at the platform. The
	 * presence of the human either provides another indication of platform ownership or a mechanism
	 * to ensure that the execution of the command is not the result of a remote software process.
	 * This command allows a process on the platform to indicate the assertion of physical presence.
	 * As this command is executable by software there must be protections against the improper
	 * invocation of this command. The physicalPresenceHWEnable and physicalPresenceCMDEnable indicate
	 * the ability for either SW or HW to indicate physical presence. These flags can be reset until
	 * the physicalPresenceLifetimeLock is set. The platform manufacturer should set these flags to
	 * indicate the capabilities of the platform the TPM is bound to. The command provides two sets of
	 * functionality. The first is to enable, permanently, either the HW or the SW ability to assert
	 * physical presence. The second is to allow SW, if enabled, to assert physical presence.
	 * 
	 * @param dest The destination where the byte stream is written to.
	 * @param physicalPresence The state to set the TPM's PhysicalPresence flags.
	 * 
	 * @return The returned Object[] holds the following elements:
	 *         <ul>
	 *         <li> 0 ... TPM return code (Long)
	 *         </ul>
	 * 
	 * @throws  TcTpmException This exception indicates that a TPM error has occurred. The specific
	 *           error code id held by the exception.
	 * 
	 * @TPM_V2_R101 35
	 */
	public static Object[] TscPhysicalPresence(TcIStreamDest dest, int physicalPresence)
		throws TcTddlException, TcTpmException
	{

		TcBlobData inBlob = blobUINT16(TcTpmConstants.TPM_TAG_RQU_COMMAND);
		inBlob.append(blobUINT32(0)); // paramSize is set later
		inBlob.append(blobUINT32(TcTpmOrdinals.TSC_ORD_PhysicalPresence));
		inBlob.append(blobUINT16(physicalPresence));

		// all parameters filled in - set the length of the blob
		setParamSize(inBlob);

		// send byte stream
		TcBlobData tpmOutBlob = dest.transmitData(inBlob);
		TcTpmGenericReturnBlob outBlob = new TcTpmGenericReturnBlob(tpmOutBlob);

		// check TPM return code: if call was not successful, an exception is thrown
		handleRetCode(outBlob);

		return new Object[] { outBlob.getRetCodeAsLong(), };
	}


	/*************************************************************************************************
	 * The PC TPM Interface Specification (TIS) specifies setting tpmEstablished to TRUE upon
	 * execution of the HASH_START sequence. The setting implies the creation of a Trusted Operating
	 * System on the platform. Platforms will use the value of tpmEstablished to determine if
	 * operations necessary to maintain the security perimeter are necessary. The tpmEstablished bit
	 * provides a non-volatile, secure reporting that a HASH_START was previously run on the platform.
	 * When a platform makes use of the tpmEstablished bit, the platform can reset tpmEstablished as
	 * the operation is no longer necessary. For example, a platform could use tpmEstablished to
	 * ensure that, if HASH_START had ever been, executed the platform could use the value to invoke
	 * special processing. Once the processing is complete the platform will wish to reset
	 * tpmEstablished to avoid invoking the special process again. The TPM_PERMANENT_FLAGS ->
	 * tpmEstablished bit described in the TPM specifications uses positive logic. The TPM_ACCESS
	 * register uses negative logic, so that TRUE is reflected as a 0.
	 * 
	 * @param dest The destination where the byte stream is written to.
	 * 
	 * @return The returned Object[] holds the following elements:
	 *         <ul>
	 *         <li> 0 ... TPM return code (Long)
	 *         </ul>
	 * 
	 * @throws  TcTpmException This exception indicates that a TPM error has occurred. The specific
	 *           error code id held by the exception.
	 * 
	 * @TPM_V2_R101 36
	 */
	public static Object[] TscResetEstablishmentBit(TcIStreamDest dest) throws TcTddlException, TcTpmException
	{

		TcBlobData inBlob = blobUINT16(TcTpmConstants.TPM_TAG_RQU_COMMAND);
		inBlob.append(blobUINT32(0)); // paramSize is set later
		inBlob.append(blobUINT32(TcTpmOrdinals.TSC_ORD_ResetEstablishmentBit));

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
