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
import iaik.tc.tss.api.structs.tpm.TcTpmGenericReturnBlob;
import iaik.tc.tss.api.structs.tpm.TcTpmNonce;
import iaik.tc.tss.api.structs.tpm.TcTpmSecret;
import iaik.tc.tss.impl.java.tddl.TcIStreamDest;

/**
 * This class provides a set of TPM commands to control the enable/disable and activate/deactivate
 * flags of the TPM.
 * 
 * In inactive or disabled state, a TPM is not able to execute commands that use the resources of
 * the TPM (e.g. loading keys). The difference between inactive and disabled is that a disabled TPM
 * is unable to execute the TpmTakeOwnership command. An deactivated TPM, however, is able to
 * execute the TpmTakeOwnership command.
 * 
 * The enable/disable state of a TPM is controlled by a permanent flag called pFlags.tpmDisabled.
 * Setting this flag to TRUE means that the TPM is disabled while setting it to FALSE means that the
 * TPM is enabled. From the disabled state the transition to the enabled state can occur using the
 * TpmOwnerSetDisable command (requires owner authorization) or the TpmPhysicalEnable command
 * (requires physical presence as authorization). From the enabled state the transition to the
 * disabled state can occur using the TpmOwnerSetDisable command (requires owner authorization) or
 * the TpmPhysicalDisable command (requires physical presence as authorization).
 * 
 * Controlling the activation state of the TPM involves both, permanent and volatile flags. The
 * pFlags.tpmDeacticated flags is copied to vFlags.tpmDeactivated during initialization. The TPM
 * then only references this volatile flag during execution. The TomSetTempDeactivated command
 * temporarily deactivates the TPM (until next reboot). What this command does is setting the
 * vFlags.tpmDeactivated flag to TRUE. The only possible way to reset the vFlags.tpmDeactivated
 * flags is rebooting the platform where the pFlags.tpmDeactivated is copied to
 * vFlags.tpmDeactivate. Toggling the state of pFlags.tpmDeactivated requires physical presence and
 * is done via the TpmPhysicalSetDeactivated command. The toggling of pFlags.tpmDeactivated does not
 * affect the current operation since the vFlags.tpmDeactivated is not modified. A reboot of the
 * platform is required where the pFlags.tpmDeactivated is copied into vFlags.tpmDeactivated.
 * 
 * The TPM spec gives the following the rationales for the existence of the (de)activation flag:
 * 
 * (1) TPM activation is for Operator convenience. It allows the operator to deactivate the platform
 * (temporarily, using TPM_SetTempDeactivated) during a user session when the operator does not want
 * to disclose platform or attestation identity. This provides operator privacy, since PCRs could
 * provide cryptographic proof of an operation. PCRs are inaccessible when a TPM is deactivated.
 * They cannot be used for authorization, nor can they be read. The reboot required to activate a
 * TPM also resets the PCRs.
 * 
 * (2) Deactivated may be used to prevent the (obscure) attack where a TPM is readied for
 * TPM_TakeOwnership but a remote rogue manages to take ownership of a platform just before the
 * genuine owner, and immediately has use of the TPM's facilities. To defeat this attack, a genuine
 * owner should set disable==FALSE, ownership==TRUE, deactivate==TRUE, execute TpmTakeOwnership, and
 * then set deactivate==FALSE after verifying that the genuine owner is the actual TPM owner.
 * 
 * A note on physical presence: Physical presence is indicated by the vFlags.PhysicalPresence flag.
 * vFlags.PhasicalPresence == TRUE is a requirement for several TPM commands. The actual
 * implementation of the physical presence assertion mechanism is up to the TPM and platform
 * manufacturer.
 */
public class TcTpmCmdAdminOptIn extends TcTpmCmdCommon {

	/*************************************************************************************************
	 * When enabled but without an owner this command sets the pFlags.ownershipDisabled that allows or
	 * disallows the ability to insert an owner. This command requires physical presence.
	 * 
	 * @param dest The destination where the byte stream is written to.
	 * @param state State to which ownership flag is to be set.
	 * 
	 * @throws TcTpmException This exception indicates that a TPM error has occurred. The specific
	 *           error code id held by the exception.
	 * 
	 * @TPM_V2_R101 15
	 */
	public static Object[] TpmSetOwnerInstall(TcIStreamDest dest, boolean state)
		throws TcTddlException, TcTpmException
	{

		TcBlobData inBlob = blobUINT16(TcTpmConstants.TPM_TAG_RQU_COMMAND);
		inBlob.append(blobUINT32(0)); // paramSize is set later
		inBlob.append(blobUINT32(TcTpmOrdinals.TPM_ORD_SetOwnerInstall));
		inBlob.append(blobBOOL(state));

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
	 * The TpmOwnerSetDisable command can be used by the TPM owner to set the pFalgs.tpmDisabled.
	 * Setting this value to true means that the TPM is disabled, setting it to false means that the
	 * TPM is enabled. This command is suitable for post-boot and remote invocation.
	 * 
	 * @param dest The destination where the byte stream is written to.
	 * @param disableState Value for disable state (enable if TRUE)
	 * @param inAuth1 The authorization session digest for inputs and owner authentication.
	 * 
	 * @return The authorization values for the session containing new nonceEven
	 * 
	 * @throws TcTpmException This exception indicates that a TPM error has occurred. The specific
	 *           error code id held by the exception.
	 * 
	 * @TPM_V2_R101 16
	 */
	public static Object[] TpmOwnerSetDisable(TcIStreamDest dest, boolean disableState,
			TcTcsAuth inAuth1) throws TcTddlException, TcTpmException
	{

		TcBlobData inBlob = blobUINT16(TcTpmConstants.TPM_TAG_RQU_AUTH1_COMMAND);
		inBlob.append(blobUINT32(0)); // paramSize is set later
		inBlob.append(blobUINT32(TcTpmOrdinals.TPM_ORD_OwnerSetDisable));
		inBlob.append(blobBOOL(disableState));
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
	 * This method sets the pFlags.tpmDisabled to FALSE using physical presence as authorization. An
	 * un-owned TPM requires physical presence to be enabled. This command can also be used if the TPM
	 * is already owned.
	 * 
	 * @param dest The destination where the byte stream is written to.
	 * 
	 * @throws TcTpmException This exception indicates that a TPM error has occurred. The specific
	 *           error code id held by the exception.
	 * 
	 * @TPM_V2_R101 17
	 */
	public static Object[] TpmPhysicalEnable(TcIStreamDest dest)
		throws TcTddlException, TcTpmException
	{

		TcBlobData inBlob = blobUINT16(TcTpmConstants.TPM_TAG_RQU_COMMAND);
		inBlob.append(blobUINT32(0)); // paramSize is set later
		inBlob.append(blobUINT32(TcTpmOrdinals.TPM_ORD_PhysicalEnable));

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
	 * This method sets the pFlags.tpmDisabled to TRUE using physical presence as authorization. Using
	 * this command, an operator can disabled a TPM without knowing the owner secret. Physical
	 * presence is sufficient as an authorization for this operation.
	 * 
	 * @param dest The destination where the byte stream is written to.
	 * 
	 * @throws TcTpmException This exception indicates that a TPM error has occurred. The specific
	 *           error code id held by the exception.
	 * 
	 * @TPM_V2_R101 18
	 */
	public static Object[] TpmPhysicalDisable(TcIStreamDest dest)
		throws TcTddlException, TcTpmException
	{

		TcBlobData inBlob = blobUINT16(TcTpmConstants.TPM_TAG_RQU_COMMAND);
		inBlob.append(blobUINT32(0)); // paramSize is set later
		inBlob.append(blobUINT32(TcTpmOrdinals.TPM_ORD_PhysicalDisable));

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
	 * This command allows to modify the pFlags.tpmDeactivated flag using physical presence as
	 * authorization. The contents of pFlags.tpmDeactivated is copied into vFlags.tpmDeactivated upon
	 * TPM initialization.
	 * 
	 * @param dest The destination where the byte stream is written to.
	 * @param state State to which deactivated flag is to be set.
	 * 
	 * @throws TcTpmException This exception indicates that a TPM error has occurred. The specific
	 *           error code id held by the exception.
	 * 
	 * @TPM_V2_R101 19
	 */
	public static Object[] TpmPhysicalSetDeactivated(TcIStreamDest dest, boolean state)
		throws TcTddlException, TcTpmException
	{

		TcBlobData inBlob = blobUINT16(TcTpmConstants.TPM_TAG_RQU_COMMAND);
		inBlob.append(blobUINT32(0)); // paramSize is set later
		inBlob.append(blobUINT32(TcTpmOrdinals.TPM_ORD_PhysicalSetDeactivated));
		inBlob.append(blobBOOL(state));

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
	 * This command allows the operator of the platform to deactivate the TPM until the next boot of
	 * the platform. This is done by setting the vFlags.tpmDeactivated to TRUE. Setting this flag does
	 * not affect the pFlags.tpmDeactivated which copied to vFalgs.tpmDeactivated at TPM
	 * initialization. This command requires operator authentication.
	 * 
	 * @param dest The destination where the byte stream is written to.
	 * @param inAuth1 HMAC key: operatorAuth
	 * 
	 * @return The authorization values for session containing the new nonceEven.
	 * 
	 * @throws TcTpmException This exception indicates that a TPM error has occurred. The specific
	 *           error code id held by the exception.
	 * 
	 * @TPM_V2_R101 20
	 */
	public static Object[] TpmSetTempDeactivated(TcIStreamDest dest, TcTcsAuth inAuth1)
		throws TcTddlException, TcTpmException
	{

		TcBlobData inBlob = blobUINT16(TcTpmConstants.TPM_TAG_RQU_AUTH1_COMMAND);
		inBlob.append(blobUINT32(0)); // paramSize is set later
		inBlob.append(blobUINT32(TcTpmOrdinals.TPM_ORD_SetTempDeactivated));
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
	 * This command allows deactivation the TPM until the next boot of the platform. This is done by
	 * setting the vFlags.tpmDeactivated to TRUE. Setting this flag does not affect the
	 * pFlags.tpmDeactivated which copied to vFalgs.tpmDeactivated at TPM initialization. 
	 * This command requires physical presence.
	 * 
	 * @param dest
	 * 
	 * @throws TcTddlException
	 * @throws TcTpmException
	 */
	public static Object[] tpmSetTempDeactivatedNoAuth(TcIStreamDest dest)
		throws TcTddlException, TcTpmException
	{

		TcBlobData inBlob = blobUINT16(TcTpmConstants.TPM_TAG_RQU_COMMAND);
		inBlob.append(blobUINT32(0)); // paramSize is set later
		inBlob.append(blobUINT32(TcTpmOrdinals.TPM_ORD_SetTempDeactivated));

		// all parameters filled in - set the length of the blob
		setParamSize(inBlob);

		// send byte stream
		TcBlobData tpmOutBlob = dest.transmitData(inBlob);
		TcTpmGenericReturnBlob outBlob = new TcTpmGenericReturnBlob(tpmOutBlob);

		// check TPM return code: if call was not successful, an exception is thrown
		handleRetCode(outBlob);

		return new Object[] { outBlob.getRetCodeAsLong() };
	}


	/*************************************************************************************************
	 * This command allows the setting of the operator AuthData value. There is no confidentiality
	 * applied to the operator authentication as the value is send under the assumption of being local
	 * to the platform (i.e. physical presence is required). If there is a concern regarding the path
	 * between the TPM and the keyboard then unless the keyboard is using encryption and a secure
	 * channel an attacker can read the values.
	 * 
	 * @param dest The destination where the byte stream is written to.
	 * @param operatorAuth The operator AuthData
	 * 
	 * @return TcTpmGenericReturnBlob holding the data received from the TPM
	 * 
	 * @throws TcTpmException This exception indicates that a TPM error has occurred. The specific
	 *           error code id held by the exception.
	 * 
	 * @TPM_V2_R101 22
	 */
	public static Object[] TpmSetOperatorAuth(TcIStreamDest dest, TcTpmSecret operatorAuth)
		throws TcTddlException, TcTpmException
	{

		TcBlobData inBlob = blobUINT16(TcTpmConstants.TPM_TAG_RQU_COMMAND);
		inBlob.append(blobUINT32(0)); // paramSize is set later
		inBlob.append(blobUINT32(TcTpmOrdinals.TPM_ORD_SetOperatorAuth));
		inBlob.append(operatorAuth.getEncoded());

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