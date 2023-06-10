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
import iaik.tc.tss.impl.java.tddl.TcIStreamDest;

public class TcTpmCmdAdminStartup extends TcTpmCmdCommon {

	/*************************************************************************************************
	 * TPM_Startup is always preceded by TPM_Init, which is the physical indication (a systemwide
	 * reset) that TPM initialization is necessary. There are many events on a platform that can cause
	 * a reset and the response to these events can require different operations to occur on the TPM.
	 * The mere reset indication does not contain sufficient information to inform the TPM as to what
	 * type of reset is occurring. Additional information known by the platform initialization code
	 * needs transmitting to the TPM. The TPM_Startup command provides the mechanism to transmit the
	 * information.
	 * 
	 * The TPM can startup in three different modes: A "clear" start where all variables go back to
	 * their default or non-volatile set state A "save" start where the TPM recovers appropriate
	 * information and restores various values based on a prior TPM_SaveState. This recovery requires
	 * an invocation of TPM_Init to be successful. A failing "save" start must shut down the TPM. The
	 * CRTM cannot leave the TPM in a state where an untrusted upper software layer could issue a
	 * "clear" and then extend PCR's and thus mimic the CRTM. A "deactivated" start where the TPM
	 * turns itself off and requires another TPM_Init before the TPM will execute in a fully
	 * operational state.
	 * 
	 * @param dest The destination where the byte stream is written to.
	 * @param startupType This flag specifies the type of startup. Legal values are
	 *          {@link TcTpmConstants#TPM_ST_CLEAR}, {@link TcTpmConstants#TPM_ST_STATE} and
	 *          {@link TcTpmConstants#TPM_ST_DEACTIVATED}.
	 * 
	 * @throws  TcTpmException This exception indicates that a TPM error has occurred. The specific
	 *           error code id held by the exception.
	 * 
	 * @TPM_V2_R101 6
	 */
	public static Object[] TpmStartup(TcIStreamDest dest, int startupType) throws TcTddlException, TcTpmException
	{

		TcBlobData inBlob = blobUINT16(TcTpmConstants.TPM_TAG_RQU_COMMAND);
		inBlob.append(blobUINT32(0)); // paramSize is set later
		inBlob.append(blobUINT32(TcTpmOrdinals.TPM_ORD_Startup));
		inBlob.append(blobUINT16(startupType));

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
	 * This command warns a TPM to save some state information. If the relevant shielded storage is
	 * non-volatile, this command need have no effect. If the relevant shielded storage is volatile
	 * and the TPM alone is unable to detect the loss of external power in time to move data to
	 * non-volatile memory, this command should be presented before the TPM enters a low or no power
	 * state.
	 * 
	 * @param dest The destination where the byte stream is written to.
	 * 
	 * @throws  TcTpmException This exception indicates that a TPM error has occurred. The specific
	 *           error code id held by the exception.
	 * 
	 * @TPM_V2_R101 9
	 */
	public static Object[] TpmSaveState(TcIStreamDest dest) throws TcTddlException, TcTpmException
	{

		TcBlobData inBlob = blobUINT16(TcTpmConstants.TPM_TAG_RQU_COMMAND);
		inBlob.append(blobUINT32(0)); // paramSize is set later
		inBlob.append(blobUINT32(TcTpmOrdinals.TPM_ORD_SaveState));

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
