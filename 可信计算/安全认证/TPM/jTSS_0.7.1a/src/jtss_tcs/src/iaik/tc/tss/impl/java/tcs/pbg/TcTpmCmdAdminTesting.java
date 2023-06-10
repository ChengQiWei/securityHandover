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

public class TcTpmCmdAdminTesting extends TcTpmCmdCommon {

	/*************************************************************************************************
	 * This command tests all of the TPM capabilities. Unlike TpmContinueSelfTest, which may
	 * optionally return immediately and then perform the tests, TPM_SelfTestFull always performs the
	 * tests and then returns success or failure.
	 * 
	 * @param dest The destination where the byte stream is written to.
	 * 
	 * @throws  TcTpmException This exception indicates that a TPM error has occurred. The specific
	 *           error code id held by the exception.
	 * 
	 * @TPM_V2_R101 11
	 */
	public static Object[] TpmSelfTestFull(TcIStreamDest dest) throws TcTddlException, TcTpmException
	{

		TcBlobData inBlob = blobUINT16(TcTpmConstants.TPM_TAG_RQU_COMMAND);
		inBlob.append(blobUINT32(0)); // paramSize is set later
		inBlob.append(blobUINT32(TcTpmOrdinals.TPM_ORD_SelfTestFull));

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
	 * After initialization (TpmInit) the TPM performs a limited self-test ensuring that a limited set
	 * of TPM commands will perform properly. This limitation allows the TPM to become operational in
	 * a small amount of time.
	 * 
	 * The command set available after this limited self-test includes TpmExtend (allowing
	 * measurements at an early stage of boot-up), TpmStartup, TpmContinueSelftest, TpmSelfTestFull
	 * and TpmGetCapability.
	 * 
	 * The TpmContinueSelftest command informs the TPM that it should complete the self-test of all
	 * further TPM functions. The TPM may return success immediately and then perform the self-test,
	 * or it may perform the self-test and then return success or failure.
	 * 
	 * @param dest The destination where the byte stream is written to.
	 * 
	 * @throws  TcTpmException This exception indicates that a TPM error has occurred. The specific
	 *           error code id held by the exception.
	 * 
	 * @TPM_V2_R101 12
	 */
	public static Object[] TpmContinueSelfTest(TcIStreamDest dest) throws TcTddlException, TcTpmException
	{

		TcBlobData inBlob = blobUINT16(TcTpmConstants.TPM_TAG_RQU_COMMAND);
		inBlob.append(blobUINT32(0)); // paramSize is set later
		inBlob.append(blobUINT32(TcTpmOrdinals.TPM_ORD_ContinueSelfTest));

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
	 * TpmGetTestResult provides manufacturer specific information regarding the results of the
	 * self-test. This command will work when the TPM is in limited operation mode or self-test
	 * failure mode. The reason for allowing this command to operate in the failure mode is to allow
	 * TPM manufacturers to obtain diagnostic information.
	 * 
	 * @param dest The destination where the byte stream is written to.
	 * 
	 * @return TcBlobData Vendor specific test result.
	 * 
	 * @throws  TcTpmException This exception indicates that a TPM error has occurred. The specific
	 *           error code id held by the exception.
	 * 
	 * @TPM_V2_R101 14
	 */
	public static Object[] TpmGetTestResult(TcIStreamDest dest) throws TcTddlException, TcTpmException
	{

		TcBlobData inBlob = blobUINT16(TcTpmConstants.TPM_TAG_RQU_COMMAND);
		inBlob.append(blobUINT32(0)); // paramSize is set later
		inBlob.append(blobUINT32(TcTpmOrdinals.TPM_ORD_GetTestResult));

		// all parameters filled in - set the length of the blob
		setParamSize(inBlob);

		// send byte stream
		TcBlobData tpmOutBlob = dest.transmitData(inBlob);
		TcTpmGenericReturnBlob outBlob = new TcTpmGenericReturnBlob(tpmOutBlob);

		// check TPM return code: if call was not successful, an exception is thrown
		handleRetCode(outBlob);

		// decode output values
		long outDataSize = outBlob.decodeUINT32();
		TcBlobData outData = outBlob.decodeBytes(outDataSize);

		return new Object[] { outBlob.getRetCodeAsLong(), outData };
	}
}
