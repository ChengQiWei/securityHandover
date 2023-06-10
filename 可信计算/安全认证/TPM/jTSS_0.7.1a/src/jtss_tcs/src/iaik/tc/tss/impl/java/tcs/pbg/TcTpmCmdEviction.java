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

/**
 * The TPM has numerous resources held inside of the TPM that may need eviction. The need for
 * eviction occurs when the number or resources in use by the TPM exceed the available space. For
 * resources that are hard to reload (i.e. keys tied to PCR values) the outside entity should first
 * perform a context save before evicting items. In version 1.1 there were separate commands to
 * evict separate resource types. This new command set uses the resource types defined for context
 * saving and creates a generic command that will evict all resource types.
 */
public class TcTpmCmdEviction extends TcTpmCmdCommon {

	/*************************************************************************************************
	 * This command flushes a handle of the given resource type from the TPM. The resources associated
	 * with the given handle are freed.
	 * 
	 * @param dest The destination where the byte stream is written to.
	 * @param handle The handle of the item to flush
	 * @param resourceType The type of resource that is being flushed
	 * 
	 * @return The returned Object[] holds the following elements:
	 *         <ul>
	 *         <li> 0 ... TPM return code (Long)
	 *         </ul>
	 * 
	 * @throws  TcTpmException This exception indicates that a TPM error has occurred. The specific
	 *           error code id held by the exception.
	 * 
	 * @TPM_V2_R101 227
	 */
	public static Object[] TpmFlushSpecific(TcIStreamDest dest, long handle, long resourceType)
		throws TcTddlException, TcTpmException
	{

		TcBlobData inBlob = blobUINT16(TcTpmConstants.TPM_TAG_RQU_COMMAND);
		inBlob.append(blobUINT32(0)); // paramSize is set later
		inBlob.append(blobUINT32(TcTpmOrdinals.TPM_ORD_FlushSpecific));
		inBlob.append(blobUINT32(handle));
		inBlob.append(blobUINT32(resourceType));

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
