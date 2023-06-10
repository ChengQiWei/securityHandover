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
import iaik.tc.tss.api.structs.tpm.TcTpmDigest;
import iaik.tc.tss.api.structs.tpm.TcTpmGenericReturnBlob;
import iaik.tc.tss.impl.java.tddl.TcIStreamDest;

public class TcTpmCmdVendorSpecific extends TcTpmCmdCommon {

	
	/*************************************************************************************************
	 * This method reads the EK certificate embedded in 1.1b Infineon chips. The certificate is not
	 * read in one piece but it is split into several parts which have to be read one by one and then
	 * put together.
	 * Note that this functionality is vendor specific for Infineon 1.1b TPMs!
	 * 
	 * @param dest The destination where the byte stream is written to.
	 * @param index The index of the certificate part to be read.
	 * @param antiReplay Nonce received form the TSP that is included in the checksum calculation.
	 * 
	 * @return The returned Object[] holds the following elements:
	 *         <ul>
	 *         <li> 0 ... max part index (short)
	 *         <li> 1 ... checksum (TcTpmDigest)
	 *         <li> 2 ... the requested part of the certificate (TcBlobData)
	 *         </ul>
	 *         
	 * @throws TcTddlException
	 * @throws TcTpmException
	 */
	public static Object[] IfxReadTpm11EkCert(TcIStreamDest dest, byte index, TcBlobData antiReplay)
		throws TcTddlException, TcTpmException
	{
		TcBlobData inBlob = blobUINT16(TcTpmConstants.TPM_TAG_RQU_COMMAND);
		inBlob.append(blobUINT32(0)); // paramSize is set later
		inBlob.append(blobUINT32(TcTpmOrdinals.TPM_ORD_IFX_ReadCert11));
		inBlob.append(blobBYTE(index));
		inBlob.append(antiReplay);

		// all params filled in - set the length of the blob
		setParamSize(inBlob);

		// send byte stream
		TcBlobData tpmOutBlob = dest.transmitData(inBlob);
		TcTpmGenericReturnBlob outBlob = new TcTpmGenericReturnBlob(tpmOutBlob);

		// check TPM return code: if call was not successful, an exception is thrown
		handleRetCode(outBlob);

		// decode output values
		short maxIndex = outBlob.decodeByte();
		TcTpmDigest checksum = new TcTpmDigest(outBlob);
		long sizeOfEkCertPart = outBlob.decodeUINT32();
		TcBlobData ekCertPart = outBlob.decodeBytes(sizeOfEkCertPart);

		
		return new Object[] { new Short(maxIndex), checksum, ekCertPart };
	}

}
