/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.impl.java.tcs;


import iaik.tc.tss.api.constants.tpm.TcTpmConstants;
import iaik.tc.tss.api.exceptions.tcs.TcTddlException;
import iaik.tc.tss.api.exceptions.tcs.TcTpmException;
import iaik.tc.tss.api.structs.common.TcBasicTypeDecoder;
import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.tss.impl.java.tcs.pbg.TcTpmCmdCapability;
import iaik.tc.tss.impl.java.tddl.TcTddl;

import java.util.SortedMap;
import java.util.TreeMap;

/**
 * This class provides methods that are commonly used throughout the TCS. This includes e.g.
 * checking if a specific command ordinal is supported by the TPM. One example is to determine if
 * LoadKey oder LoadKey2 should be used.
 */
public class TcTcsCommon {

	/**
	 * cache of supported ordinals (mapping: <Long>Ordinal -> <Boolean>isSupported)
	 */
	protected static SortedMap supportedOrdinals_ = new TreeMap();

	/**
	 * This field holds the number of PCRs supported by this TPM.
	 */
	protected static long numPcrs_ = 0;

	/**
	 * TPM manufacturer string for TPM emulator.
	 */
	public static String TPM_MAN_ETHZ = "ETHZ";


	/*************************************************************************************************
	 * This method allows to check if a given command ordinal is supported by the TPM. The same
	 * functionality can be achieved using the getCapability functionality to check for supported
	 * ordinals. This method however, is simpler to use and additionally provides caching of the
	 * results. In cases where the same ordinal is queried more than once, this method avoids the
	 * calls to the TPM.
	 * 
	 * @param ordinal The TPM command ordinal to be checked.
	 * 
	 * @return Returns true if the ordinal is supported, false otherwise.
	 * 
	 * @throws {@link TcTddlException}
	 * @throws {@link TcTpmException}
	 */
	public static boolean isOrdinalSupported(long ordinal)
			throws TcTddlException, TcTpmException {
		return isOrdinalSupported(TcTddl.getInstance(), ordinal);
	}

	/*************************************************************************************************
	 * This method allows to check if a given command ordinal is supported by the TPM. The same
	 * functionality can be achieved using the getCapability functionality to check for supported
	 * ordinals. This method however, is simpler to use and additionally provides caching of the
	 * results. In cases where the same ordinal is queried more than once, this method avoids the
	 * calls to the TPM.
	 * 
	 * @param tddl The TcTddl to use.
	 * @param ordinal The TPM command ordinal to be checked.
	 * 
	 * @return Returns true if the ordinal is supported, false otherwise.
	 * 
	 * @throws {@link TcTddlException}
	 * @throws {@link TcTpmException}
	 */
	public static boolean isOrdinalSupported(TcTddl tddl, long ordinal)
			throws TcTddlException, TcTpmException {

		Long ord = new Long(ordinal);

		synchronized (supportedOrdinals_) {
			if (supportedOrdinals_.containsKey(ord)) {
				Boolean isSppurted = (Boolean) supportedOrdinals_.get(ord);
				return isSppurted.booleanValue();
			} else {
				TcBlobData subCap = TcBlobData.newUINT32(ordinal);
				Object[] tpmOutData = TcTpmCmdCapability.TpmGetCapability(tddl,
						TcTpmConstants.TPM_CAP_ORD, subCap);
				TcBlobData isSupportedBlob = (TcBlobData) tpmOutData[1];
				boolean retVal = new TcBasicTypeDecoder(isSupportedBlob)
						.decodeBoolean();
				supportedOrdinals_.put(ord, new Boolean(retVal));
				return retVal;
			}
		}
	}

	/*************************************************************************************************
	 * This method checks if the manufacturer string of the TPM matches the
	 * provided one.
	 */
	public static boolean tpmManufacturerIs(String manString)
			throws TcTddlException, TcTpmException {
		return tpmManufacturerIs(TcTddl.getInstance(), manString);
	}

	/*************************************************************************************************
	 * This method checks if the manufacturer string of the TPM matches the
	 * provided one.
	 */
	public static boolean tpmManufacturerIs(TcTddl tddl, String manString)
			throws TcTddlException, TcTpmException {
		TcBlobData subCap = TcBlobData
				.newUINT32(TcTpmConstants.TPM_CAP_PROP_MANUFACTURER);
		Object[] tpmOutData = TcTpmCmdCapability.TpmGetCapability(tddl,
				TcTpmConstants.TPM_CAP_PROPERTY, subCap);
		return (((TcBlobData) tpmOutData[1]).toStringASCII().equals(manString));
	}


	/*************************************************************************************************
	 * This method returns the number of PCRs supported by the TPM.
	 */
	public static long getNumPcrs() throws TcTddlException, TcTpmException
	{
		if (numPcrs_ == 0) {
			TcTddl dest = TcTddl.getInstance();
			TcBlobData subCap = TcBlobData.newUINT32(TcTpmConstants.TPM_CAP_PROP_PCR);
			Object[] tpmOutData = TcTpmCmdCapability.TpmGetCapability(dest,
					TcTpmConstants.TPM_CAP_PROPERTY, subCap);
			numPcrs_ = new TcBasicTypeDecoder(((TcBlobData) tpmOutData[1])).decodeUINT32();
		}

		return numPcrs_;
	}

}
