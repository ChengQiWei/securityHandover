/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.api.structs.tpm;

import java.util.Arrays;

import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.utils.misc.CheckPrecondition;

public class TcTpmStructsHelpers {

	private TcTpmStructsHelpers()
	{
	}


	/************************************************************************************************
	 * This method is used to determine if a struct (blob) received from the TPM is a 1.1. structure
	 * or not. The method relies on the fact that structures from the 1.1 TPM spec carry a
	 * TPM_STRUCT_VERSION as their first field. The first two bytes of this version are expected to
	 * be 0x01, 0x01. TPM 1.2 structures carry a 2 byte tag as their first field. 
	 */
	public static final boolean isTpm11Struct(TcBlobData struct)
	{
		CheckPrecondition.notNull(struct, "struct");
		byte[] structHeader = struct.getRange(0, 2);
		byte[] structHeader11 = new byte[] { 0x01, 0x01 };
		return Arrays.equals(structHeader, structHeader11);
	}
}
