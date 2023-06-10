/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.api.structs.tpm;


import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder;

/**
 * This indicates the version of the structure.
 * 
 * Version 1.2 deprecates the use of this structure in all other structures. The TPM_STRUCT_VER
 * structure itself is not deprecated as many other structures that contain this structure are not
 * deprecated. The rationale behind keeping this structure and adding the new version structure is
 * that in version 1.1 this structure was in use for two purposes. The first was to indicate the
 * structure version, and in that mode the revMajor and revMinor were supposed to be set to 0. The
 * second use was in TPM_GetCapability and the structure would then return the correct revMajor and
 * revMinor. This use model caused problems in keeping track of when the revs were or were not set
 * and how software used the information.
 * 
 * Version 1.2 went to structure tags. Some structures did not change and the TPM_STRUCT_VER is
 * still in use To avoid the problems from 1.1, this structure now is a fixed value and only remains
 * for backwards compatibility. Structure versioning comes from the tag on the structure, and the
 * TPM_GetCapability response for TPM versioning uses TPM_VERSION.
 * 
 * 
 */
public class TcTpmStructVer extends TcTpmVersion {

	/** This constant can be used for TPM 1.1 version comparisons */
	public static final TcTpmStructVer TPM_V1_1 = new TcTpmStructVer();

	static {
		TPM_V1_1.setMajor((short)1);
		TPM_V1_1.setMinor((short)1);
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder()
	 */
	public TcTpmStructVer()
	{
		super();
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcBlobData)
	 */
	public TcTpmStructVer(TcBlobData data)
	{
		super(data);
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcBlobData,
	 *      int)
	 */
	public TcTpmStructVer(TcBlobData data, int offset)
	{
		super(data, offset);
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder)
	 */
	public TcTpmStructVer(TcCompositeTypeDecoder composite)
	{
		super(composite);
	}

}
