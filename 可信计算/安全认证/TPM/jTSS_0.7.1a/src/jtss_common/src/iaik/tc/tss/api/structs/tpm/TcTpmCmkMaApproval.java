/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.api.structs.tpm;


import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder;
import iaik.tc.utils.misc.Utils;

public class TcTpmCmkMaApproval extends TcCompositeTypeDecoder {
	protected int tag_;

	protected TcTpmDigest migrationAuthorityDigest_;


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder()
	 */
	public TcTpmCmkMaApproval()
	{
		super();
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcBlobData)
	 */
	public TcTpmCmkMaApproval(TcBlobData data)
	{
		super(data);
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcBlobData,
	 *      int)
	 */
	public TcTpmCmkMaApproval(TcBlobData data, int offset)
	{
		super(data, offset);
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder)
	 */
	public TcTpmCmkMaApproval(TcCompositeTypeDecoder composite)
	{
		super(composite);
	}


	/*************************************************************************************************
	 * This method decodes the TPM_CMK_MA_APPROVAL from the byte blob.
	 */
	protected void decode()
	{
		checkBoundaryPreconditions(22);

		tag_ = decodeUINT16();
		migrationAuthorityDigest_ = new TcTpmDigest(this);

	}


	/*************************************************************************************************
	 * This method encodes the TPM_CMK_MA_APPROVAL as a byte blob.
	 */
	public TcBlobData getEncoded()
	{
		TcBlobData retVal = TcBlobData.newUINT16( tag_);
		if (migrationAuthorityDigest_ != null) {
			retVal.append(migrationAuthorityDigest_.getEncoded());
		}

		return retVal;
	}


	/*************************************************************************************************
	 * This method returns a String representation of the object.
	 */
	public String toString()
	{
		StringBuffer retVal = new StringBuffer();

		retVal.append("tag: ");
		retVal.append(tag_);
		retVal.append(Utils.getNL());
		if (migrationAuthorityDigest_ != null) {
			retVal.append("migrationAuthorityDigest: ");
			retVal.append(migrationAuthorityDigest_.toString());
			retVal.append(Utils.getNL());
		}

		return retVal.toString();
	}


	/*************************************************************************************************
	 * Returns contents of the tag field.
	 */
	public int getTag()
	{
		return tag_;
	}


	/*************************************************************************************************
	 * Sets the tag field.
	 */
	public void setTag(int tag)
	{
		tag_ = tag;
	}


	/*************************************************************************************************
	 * Returns contents of the migrationAuthorityDigest field.
	 */
	public TcTpmDigest getMigrationAuthorityDigest()
	{
		return migrationAuthorityDigest_;
	}


	/*************************************************************************************************
	 * Sets the migrationAuthorityDigest field.
	 */
	public void setMigrationAuthorityDigest(TcTpmDigest migrationAuthorityDigest)
	{
		migrationAuthorityDigest_ = migrationAuthorityDigest;
	}

}
