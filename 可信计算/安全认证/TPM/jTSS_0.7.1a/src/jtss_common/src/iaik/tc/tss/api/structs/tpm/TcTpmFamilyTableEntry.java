/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.api.structs.tpm;


import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder;
import iaik.tc.utils.misc.Utils;

public class TcTpmFamilyTableEntry extends TcCompositeTypeDecoder {
	protected int tag_;

	protected TcTpmFamilyLabel label_;

	protected long familyID_;

	protected long verificationCount_;

	protected long flags_;


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder()
	 */
	public TcTpmFamilyTableEntry()
	{
		super();
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcBlobData)
	 */
	public TcTpmFamilyTableEntry(TcBlobData data)
	{
		super(data);
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcBlobData,
	 *      int)
	 */
	public TcTpmFamilyTableEntry(TcBlobData data, int offset)
	{
		super(data, offset);
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder)
	 */
	public TcTpmFamilyTableEntry(TcCompositeTypeDecoder composite)
	{
		super(composite);
	}


	/*************************************************************************************************
	 * This method decodes the TPM_FAMILY_TABLE_ENTRY from the byte blob.
	 */
	protected void decode()
	{
		checkBoundaryPreconditions(2 + 1 + 3 * 4);

		tag_ = decodeUINT16();
		label_ = new TcTpmFamilyLabel(this);
		familyID_ = decodeUINT32();
		verificationCount_ = decodeUINT32();
		flags_ = decodeUINT32();

	}


	/*************************************************************************************************
	 * This method encodes the TPM_FAMILY_TABLE_ENTRY as a byte blob.
	 */
	public TcBlobData getEncoded()
	{
		TcBlobData retVal = TcBlobData.newUINT16( tag_);
		if (label_ != null) {
			retVal.append(label_.getEncoded());
		}
		retVal.append(TcBlobData.newUINT32( familyID_));
		retVal.append(TcBlobData.newUINT32( verificationCount_));
		retVal.append(TcBlobData.newUINT32( flags_));

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
		if (label_ != null) {
			retVal.append("label: ");
			retVal.append(label_.toString());
			retVal.append(Utils.getNL());
		}
		retVal.append("familyID: ");
		retVal.append(familyID_);
		retVal.append(Utils.getNL());
		retVal.append("verificationCount: ");
		retVal.append(verificationCount_);
		retVal.append(Utils.getNL());
		retVal.append("flags: ");
		retVal.append(flags_);
		retVal.append(Utils.getNL());

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
	 * Returns contents of the label field.
	 */
	public TcTpmFamilyLabel getLabel()
	{
		return label_;
	}


	/*************************************************************************************************
	 * Sets the label field.
	 */
	public void setLabel(TcTpmFamilyLabel label)
	{
		label_ = label;
	}


	/*************************************************************************************************
	 * Returns contents of the familyID field.
	 */
	public long getFamilyID()
	{
		return familyID_;
	}


	/*************************************************************************************************
	 * Sets the familyID field.
	 */
	public void setFamilyID(long familyID)
	{
		familyID_ = familyID;
	}


	/*************************************************************************************************
	 * Returns contents of the verificationCount field.
	 */
	public long getVerificationCount()
	{
		return verificationCount_;
	}


	/*************************************************************************************************
	 * Sets the verificationCount field.
	 */
	public void setVerificationCount(long verificationCount)
	{
		verificationCount_ = verificationCount;
	}


	/*************************************************************************************************
	 * Returns contents of the flags field.
	 */
	public long getFlags()
	{
		return flags_;
	}


	/*************************************************************************************************
	 * Sets the flags field.
	 */
	public void setFlags(long flags)
	{
		flags_ = flags;
	}

}
