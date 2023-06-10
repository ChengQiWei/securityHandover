/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.api.structs.tpm;


import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder;
import iaik.tc.utils.misc.Utils;

public class TcTpmDelegatePublic extends TcCompositeTypeDecoder {
	protected int tag_;

	protected TcTpmDelegateLabel label_;

	protected TcTpmPcrInfoShort pcrInfo_;

	protected TcTpmDelegations permissions_;

	protected long familyID_;

	protected long verificationCount_;


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder()
	 */
	public TcTpmDelegatePublic()
	{
		super();
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcBlobData)
	 */
	public TcTpmDelegatePublic(TcBlobData data)
	{
		super(data);
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcBlobData,
	 *      int)
	 */
	public TcTpmDelegatePublic(TcBlobData data, int offset)
	{
		super(data, offset);
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder)
	 */
	public TcTpmDelegatePublic(TcCompositeTypeDecoder composite)
	{
		super(composite);
	}


	/*************************************************************************************************
	 * This method decodes the TPM_DELEGATE_PUBLIC from the byte blob.
	 */
	protected void decode()
	{
		checkBoundaryPreconditions(2 + 1 + 23 + 14 + 4 + 4);

		tag_ = decodeUINT16();
		label_ = new TcTpmDelegateLabel(this);
		pcrInfo_ = new TcTpmPcrInfoShort(this);
		permissions_ = new TcTpmDelegations(this);
		familyID_ = decodeUINT32();
		verificationCount_ = decodeUINT32();

	}


	/*************************************************************************************************
	 * This method encodes the TPM_DELEGATE_PUBLIC as a byte blob.
	 */
	public TcBlobData getEncoded()
	{
		TcBlobData retVal = TcBlobData.newUINT16( tag_);
		if (label_ != null) {
			retVal.append(label_.getEncoded());
		}
		if (pcrInfo_ != null) {
			retVal.append(pcrInfo_.getEncoded());
		}
		if (permissions_ != null) {
			retVal.append(permissions_.getEncoded());
		}
		retVal.append(TcBlobData.newUINT32( familyID_));
		retVal.append(TcBlobData.newUINT32( verificationCount_));

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
		if (pcrInfo_ != null) {
			retVal.append("pcrInfo: ");
			retVal.append(pcrInfo_.toString());
			retVal.append(Utils.getNL());
		}
		if (permissions_ != null) {
			retVal.append("permissions: ");
			retVal.append(permissions_.toString());
			retVal.append(Utils.getNL());
		}
		retVal.append("familyID: ");
		retVal.append(familyID_);
		retVal.append(Utils.getNL());
		retVal.append("verificationCount: ");
		retVal.append(verificationCount_);
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
	public TcTpmDelegateLabel getLabel()
	{
		return label_;
	}


	/*************************************************************************************************
	 * Sets the label field.
	 */
	public void setLabel(TcTpmDelegateLabel label)
	{
		label_ = label;
	}


	/*************************************************************************************************
	 * Returns contents of the pcrInfo field.
	 */
	public TcTpmPcrInfoShort getPcrInfo()
	{
		return pcrInfo_;
	}


	/*************************************************************************************************
	 * Sets the pcrInfo field.
	 */
	public void setPcrInfo(TcTpmPcrInfoShort pcrInfo)
	{
		pcrInfo_ = pcrInfo;
	}


	/*************************************************************************************************
	 * Returns contents of the permissions field.
	 */
	public TcTpmDelegations getPermissions()
	{
		return permissions_;
	}


	/*************************************************************************************************
	 * Sets the permissions field.
	 */
	public void setPermissions(TcTpmDelegations permissions)
	{
		permissions_ = permissions;
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

}
