/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.api.structs.tpm;


import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder;
import iaik.tc.utils.misc.Utils;

public class TcTpmDelegateTableRow extends TcCompositeTypeDecoder {
	protected int tag_;

	protected TcTpmDelegatePublic pub_;

	protected TcTpmSecret authValue_;


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder()
	 */
	public TcTpmDelegateTableRow()
	{
		super();
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcBlobData)
	 */
	public TcTpmDelegateTableRow(TcBlobData data)
	{
		super(data);
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcBlobData,
	 *      int)
	 */
	public TcTpmDelegateTableRow(TcBlobData data, int offset)
	{
		super(data, offset);
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder)
	 */
	public TcTpmDelegateTableRow(TcCompositeTypeDecoder composite)
	{
		super(composite);
	}


	/*************************************************************************************************
	 * This method decodes the TPM_DELEGATE_TABLE_ROW from the byte blob.
	 */
	protected void decode()
	{
		checkBoundaryPreconditions(2 + 48 + 20);

		tag_ = decodeUINT16();
		pub_ = new TcTpmDelegatePublic(this);
		authValue_ = new TcTpmSecret(this);

	}


	/*************************************************************************************************
	 * This method encodes the TPM_DELEGATE_TABLE_ROW as a byte blob.
	 */
	public TcBlobData getEncoded()
	{
		TcBlobData retVal = TcBlobData.newUINT16( tag_);
		if (pub_ != null) {
			retVal.append(pub_.getEncoded());
		}
		if (authValue_ != null) {
			retVal.append(authValue_.getEncoded());
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
		if (pub_ != null) {
			retVal.append("pub: ");
			retVal.append(pub_.toString());
			retVal.append(Utils.getNL());
		}
		if (authValue_ != null) {
			retVal.append("authValue: ");
			retVal.append(authValue_.toString());
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
	 * Returns contents of the pub field.
	 */
	public TcTpmDelegatePublic getPub()
	{
		return pub_;
	}


	/*************************************************************************************************
	 * Sets the pub field.
	 */
	public void setPub(TcTpmDelegatePublic pub)
	{
		pub_ = pub;
	}


	/*************************************************************************************************
	 * Returns contents of the authValue field.
	 */
	public TcTpmSecret getAuthValue()
	{
		return authValue_;
	}


	/*************************************************************************************************
	 * Sets the authValue field.
	 */
	public void setAuthValue(TcTpmSecret authValue)
	{
		authValue_ = authValue;
	}

}
