/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.api.structs.tpm;


import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder;
import iaik.tc.utils.misc.Utils;

public class TcTpmCmkMigauth extends TcCompositeTypeDecoder {
	protected int tag_;

	protected TcTpmDigest msaDigest_;

	protected TcTpmDigest pubKeyDigest_;


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder()
	 */
	public TcTpmCmkMigauth()
	{
		super();
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcBlobData)
	 */
	public TcTpmCmkMigauth(TcBlobData data)
	{
		super(data);
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcBlobData,
	 *      int)
	 */
	public TcTpmCmkMigauth(TcBlobData data, int offset)
	{
		super(data, offset);
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder)
	 */
	public TcTpmCmkMigauth(TcCompositeTypeDecoder composite)
	{
		super(composite);
	}


	/*************************************************************************************************
	 * This method decodes the TPM_CMK_MIGAUTH from the byte blob.
	 */
	protected void decode()
	{
		checkBoundaryPreconditions(2 + 20 + 20);

		tag_ = decodeUINT16();
		msaDigest_ = new TcTpmDigest(this);
		pubKeyDigest_ = new TcTpmDigest(this);

	}


	/*************************************************************************************************
	 * This method encodes the TPM_CMK_MIGAUTH as a byte blob.
	 */
	public TcBlobData getEncoded()
	{
		TcBlobData retVal = TcBlobData.newUINT16( tag_);
		if (msaDigest_ != null) {
			retVal.append(msaDigest_.getEncoded());
		}
		if (pubKeyDigest_ != null) {
			retVal.append(pubKeyDigest_.getEncoded());
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
		if (msaDigest_ != null) {
			retVal.append("msaDigest: ");
			retVal.append(msaDigest_.toString());
			retVal.append(Utils.getNL());
		}
		if (pubKeyDigest_ != null) {
			retVal.append("pubKeyDigest: ");
			retVal.append(pubKeyDigest_.toString());
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
	 * Returns contents of the msaDigest field.
	 */
	public TcTpmDigest getMsaDigest()
	{
		return msaDigest_;
	}


	/*************************************************************************************************
	 * Sets the msaDigest field.
	 */
	public void setMsaDigest(TcTpmDigest msaDigest)
	{
		msaDigest_ = msaDigest;
	}


	/*************************************************************************************************
	 * Returns contents of the pubKeyDigest field.
	 */
	public TcTpmDigest getPubKeyDigest()
	{
		return pubKeyDigest_;
	}


	/*************************************************************************************************
	 * Sets the pubKeyDigest field.
	 */
	public void setPubKeyDigest(TcTpmDigest pubKeyDigest)
	{
		pubKeyDigest_ = pubKeyDigest;
	}

}
