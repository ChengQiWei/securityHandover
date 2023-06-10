/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.api.structs.tpm;


import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder;
import iaik.tc.utils.misc.Utils;

public class TcTpmCmkSigticket extends TcCompositeTypeDecoder {
	protected int tag_;

	protected TcTpmDigest verKeyDigest_;

	protected TcTpmDigest signedData_;


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder()
	 */
	public TcTpmCmkSigticket()
	{
		super();
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcBlobData)
	 */
	public TcTpmCmkSigticket(TcBlobData data)
	{
		super(data);
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcBlobData,
	 *      int)
	 */
	public TcTpmCmkSigticket(TcBlobData data, int offset)
	{
		super(data, offset);
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder)
	 */
	public TcTpmCmkSigticket(TcCompositeTypeDecoder composite)
	{
		super(composite);
	}


	/*************************************************************************************************
	 * This method decodes the TPM_CMK_SIGTICKET from the byte blob.
	 */
	protected void decode()
	{
		checkBoundaryPreconditions(2 + 20 + 20);

		tag_ = decodeUINT16();
		verKeyDigest_ = new TcTpmDigest(this);
		signedData_ = new TcTpmDigest(this);

	}


	/*************************************************************************************************
	 * This method encodes the TPM_CMK_SIGTICKET as a byte blob.
	 */
	public TcBlobData getEncoded()
	{
		TcBlobData retVal = TcBlobData.newUINT16( tag_);
		if (verKeyDigest_ != null) {
			retVal.append(verKeyDigest_.getEncoded());
		}
		if (signedData_ != null) {
			retVal.append(signedData_.getEncoded());
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
		if (verKeyDigest_ != null) {
			retVal.append("verKeyDigest: ");
			retVal.append(verKeyDigest_.toString());
			retVal.append(Utils.getNL());
		}
		if (signedData_ != null) {
			retVal.append("signedData: ");
			retVal.append(signedData_.toString());
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
	 * Returns contents of the verKeyDigest field.
	 */
	public TcTpmDigest getVerKeyDigest()
	{
		return verKeyDigest_;
	}


	/*************************************************************************************************
	 * Sets the verKeyDigest field.
	 */
	public void setVerKeyDigest(TcTpmDigest verKeyDigest)
	{
		verKeyDigest_ = verKeyDigest;
	}


	/*************************************************************************************************
	 * Returns contents of the signedData field.
	 */
	public TcTpmDigest getSignedData()
	{
		return signedData_;
	}


	/*************************************************************************************************
	 * Sets the signedData field.
	 */
	public void setSignedData(TcTpmDigest signedData)
	{
		signedData_ = signedData;
	}

}
