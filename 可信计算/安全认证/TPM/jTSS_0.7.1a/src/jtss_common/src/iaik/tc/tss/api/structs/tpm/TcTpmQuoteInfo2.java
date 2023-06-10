/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.api.structs.tpm;


import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder;
import iaik.tc.utils.misc.Utils;

public class TcTpmQuoteInfo2 extends TcCompositeTypeDecoder {
	protected int tag_;

	protected String fixed_;

	protected TcTpmNonce externalData_;

	protected TcTpmPcrInfoShort infoShort_;


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder()
	 */
	public TcTpmQuoteInfo2()
	{
		super();
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcBlobData)
	 */
	public TcTpmQuoteInfo2(TcBlobData data)
	{
		super(data);
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcBlobData,
	 *      int)
	 */
	public TcTpmQuoteInfo2(TcBlobData data, int offset)
	{
		super(data, offset);
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder)
	 */
	public TcTpmQuoteInfo2(TcCompositeTypeDecoder composite)
	{
		super(composite);
	}


	/*************************************************************************************************
	 * This method decodes the TPM_QUOTE_INFO2 from the byte blob.
	 */
	protected void decode()
	{
		checkBoundaryPreconditions(2 + 4 + 20 + 23);

		tag_ = decodeUINT16();
		fixed_ = decodeBytes(4).toStringASCII();
		externalData_ = new TcTpmNonce(this);
		infoShort_ = new TcTpmPcrInfoShort(this);

	}


	/*************************************************************************************************
	 * This method encodes the TPM_QUOTE_INFO2 as a byte blob.
	 */
	public TcBlobData getEncoded()
	{
		TcBlobData retVal = TcBlobData.newUINT16( tag_);
		retVal.append(TcBlobData.newStringASCII(fixed_));
		if (externalData_ != null) {
			retVal.append(externalData_.getEncoded());
		}
		if (infoShort_ != null) {
			retVal.append(infoShort_.getEncoded());
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
		retVal.append("fixed: ");
		retVal.append(fixed_);
		retVal.append(Utils.getNL());
		if (externalData_ != null) {
			retVal.append("externalData: ");
			retVal.append(externalData_.toString());
			retVal.append(Utils.getNL());
		}
		if (infoShort_ != null) {
			retVal.append("infoShort: ");
			retVal.append(infoShort_.toString());
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
	 * Returns contents of the fixed field.
	 */
	public String getFixed()
	{
		return fixed_;
	}


	/*************************************************************************************************
	 * Sets the fixed field.
	 */
	public void setFixed(String fixed)
	{
		fixed_ = fixed;
	}


	/*************************************************************************************************
	 * Returns contents of the externalData field.
	 */
	public TcTpmNonce getExternalData()
	{
		return externalData_;
	}


	/*************************************************************************************************
	 * Sets the externalData field.
	 */
	public void setExternalData(TcTpmNonce externalData)
	{
		externalData_ = externalData;
	}


	/*************************************************************************************************
	 * Returns contents of the infoShort field.
	 */
	public TcTpmPcrInfoShort getInfoShort()
	{
		return infoShort_;
	}


	/*************************************************************************************************
	 * Sets the infoShort field.
	 */
	public void setInfoShort(TcTpmPcrInfoShort infoShort)
	{
		infoShort_ = infoShort;
	}

}
