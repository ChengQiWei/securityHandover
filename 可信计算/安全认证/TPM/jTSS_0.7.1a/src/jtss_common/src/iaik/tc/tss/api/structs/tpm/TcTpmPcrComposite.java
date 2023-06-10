/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.api.structs.tpm;


import iaik.tc.tss.api.constants.tpm.TcTpmConstants;
import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder;
import iaik.tc.utils.misc.Utils;

/**
 * The composite structure provides the index and value of the PCR register to be used when creating
 * the value that SEALS an entity to the composite.
 * 
 * @TPM_V1 61
 */
public class TcTpmPcrComposite extends TcCompositeTypeDecoder {

	/**
	 * The indication of which PCR values are active.
	 */
	protected TcTpmPcrSelection select_;

	/**
	 * This is an array of TPM_PCRVALUE structures. The values come in the order specified by the
	 * select parameter.
	 */
	protected TcTpmPcrValue[] pcrValue_;


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder()
	 */
	public TcTpmPcrComposite()
	{
		super();
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcBlobData)
	 */
	public TcTpmPcrComposite(TcBlobData data)
	{
		super(data);
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcBlobData,
	 *      int)
	 */
	public TcTpmPcrComposite(TcBlobData data, int offset)
	{
		super(data, offset);
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder)
	 */
	public TcTpmPcrComposite(TcCompositeTypeDecoder composite)
	{
		super(composite);
	}


	/*************************************************************************************************
	 * This method decodes the TPM_PCR_COMPOSITE from the byte blob.
	 */
	protected void decode()
	{
		select_ = new TcTpmPcrSelection(this);
		long valueSize = decodeUINT32();
		if (valueSize > 0) {
			pcrValue_ = new TcTpmPcrValue[(int) (valueSize / TcTpmConstants.TPM_SHA1BASED_NONCE_LEN)];
			for (int i = 0; i < valueSize / TcTpmConstants.TPM_SHA1BASED_NONCE_LEN; i++) {
				pcrValue_[i] = new TcTpmPcrValue(this);
			}
		}
	}


	/*************************************************************************************************
	 * This method encodes the TPM_PCR_COMPOSITE as a byte blob.
	 */
	public TcBlobData getEncoded()
	{
		TcBlobData retVal = TcBlobData.newUINT32(getValueSize());
		if (select_ != null) {
			retVal.prepend(select_.getEncoded());
		}
		if (getValueSize() > 0 && pcrValue_ != null) {
			for (int i = 0; i < pcrValue_.length; i++) {
				retVal.append(pcrValue_[i].getEncoded());
			}
		}
		return retVal;
	}


	/*************************************************************************************************
	 * This method returns a String representation of the object.
	 */
	public String toString()
	{
		StringBuffer retVal = new StringBuffer();

		if (select_ != null) {
			retVal.append("select: ");
			retVal.append(Utils.getNL());
			retVal.append(select_.toString());
			retVal.append(Utils.getNL());
		}
		retVal.append("valueSize: ");
		retVal.append(getValueSize());
		retVal.append(Utils.getNL());
		if (pcrValue_ != null) {
			for (int i = 0; i < pcrValue_.length; i++) {
				retVal.append(pcrValue_[i].toString());
			}
		}
		return retVal.toString();
	}


	/*************************************************************************************************
	 * Returns contents of the select field.
	 */
	public TcTpmPcrSelection getSelect()
	{
		return select_;
	}


	/*************************************************************************************************
	 * Sets the select field.
	 */
	public void setSelect(TcTpmPcrSelection select)
	{
		select_ = select;
	}


	/*************************************************************************************************
	 * Returns contents of the valueSize field.
	 */
	public long getValueSize()
	{
		if (pcrValue_ == null) {
			return 0;
		} else {
			return pcrValue_.length * TcTpmConstants.TPM_SHA1BASED_NONCE_LEN;
		}
	}


	/*************************************************************************************************
	 * Returns contents of the pcrValue field.
	 */
	public TcTpmPcrValue[] getPcrValue()
	{
		return pcrValue_;
	}


	/*************************************************************************************************
	 * Sets the pcrValue field.
	 */
	public void setPcrValue(TcTpmPcrValue[] pcrValue)
	{
		pcrValue_ = pcrValue;
	}
}
