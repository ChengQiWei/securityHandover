/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.api.structs.tpm;


import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder;
import iaik.tc.utils.misc.Utils;

public class TcTpmContextSensitive extends TcCompositeTypeDecoder {
	protected int tag_;

	protected TcTpmNonce contextNonce_;

	protected TcBlobData internalData_;


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder()
	 */
	public TcTpmContextSensitive()
	{
		super();
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcBlobData)
	 */
	public TcTpmContextSensitive(TcBlobData data)
	{
		super(data);
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcBlobData,
	 *      int)
	 */
	public TcTpmContextSensitive(TcBlobData data, int offset)
	{
		super(data, offset);
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder)
	 */
	public TcTpmContextSensitive(TcCompositeTypeDecoder composite)
	{
		super(composite);
	}


	/*************************************************************************************************
	 * This method decodes the TPM_CONTEXT_SENSITIVE from the byte blob.
	 */
	protected void decode()
	{
		checkBoundaryPreconditions(2 + 20 + 4);

		tag_ = decodeUINT16();
		contextNonce_ = new TcTpmNonce(this);
		long internalSize = decodeUINT32();
		if (internalSize > 0) {
			internalData_ = decodeBytes(internalSize);
		}

	}


	/*************************************************************************************************
	 * This method encodes the TPM_CONTEXT_SENSITIVE as a byte blob.
	 */
	public TcBlobData getEncoded()
	{
		TcBlobData retVal = TcBlobData.newUINT16( tag_);
		if (contextNonce_ != null) {
			retVal.append(contextNonce_.getEncoded());
		}
		retVal.append(TcBlobData.newUINT32( getInternalSize()));
		if (internalData_ != null) {
			retVal.append(internalData_);
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
		if (contextNonce_ != null) {
			retVal.append("contextNonce: ");
			retVal.append(contextNonce_.toString());
			retVal.append(Utils.getNL());
		}
		retVal.append("internalSize: ");
		retVal.append(getInternalSize());
		retVal.append(Utils.getNL());
		if (internalData_ != null) {
			retVal.append("internalData: ");
			retVal.append(internalData_.toHexString());
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
	 * Returns contents of the contextNonce field.
	 */
	public TcTpmNonce getContextNonce()
	{
		return contextNonce_;
	}


	/*************************************************************************************************
	 * Sets the contextNonce field.
	 */
	public void setContextNonce(TcTpmNonce contextNonce)
	{
		contextNonce_ = contextNonce;
	}


	/*************************************************************************************************
	 * Returns contents of the internalSize field.
	 */
	public long getInternalSize()
	{
		if (internalData_ == null) {
			return 0;
		} else {
			return internalData_.getLengthAsLong();
		}
	}


	/*************************************************************************************************
	 * Returns contents of the internalData field.
	 */
	public TcBlobData getInternalData()
	{
		return internalData_;
	}


	/*************************************************************************************************
	 * Sets the internalData field.
	 */
	public void setInternalData(TcBlobData internalData)
	{
		internalData_ = internalData;
	}

}
