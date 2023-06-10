/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.api.structs.tpm;


import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder;
import iaik.tc.utils.misc.Utils;

public class TcTpmCounterValue extends TcCompositeTypeDecoder {
	protected int tag_;

	protected String label_; // 4 bytes

	protected long counter_;


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder()
	 */
	public TcTpmCounterValue()
	{
		super();
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcBlobData)
	 */
	public TcTpmCounterValue(TcBlobData data)
	{
		super(data);
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcBlobData,
	 *      int)
	 */
	public TcTpmCounterValue(TcBlobData data, int offset)
	{
		super(data, offset);
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder)
	 */
	public TcTpmCounterValue(TcCompositeTypeDecoder composite)
	{
		super(composite);
	}


	/*************************************************************************************************
	 * This method decodes the TPM_COUNTER_VALUE from the byte blob.
	 */
	protected void decode()
	{
		checkBoundaryPreconditions(10);

		tag_ = decodeUINT16();
		label_ = decodeBytes(4).toStringASCII();
		counter_ = decodeUINT32();

	}


	/*************************************************************************************************
	 * This method encodes the TPM_COUNTER_VALUE as a byte blob.
	 */
	public TcBlobData getEncoded()
	{
		TcBlobData retVal = TcBlobData.newUINT16( tag_);
		retVal.append(TcBlobData.newStringASCII(label_));
		retVal.append(TcBlobData.newUINT32( counter_));

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
		retVal.append("label: ");
		retVal.append(label_);
		retVal.append(Utils.getNL());
		retVal.append("counter: ");
		retVal.append(counter_);
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
	public String getLabel()
	{
		return label_;
	}


	/*************************************************************************************************
	 * Sets the label field.
	 */
	public void setLabel(String label)
	{
		label_ = label;
	}


	/*************************************************************************************************
	 * Returns contents of the counter field.
	 */
	public long getCounter()
	{
		return counter_;
	}


	/*************************************************************************************************
	 * Sets the counter field.
	 */
	public void setCounter(long counter)
	{
		counter_ = counter;
	}

}
