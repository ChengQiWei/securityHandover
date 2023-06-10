/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.api.structs.tpm;


import iaik.tc.tss.api.constants.tpm.TcTpmConstants;
import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder;
import iaik.tc.utils.misc.Utils;

public class TcTpmNvAttributes extends TcCompositeTypeDecoder {
	protected int tag_;

	protected long attributes_;


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 *
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder()
	 */
	public TcTpmNvAttributes()
	{
		super();
		tag_ = TcTpmConstants.TPM_TAG_NV_ATTRIBUTES;
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 *
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcBlobData)
	 */
	public TcTpmNvAttributes(TcBlobData data)
	{
		super(data);
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 *
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcBlobData,
	 *      int)
	 */
	public TcTpmNvAttributes(TcBlobData data, int offset)
	{
		super(data, offset);
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 *
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder)
	 */
	public TcTpmNvAttributes(TcCompositeTypeDecoder composite)
	{
		super(composite);
	}


	/*************************************************************************************************
	 * This method decodes the TPM_NV_ATTRIBUTES from the byte blob.
	 */
	protected void decode()
	{
		checkBoundaryPreconditions(2 + 4);

		tag_ = decodeUINT16();
		attributes_ = decodeUINT32();

	}


	/*************************************************************************************************
	 * This method encodes the TPM_NV_ATTRIBUTES as a byte blob.
	 */
	public TcBlobData getEncoded()
	{
		TcBlobData retVal = TcBlobData.newUINT16( tag_);
		retVal.append(TcBlobData.newUINT32( attributes_));

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
		retVal.append("attributes: ");
		retVal.append(attributes_);
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
	 * Returns contents of the attributes field.
	 */
	public long getAttributes()
	{
		return attributes_;
	}


	/*************************************************************************************************
	 * Sets the attributes field.
	 */
	public void setAttributes(long attributes)
	{
		attributes_ = attributes;
	}

}
