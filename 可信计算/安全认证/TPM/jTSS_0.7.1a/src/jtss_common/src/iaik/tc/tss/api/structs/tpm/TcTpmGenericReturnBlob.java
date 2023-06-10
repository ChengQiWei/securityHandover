/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.api.structs.tpm;


import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder;
import iaik.tc.utils.misc.Utils;

public class TcTpmGenericReturnBlob extends TcCompositeTypeDecoder {

	protected int tag_;

	protected long paramSize_;

	protected long retCode_;


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder()
	 */
	public TcTpmGenericReturnBlob()
	{
		super();
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcBlobData)
	 */
	public TcTpmGenericReturnBlob(TcBlobData data)
	{
		super(data);
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcBlobData,
	 *      int)
	 */
	public TcTpmGenericReturnBlob(TcBlobData data, int offset)
	{
		super(data, offset);
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder)
	 */
	public TcTpmGenericReturnBlob(TcCompositeTypeDecoder composite)
	{
		super(composite);
	}


	/*************************************************************************************************
	 * This method decodes the TPM_NV_ATTRIBUTES from the byte blob.
	 */
	protected void decode()
	{
		tag_ = decodeUINT16();
		paramSize_ = decodeUINT32();
		retCode_ = decodeUINT32();
	}


	/*************************************************************************************************
	 * This method encodes the TPM_GENERIC_RETURN_BLOB as a byte blob.
	 */
	public TcBlobData getEncoded()
	{
		return (TcBlobData)blob_.clone();
	}


	/*************************************************************************************************
	 * Returns contents of the tag field.
	 */
	public int getTag()
	{
		return tag_;
	}


	/*************************************************************************************************
	 * Returns contents of the paramSize field.
	 */
	public long getParamSize()
	{
		return paramSize_;
	}


	/*************************************************************************************************
	 * Returns contents of the retCode field.
	 */
	public long getRetCode()
	{
		return retCode_;
	}


	/*************************************************************************************************
	 * Returns contents of the retCode field.
	 */
	public Long getRetCodeAsLong()
	{
		return new Long(retCode_);
	}


	/*************************************************************************************************
	 * Returns a String representation of the object.
	 */
	public String toString()
	{
		StringBuffer retVal = new StringBuffer();
		retVal.append("tag: " + tag_ + Utils.getNL());
		retVal.append("paramSize: " + paramSize_ + Utils.getNL());
		retVal.append("return code: " + Utils.longToHex(retCode_) + Utils.getNL());
		return retVal.toString();
	}

}
