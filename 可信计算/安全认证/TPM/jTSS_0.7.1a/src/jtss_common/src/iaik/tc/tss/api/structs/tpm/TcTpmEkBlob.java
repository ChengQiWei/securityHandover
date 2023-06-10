/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.api.structs.tpm;


import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder;
import iaik.tc.utils.misc.Utils;

public class TcTpmEkBlob extends TcCompositeTypeDecoder {
	protected int tag_;

	protected int ekType_;

	protected TcBlobData blob_;


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder()
	 */
	public TcTpmEkBlob()
	{
		super();
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcBlobData)
	 */
	public TcTpmEkBlob(TcBlobData data)
	{
		super(data);
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcBlobData,
	 *      int)
	 */
	public TcTpmEkBlob(TcBlobData data, int offset)
	{
		super(data, offset);
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder)
	 */
	public TcTpmEkBlob(TcCompositeTypeDecoder composite)
	{
		super(composite);
	}


	/*************************************************************************************************
	 * This method decodes the TPM_EK_BLOB from the byte blob.
	 */
	protected void decode()
	{
		checkBoundaryPreconditions(2 + 2 + 4);

		tag_ = decodeUINT16();
		ekType_ = decodeUINT16();
		long blobSize = decodeUINT32();
		if (blobSize > 0) {
			blob_ = decodeBytes(blobSize);
		}

	}


	/*************************************************************************************************
	 * This method encodes the TPM_EK_BLOB as a byte blob.
	 */
	public TcBlobData getEncoded()
	{
		TcBlobData retVal = TcBlobData.newUINT16( tag_);
		retVal.append(TcBlobData.newUINT16( ekType_));
		retVal.append(TcBlobData.newUINT32(getBlobSize()));
		if (blob_ != null) {
			retVal.append(blob_);
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
		retVal.append("ekType: ");
		retVal.append(ekType_);
		retVal.append(Utils.getNL());
		retVal.append("blobSize: ");
		retVal.append(getBlobSize());
		retVal.append(Utils.getNL());
		if (blob_ != null) {
			retVal.append("blob: ");
			retVal.append(blob_.toHexString());
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
	 * Returns contents of the ekType field.
	 */
	public int getEkType()
	{
		return ekType_;
	}


	/*************************************************************************************************
	 * Sets the ekType field.
	 */
	public void setEkType(int ekType)
	{
		ekType_ = ekType;
	}


	/*************************************************************************************************
	 * Returns contents of the blobSize field.
	 */
	public long getBlobSize()
	{
		if (blob_ == null) {
			return 0;
		} else {
			return blob_.getLengthAsLong();
		}
	}


	/*************************************************************************************************
	 * Returns contents of the blob field.
	 */
	public TcBlobData getBlob()
	{
		return blob_;
	}


	/*************************************************************************************************
	 * Sets the blob field.
	 */
	public void setBlob(TcBlobData blob)
	{
		blob_ = blob;
	}

}
