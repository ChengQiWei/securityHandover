/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.api.structs.tpm;


import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder;
import iaik.tc.utils.misc.Utils;

public class TcTpmSignInfo extends TcCompositeTypeDecoder {
	protected int tag_;

	protected String fixed_;

	protected TcTpmNonce replay_;

	protected long dataLen_;

	protected TcBlobData data_;


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder()
	 */
	public TcTpmSignInfo()
	{
		super();
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcBlobData)
	 */
	public TcTpmSignInfo(TcBlobData data)
	{
		super(data);
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcBlobData,
	 *      int)
	 */
	public TcTpmSignInfo(TcBlobData data, int offset)
	{
		super(data, offset);
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder)
	 */
	public TcTpmSignInfo(TcCompositeTypeDecoder composite)
	{
		super(composite);
	}


	/*************************************************************************************************
	 * This method decodes the TPM_SIGN_INFO from the byte blob.
	 */
	protected void decode()
	{
		checkBoundaryPreconditions(2 + 4 + 20 + 4);

		tag_ = decodeUINT16();
		fixed_ = decodeBytes(4).toStringASCII();
		replay_ = new TcTpmNonce(this);
		dataLen_ = decodeUINT32();
		if (dataLen_ > 0) {
			data_ = decodeBytes(dataLen_);
		}
	}


	/*************************************************************************************************
	 * This method encodes the TPM_SIGN_INFO as a byte blob.
	 */
	public TcBlobData getEncoded()
	{
		TcBlobData retVal = TcBlobData.newUINT16( tag_);
		retVal.append(TcBlobData.newStringASCII(fixed_));
		if (replay_ != null) {
			retVal.append(replay_.getEncoded());
		}
		retVal.append(TcBlobData.newUINT32( dataLen_));
		if (data_ != null) {
			retVal.append(data_);
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
		if (replay_ != null) {
			retVal.append("replay: ");
			retVal.append(replay_.toString());
			retVal.append(Utils.getNL());
		}
		retVal.append("dataLen: ");
		retVal.append(dataLen_);
		retVal.append(Utils.getNL());
		if (data_ != null) {
			retVal.append("data: ");
			retVal.append(data_.toHexString());
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
	 * Returns contents of the replay field.
	 */
	public TcTpmNonce getReplay()
	{
		return replay_;
	}


	/*************************************************************************************************
	 * Sets the replay field.
	 */
	public void setReplay(TcTpmNonce replay)
	{
		replay_ = replay;
	}


	/*************************************************************************************************
	 * Returns contents of the dataLen field.
	 */
	public long getDataLen()
	{
		return dataLen_;
	}


	/*************************************************************************************************
	 * Sets the dataLen field.
	 */
	public void setDataLen(long dataLen)
	{
		dataLen_ = dataLen;
	}


	/*************************************************************************************************
	 * Returns contents of the data field.
	 */
	public TcBlobData getData()
	{
		return data_;
	}


	/*************************************************************************************************
	 * Sets the data field.
	 */
	public void setData(TcBlobData data)
	{
		data_ = data;
	}

}
