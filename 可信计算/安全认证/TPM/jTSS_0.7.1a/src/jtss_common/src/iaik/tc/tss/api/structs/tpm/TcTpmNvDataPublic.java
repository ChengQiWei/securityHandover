/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.api.structs.tpm;


import iaik.tc.tss.api.constants.tpm.TcTpmConstants;
import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder;
import iaik.tc.utils.misc.Utils;

public class TcTpmNvDataPublic extends TcCompositeTypeDecoder {
	protected int tag_;

	protected long nvIndex_;

	protected TcTpmPcrInfoShort pcrInfoRead_;

	protected TcTpmPcrInfoShort pcrInfoWrite_;

	protected TcTpmNvAttributes permission_;

	protected boolean readSTClear_;

	protected boolean writeSTClear_;

	protected boolean writeDefine_;

	protected long dataSize_;


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 *
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder()
	 */
	public TcTpmNvDataPublic()
	{
		super();
		tag_ = TcTpmConstants.TPM_TAG_NV_DATA_PUBLIC;
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 *
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcBlobData)
	 */
	public TcTpmNvDataPublic(TcBlobData data)
	{
		super(data);
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 *
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcBlobData,
	 *      int)
	 */
	public TcTpmNvDataPublic(TcBlobData data, int offset)
	{
		super(data, offset);
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 *
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder)
	 */
	public TcTpmNvDataPublic(TcCompositeTypeDecoder composite)
	{
		super(composite);
	}


	/*************************************************************************************************
	 * This method decodes the TPM_NV_DATA_PUBLIC from the byte blob.
	 */
	protected void decode()
	{
		checkBoundaryPreconditions(2 + 4 + 2 * 23 + 6 + 3 * 1 + 4);

		tag_ = decodeUINT16();
		nvIndex_ = decodeUINT32();
		pcrInfoRead_ = new TcTpmPcrInfoShort(this);
		pcrInfoWrite_ = new TcTpmPcrInfoShort(this);
		permission_ = new TcTpmNvAttributes(this);
		readSTClear_ = decodeBoolean();
		writeSTClear_ = decodeBoolean();
		writeDefine_ = decodeBoolean();
		dataSize_ = decodeUINT32();

	}


	/*************************************************************************************************
	 * This method encodes the TPM_NV_DATA_PUBLIC as a byte blob.
	 */
	public TcBlobData getEncoded()
	{
		TcBlobData retVal = TcBlobData.newUINT16( tag_);
		retVal.append(TcBlobData.newUINT32( nvIndex_));
		if (pcrInfoRead_ != null) {
			retVal.append(pcrInfoRead_.getEncoded());
		}
		if (pcrInfoWrite_ != null) {
			retVal.append(pcrInfoWrite_.getEncoded());
		}
		if (permission_ != null) {
			retVal.append(permission_.getEncoded());
		}
		retVal.append(TcBlobData.newBYTE(Utils.booleanToByte(readSTClear_)));
		retVal.append(TcBlobData.newBYTE(Utils.booleanToByte(writeSTClear_)));
		retVal.append(TcBlobData.newBYTE(Utils.booleanToByte(writeDefine_)));
		retVal.append(TcBlobData.newUINT32(dataSize_));

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
		retVal.append("nvIndex: ");
		retVal.append(nvIndex_);
		retVal.append(Utils.getNL());
		if (pcrInfoRead_ != null) {
			retVal.append("pcrInfoRead: ");
			retVal.append(pcrInfoRead_.toString());
			retVal.append(Utils.getNL());
		}
		if (pcrInfoWrite_ != null) {
			retVal.append("pcrInfoWrite: ");
			retVal.append(pcrInfoWrite_.toString());
			retVal.append(Utils.getNL());
		}
		if (permission_ != null) {
			retVal.append("permission: ");
			retVal.append(permission_.toString());
			retVal.append(Utils.getNL());
		}
		retVal.append("readSTClear: ");
		retVal.append(readSTClear_);
		retVal.append(Utils.getNL());
		retVal.append("writeSTClear: ");
		retVal.append(writeSTClear_);
		retVal.append(Utils.getNL());
		retVal.append("writeDefine: ");
		retVal.append(writeDefine_);
		retVal.append(Utils.getNL());
		retVal.append("dataSize: ");
		retVal.append(dataSize_);
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
	 * Returns contents of the nvIndex field.
	 */
	public long getNvIndex()
	{
		return nvIndex_;
	}


	/*************************************************************************************************
	 * Sets the nvIndex field.
	 */
	public void setNvIndex(long nvIndex)
	{
		nvIndex_ = nvIndex;
	}


	/*************************************************************************************************
	 * Returns contents of the pcrInfoRead field.
	 */
	public TcTpmPcrInfoShort getPcrInfoRead()
	{
		return pcrInfoRead_;
	}


	/*************************************************************************************************
	 * Sets the pcrInfoRead field.
	 */
	public void setPcrInfoRead(TcTpmPcrInfoShort pcrInfoRead)
	{
		pcrInfoRead_ = pcrInfoRead;
	}


	/*************************************************************************************************
	 * Returns contents of the pcrInfoWrite field.
	 */
	public TcTpmPcrInfoShort getPcrInfoWrite()
	{
		return pcrInfoWrite_;
	}


	/*************************************************************************************************
	 * Sets the pcrInfoWrite field.
	 */
	public void setPcrInfoWrite(TcTpmPcrInfoShort pcrInfoWrite)
	{
		pcrInfoWrite_ = pcrInfoWrite;
	}


	/*************************************************************************************************
	 * Returns contents of the permission field.
	 */
	public TcTpmNvAttributes getPermission()
	{
		return permission_;
	}


	/*************************************************************************************************
	 * Sets the permission field.
	 */
	public void setPermission(TcTpmNvAttributes permission)
	{
		permission_ = permission;
	}


	/*************************************************************************************************
	 * Returns contents of the readSTClear field.
	 */
	public boolean getReadSTClear()
	{
		return readSTClear_;
	}


	/*************************************************************************************************
	 * Sets the readSTClear field.
	 */
	public void setReadSTClear(boolean readSTClear)
	{
		readSTClear_ = readSTClear;
	}


	/*************************************************************************************************
	 * Returns contents of the writeSTClear field.
	 */
	public boolean getWriteSTClear()
	{
		return writeSTClear_;
	}


	/*************************************************************************************************
	 * Sets the writeSTClear field.
	 */
	public void setWriteSTClear(boolean writeSTClear)
	{
		writeSTClear_ = writeSTClear;
	}


	/*************************************************************************************************
	 * Returns contents of the writeDefine field.
	 */
	public boolean getWriteDefine()
	{
		return writeDefine_;
	}


	/*************************************************************************************************
	 * Sets the writeDefine field.
	 */
	public void setWriteDefine(boolean writeDefine)
	{
		writeDefine_ = writeDefine;
	}


	/*************************************************************************************************
	 * Returns contents of the dataSize field.
	 */
	public long getDataSize()
	{
		return dataSize_;
	}


	/*************************************************************************************************
	 * Sets the dataSize field.
	 */
	public void setDataSize(long dataSize)
	{
		dataSize_ = dataSize;
	}

}
