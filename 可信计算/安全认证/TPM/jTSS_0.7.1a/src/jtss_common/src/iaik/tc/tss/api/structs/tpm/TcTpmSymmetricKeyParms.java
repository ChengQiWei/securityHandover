/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.api.structs.tpm;


import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder;
import iaik.tc.utils.misc.Utils;

public class TcTpmSymmetricKeyParms extends TcCompositeTypeDecoder {
	protected long keyLength_;

	protected long blockSize_;

	protected TcBlobData iv_;


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder()
	 */
	public TcTpmSymmetricKeyParms()
	{
		super();
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcBlobData)
	 */
	public TcTpmSymmetricKeyParms(TcBlobData data)
	{
		super(data);
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcBlobData,
	 *      int)
	 */
	public TcTpmSymmetricKeyParms(TcBlobData data, int offset)
	{
		super(data, offset);
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder)
	 */
	public TcTpmSymmetricKeyParms(TcCompositeTypeDecoder composite)
	{
		super(composite);
	}


	/*************************************************************************************************
	 * This method decodes the TPM_SYMMETRIC_KEY_PARMS from the byte blob.
	 */
	protected void decode()
	{
		checkBoundaryPreconditions(4 + 4 + 4);

		keyLength_ = decodeUINT32();
		blockSize_ = decodeUINT32();
		long ivSize = decodeUINT32();
		if (ivSize > 0) {
			iv_ = decodeBytes(ivSize);
		}
	}


	/*************************************************************************************************
	 * This method encodes the TPM_SYMMETRIC_KEY_PARMS as a byte blob.
	 */
	public TcBlobData getEncoded()
	{
		TcBlobData retVal = TcBlobData.newUINT32( keyLength_);
		retVal.append(TcBlobData.newUINT32( blockSize_));
		retVal.append(TcBlobData.newUINT32(getIvSize()));
		if (iv_ != null) {
			retVal.append(iv_);
		}

		return retVal;
	}


	/*************************************************************************************************
	 * This method returns a String representation of the object.
	 */
	public String toString()
	{
		StringBuffer retVal = new StringBuffer();

		retVal.append("keyLength: ");
		retVal.append(keyLength_);
		retVal.append(Utils.getNL());
		retVal.append("blockSize: ");
		retVal.append(blockSize_);
		retVal.append(Utils.getNL());
		retVal.append("ivSize: ");
		retVal.append(getIvSize());
		retVal.append(Utils.getNL());
		if (iv_ != null) {
			retVal.append("IV: ");
			retVal.append(iv_.toHexString());
			retVal.append(Utils.getNL());
		}

		return retVal.toString();
	}


	/*************************************************************************************************
	 * Returns contents of the keyLength field.
	 */
	public long getKeyLength()
	{
		return keyLength_;
	}


	/*************************************************************************************************
	 * Sets the keyLength field.
	 */
	public void setKeyLength(long keyLength)
	{
		keyLength_ = keyLength;
	}


	/*************************************************************************************************
	 * Returns contents of the blockSize field.
	 */
	public long getBlockSize()
	{
		return blockSize_;
	}


	/*************************************************************************************************
	 * Sets the blockSize field.
	 */
	public void setBlockSize(long blockSize)
	{
		blockSize_ = blockSize;
	}


	/*************************************************************************************************
	 * Returns contents of the ivSize field.
	 */
	public long getIvSize()
	{
		if (iv_ == null) {
			return 0;
		} else {
			return iv_.getLengthAsLong();
		}
	}


	/*************************************************************************************************
	 * Returns contents of the IV field.
	 */
	public TcBlobData getIV()
	{
		return iv_;
	}


	/*************************************************************************************************
	 * Sets the IV field.
	 */
	public void setIV(TcBlobData IV)
	{
		iv_ = IV;
	}

}
