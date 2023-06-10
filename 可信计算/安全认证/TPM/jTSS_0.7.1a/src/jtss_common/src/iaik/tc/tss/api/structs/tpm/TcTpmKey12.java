/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.api.structs.tpm;


import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder;
import iaik.tc.utils.misc.Utils;

public class TcTpmKey12 extends TcCompositeTypeDecoder implements TcITpmKey {

	protected int tag_;

	protected int fill_;

	protected int keyUsage_;

	protected long keyFlags_;

	protected short authDataUsage_;

	protected TcTpmKeyParms algorithmParms_;

	protected TcBlobData pcrInfo_;

	protected TcTpmStorePubkey pubKey_;

	protected TcBlobData encData_;


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder()
	 */
	public TcTpmKey12()
	{
		super();
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcBlobData)
	 */
	public TcTpmKey12(TcBlobData data)
	{
		super(data);
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcBlobData,
	 *      int)
	 */
	public TcTpmKey12(TcBlobData data, int offset)
	{
		super(data, offset);
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder)
	 */
	public TcTpmKey12(TcCompositeTypeDecoder composite)
	{
		super(composite);
	}


	/*************************************************************************************************
	 * This method decodes the TPM_KEY12 from the byte blob.
	 */
	protected void decode()
	{
		checkBoundaryPreconditions(3 * 2 + 4 + 12 + 4 + 4 + 4);

		tag_ = decodeUINT16();
		fill_ = decodeUINT16();
		keyUsage_ = decodeUINT16();
		keyFlags_ = decodeUINT32();
		authDataUsage_ = decodeByte();
		algorithmParms_ = new TcTpmKeyParms(this);
		long pcrInfoSize = decodeUINT32();
		if (pcrInfoSize > 0) {
			pcrInfo_ = decodeBytes(pcrInfoSize);
		}
		pubKey_ = new TcTpmStorePubkey(this);
		long encSize = decodeUINT32();
		if (encSize > 0) {
			encData_ = decodeBytes(encSize);
		}

	}


	/*************************************************************************************************
	 * This method encodes the TPM_KEY12 as a byte blob.
	 */
	public TcBlobData getEncoded()
	{
		TcBlobData retVal = TcBlobData.newUINT16( tag_);
		retVal.append(TcBlobData.newUINT16( fill_));
		retVal.append(TcBlobData.newUINT16( keyUsage_));
		retVal.append(TcBlobData.newUINT32( keyFlags_));
		retVal.append(TcBlobData.newBYTE( authDataUsage_));
		if (algorithmParms_ != null) {
			retVal.append(algorithmParms_.getEncoded());
		}
		retVal.append(TcBlobData.newUINT32(getPcrInfoSize()));
		if (pcrInfo_ != null) {
			retVal.append(pcrInfo_);
		}
		if (pubKey_ != null) {
			retVal.append(pubKey_.getEncoded());
		}
		retVal.append(TcBlobData.newUINT32(getEncSize()));
		if (encData_ != null) {
			retVal.append(encData_);
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
		retVal.append("fill: ");
		retVal.append(fill_);
		retVal.append(Utils.getNL());
		retVal.append("keyUsage: ");
		retVal.append(keyUsage_);
		retVal.append(Utils.getNL());
		retVal.append("keyFlags: ");
		retVal.append(keyFlags_);
		retVal.append(Utils.getNL());
		retVal.append("authDataUsage: ");
		retVal.append(authDataUsage_);
		retVal.append(Utils.getNL());
		if (algorithmParms_ != null) {
			retVal.append("algorithmParms: ");
			retVal.append(algorithmParms_.toString());
			retVal.append(Utils.getNL());
		}
		retVal.append("PCRInfoSize: ");
		retVal.append(getPcrInfoSize());
		retVal.append(Utils.getNL());
		if (pcrInfo_ != null) {
			retVal.append("PCRInfo: ");
			retVal.append(pcrInfo_.toHexString());
			retVal.append(Utils.getNL());
		}
		if (pubKey_ != null) {
			retVal.append("pubKey: ");
			retVal.append(pubKey_.toString());
			retVal.append(Utils.getNL());
		}
		retVal.append("encSize: ");
		retVal.append(getEncSize());
		retVal.append(Utils.getNL());
		if (encData_ != null) {
			retVal.append("encData: ");
			retVal.append(encData_.toHexString());
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
	 * Returns contents of the fill field.
	 */
	public int getFill()
	{
		return fill_;
	}


	/*************************************************************************************************
	 * Sets the fill field.
	 */
	public void setFill(int fill)
	{
		fill_ = fill;
	}


	/*************************************************************************************************
	 * Returns contents of the keyUsage field.
	 */
	public int getKeyUsage()
	{
		return keyUsage_;
	}


	/*************************************************************************************************
	 * Sets the keyUsage field.
	 */
	public void setKeyUsage(int keyUsage)
	{
		keyUsage_ = keyUsage;
	}


	/*************************************************************************************************
	 * Returns contents of the keyFlags field.
	 */
	public long getKeyFlags()
	{
		return keyFlags_;
	}


	/*************************************************************************************************
	 * Sets the keyFlags field.
	 */
	public void setKeyFlags(long keyFlags)
	{
		keyFlags_ = keyFlags;
	}


	/*************************************************************************************************
	 * Returns contents of the authDataUsage field.
	 */
	public short getAuthDataUsage()
	{
		return authDataUsage_;
	}


	/*************************************************************************************************
	 * Sets the authDataUsage field.
	 */
	public void setAuthDataUsage(short authDataUsage)
	{
		authDataUsage_ = authDataUsage;
	}


	/*************************************************************************************************
	 * Returns contents of the algorithmParms field.
	 */
	public TcTpmKeyParms getAlgorithmParms()
	{
		return algorithmParms_;
	}


	/*************************************************************************************************
	 * Sets the algorithmParms field.
	 */
	public void setAlgorithmParms(TcTpmKeyParms algorithmParms)
	{
		algorithmParms_ = algorithmParms;
	}


	/*************************************************************************************************
	 * Returns contents of the pcrInfoSize field.
	 */
	public long getPcrInfoSize()
	{
		if (pcrInfo_ == null) {
			return 0;
		} else {
			return pcrInfo_.getLengthAsLong();
		}
	}


	/*************************************************************************************************
	 * Returns contents of the pcrInfo field.
	 */
	public TcBlobData getPcrInfo()
	{
		return pcrInfo_;
	}


	/*************************************************************************************************
	 * Sets the pcrInfo field.
	 */
	public void setPcrInfo(TcBlobData pcrInfo)
	{
		pcrInfo_ = pcrInfo;
	}


	/*************************************************************************************************
	 * Returns contents of the pubKey field.
	 */
	public TcTpmStorePubkey getPubKey()
	{
		return pubKey_;
	}


	/*************************************************************************************************
	 * Sets the pubKey field.
	 */
	public void setPubKey(TcTpmStorePubkey pubKey)
	{
		pubKey_ = pubKey;
	}


	/*************************************************************************************************
	 * Returns contents of the encSize field.
	 */
	public long getEncSize()
	{
		if (encData_ == null) {
			return 0;
		} else {
			return encData_.getLengthAsLong();
		}
	}


	/*************************************************************************************************
	 * Returns contents of the encData field.
	 */
	public TcBlobData getEncData()
	{
		return encData_;
	}


	/*************************************************************************************************
	 * Sets the encData field.
	 */
	public void setEncData(TcBlobData encData)
	{
		encData_ = encData;
	}

}
