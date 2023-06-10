/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.api.structs.tpm;


import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder;
import iaik.tc.utils.misc.Utils;

public class TcTpmCertifyInfo2 extends TcCompositeTypeDecoder {
	protected int tag_;

	protected short fill_;

	protected short payloadType_;

	protected int keyUsage_;

	protected long keyFlags_;

	protected short authDataUsage_;

	protected TcTpmKeyParms algorithmParms_;

	protected TcTpmDigest pubkeyDigest_;

	protected TcTpmNonce data_;

	protected boolean parentPCRStatus_;

	protected TcBlobData pcrInfo_;

	protected TcBlobData migrationAuthority_;


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder()
	 */
	public TcTpmCertifyInfo2()
	{
		super();
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcBlobData)
	 */
	public TcTpmCertifyInfo2(TcBlobData data)
	{
		super(data);
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcBlobData,
	 *      int)
	 */
	public TcTpmCertifyInfo2(TcBlobData data, int offset)
	{
		super(data, offset);
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder)
	 */
	public TcTpmCertifyInfo2(TcCompositeTypeDecoder composite)
	{
		super(composite);
	}


	/*************************************************************************************************
	 * This method decodes the TPM_CERTIFY_INFO2 from the byte blob.
	 */
	protected void decode()
	{
		checkBoundaryPreconditions(2 + 1 + 1 + 2 + 4 + 12 + 20 + 20 + 1 + 4 + 4);

		tag_ = decodeUINT16();
		fill_ = decodeByte();
		payloadType_ = decodeByte();
		keyUsage_ = decodeUINT16();
		keyFlags_ = decodeUINT32();
		authDataUsage_ = decodeByte();
		algorithmParms_ = new TcTpmKeyParms(this);
		pubkeyDigest_ = new TcTpmDigest(this);
		data_ = new TcTpmNonce(this);
		parentPCRStatus_ = decodeBoolean();
		long pcrInfoSize = decodeUINT32();
		if (pcrInfoSize > 0) {
			pcrInfo_ = decodeBytes(pcrInfoSize);
		}
		long migrationAuthoritySize = decodeUINT32();
		if (migrationAuthoritySize > 0) {
			migrationAuthority_ = decodeBytes(migrationAuthoritySize);
		}

	}


	/*************************************************************************************************
	 * This method encodes the TPM_CERTIFY_INFO2 as a byte blob.
	 */
	public TcBlobData getEncoded()
	{
		TcBlobData retVal = TcBlobData.newUINT16( tag_);
		retVal.append(TcBlobData.newBYTE( fill_));
		retVal.append(TcBlobData.newBYTE( payloadType_));
		retVal.append(TcBlobData.newUINT16( keyUsage_));
		retVal.append(TcBlobData.newUINT32( keyFlags_));
		retVal.append(TcBlobData.newBYTE( authDataUsage_));
		if (algorithmParms_ != null) {
			retVal.append(algorithmParms_.getEncoded());
		}
		if (pubkeyDigest_ != null) {
			retVal.append(pubkeyDigest_.getEncoded());
		}
		if (data_ != null) {
			retVal.append(data_.getEncoded());
		}
		retVal.append(TcBlobData.newBYTE(Utils.booleanToByte(parentPCRStatus_)));
		retVal.append(TcBlobData.newUINT32(getPcrInfoSize()));
		if (pcrInfo_ != null) {
			retVal.append(pcrInfo_);
		}
		retVal.append(TcBlobData.newUINT32(getMigrationAuthoritySize()));
		if (migrationAuthority_ != null) {
			retVal.append(migrationAuthority_);
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
		retVal.append("payloadType: ");
		retVal.append(payloadType_);
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
		if (pubkeyDigest_ != null) {
			retVal.append("pubkeyDigest: ");
			retVal.append(pubkeyDigest_.toString());
			retVal.append(Utils.getNL());
		}
		if (data_ != null) {
			retVal.append("data: ");
			retVal.append(data_.toString());
			retVal.append(Utils.getNL());
		}
		retVal.append("parentPCRStatus: ");
		retVal.append(parentPCRStatus_);
		retVal.append(Utils.getNL());
		retVal.append("PCRInfoSize: ");
		retVal.append(getPcrInfoSize());
		retVal.append(Utils.getNL());
		if (pcrInfo_ != null) {
			retVal.append("PCRInfo: ");
			retVal.append(pcrInfo_.toHexString());
			retVal.append(Utils.getNL());
		}
		retVal.append("migrationAuthoritySize: ");
		retVal.append(getMigrationAuthoritySize());
		retVal.append(Utils.getNL());
		if (migrationAuthority_ != null) {
			retVal.append("migrationAuthority: ");
			retVal.append(migrationAuthority_.toHexString());
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
	public short getFill()
	{
		return fill_;
	}


	/*************************************************************************************************
	 * Sets the fill field.
	 */
	public void setFill(short fill)
	{
		fill_ = fill;
	}


	/*************************************************************************************************
	 * Returns contents of the payloadType field.
	 */
	public short getPayloadType()
	{
		return payloadType_;
	}


	/*************************************************************************************************
	 * Sets the payloadType field.
	 */
	public void setPayloadType(short payloadType)
	{
		payloadType_ = payloadType;
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
	 * Returns contents of the pubkeyDigest field.
	 */
	public TcTpmDigest getPubkeyDigest()
	{
		return pubkeyDigest_;
	}


	/*************************************************************************************************
	 * Sets the pubkeyDigest field.
	 */
	public void setPubkeyDigest(TcTpmDigest pubkeyDigest)
	{
		pubkeyDigest_ = pubkeyDigest;
	}


	/*************************************************************************************************
	 * Returns contents of the data field.
	 */
	public TcTpmNonce getData()
	{
		return data_;
	}


	/*************************************************************************************************
	 * Sets the data field.
	 */
	public void setData(TcTpmNonce data)
	{
		data_ = data;
	}


	/*************************************************************************************************
	 * Returns contents of the parentPCRStatus field.
	 */
	public boolean getParentPCRStatus()
	{
		return parentPCRStatus_;
	}


	/*************************************************************************************************
	 * Sets the parentPCRStatus field.
	 */
	public void setParentPCRStatus(boolean parentPCRStatus)
	{
		parentPCRStatus_ = parentPCRStatus;
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
	 * Returns contents of the migrationAuthoritySize field.
	 */
	public long getMigrationAuthoritySize()
	{
		if (migrationAuthority_ == null ) {
			return 0;
		} else {
			return migrationAuthority_.getLengthAsLong();
		}
	}


	/*************************************************************************************************
	 * Returns contents of the migrationAuthority field.
	 */
	public TcBlobData getMigrationAuthority()
	{
		return migrationAuthority_;
	}


	/*************************************************************************************************
	 * Sets the migrationAuthority field.
	 */
	public void setMigrationAuthority(TcBlobData migrationAuthority)
	{
		migrationAuthority_ = migrationAuthority;
	}

}
