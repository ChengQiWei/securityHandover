/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.api.structs.tpm;


import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder;
import iaik.tc.utils.misc.Utils;

public class TcTpmMigrateAsymkey extends TcCompositeTypeDecoder {
	protected short payload_;

	protected TcTpmSecret usageAuth_;

	protected TcTpmDigest pubDataDigest_;

	protected long partPrivKeyLen_;

	protected TcBlobData partPrivKey_;


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder()
	 */
	public TcTpmMigrateAsymkey()
	{
		super();
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcBlobData)
	 */
	public TcTpmMigrateAsymkey(TcBlobData data)
	{
		super(data);
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcBlobData,
	 *      int)
	 */
	public TcTpmMigrateAsymkey(TcBlobData data, int offset)
	{
		super(data, offset);
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder)
	 */
	public TcTpmMigrateAsymkey(TcCompositeTypeDecoder composite)
	{
		super(composite);
	}


	/*************************************************************************************************
	 * This method decodes the TPM_MIGRATE_ASYMKEY from the byte blob.
	 */
	protected void decode()
	{
		checkBoundaryPreconditions(1 + 20 + 20 + 4);

		payload_ = decodeByte();
		usageAuth_ = new TcTpmSecret(this);
		pubDataDigest_ = new TcTpmDigest(this);
		partPrivKeyLen_ = decodeUINT32();
		if (partPrivKeyLen_ > 0) {
			partPrivKey_ = decodeBytes(partPrivKeyLen_);
		}

	}


	/*************************************************************************************************
	 * This method encodes the TPM_MIGRATE_ASYMKEY as a byte blob.
	 */
	public TcBlobData getEncoded()
	{
		TcBlobData retVal = TcBlobData.newBYTE( payload_);
		if (usageAuth_ != null) {
			retVal.append(usageAuth_.getEncoded());
		}
		if (pubDataDigest_ != null) {
			retVal.append(pubDataDigest_.getEncoded());
		}
		retVal.append(TcBlobData.newUINT32( partPrivKeyLen_));
		if (partPrivKey_ != null) {
			retVal.append(partPrivKey_);
		}

		return retVal;
	}


	/*************************************************************************************************
	 * This method returns a String representation of the object.
	 */
	public String toString()
	{
		StringBuffer retVal = new StringBuffer();

		retVal.append("payload: ");
		retVal.append(payload_);
		retVal.append(Utils.getNL());
		if (usageAuth_ != null) {
			retVal.append("usageAuth: ");
			retVal.append(usageAuth_.toString());
			retVal.append(Utils.getNL());
		}
		if (pubDataDigest_ != null) {
			retVal.append("pubDataDigest: ");
			retVal.append(pubDataDigest_.toString());
			retVal.append(Utils.getNL());
		}
		retVal.append("partPrivKeyLen: ");
		retVal.append(partPrivKeyLen_);
		retVal.append(Utils.getNL());
		if (partPrivKey_ != null) {
			retVal.append("partPrivKey: ");
			retVal.append(partPrivKey_.toHexString());
			retVal.append(Utils.getNL());
		}

		return retVal.toString();
	}


	/*************************************************************************************************
	 * Returns contents of the payload field.
	 */
	public short getPayload()
	{
		return payload_;
	}


	/*************************************************************************************************
	 * Sets the payload field.
	 */
	public void setPayload(short payload)
	{
		payload_ = payload;
	}


	/*************************************************************************************************
	 * Returns contents of the usageAuth field.
	 */
	public TcTpmSecret getUsageAuth()
	{
		return usageAuth_;
	}


	/*************************************************************************************************
	 * Sets the usageAuth field.
	 */
	public void setUsageAuth(TcTpmSecret usageAuth)
	{
		usageAuth_ = usageAuth;
	}


	/*************************************************************************************************
	 * Returns contents of the pubDataDigest field.
	 */
	public TcTpmDigest getPubDataDigest()
	{
		return pubDataDigest_;
	}


	/*************************************************************************************************
	 * Sets the pubDataDigest field.
	 */
	public void setPubDataDigest(TcTpmDigest pubDataDigest)
	{
		pubDataDigest_ = pubDataDigest;
	}


	/*************************************************************************************************
	 * Returns contents of the partPrivKeyLen field.
	 */
	public long getPartPrivKeyLen()
	{
		return partPrivKeyLen_;
	}


	/*************************************************************************************************
	 * Sets the partPrivKeyLen field.
	 */
	public void setPartPrivKeyLen(long partPrivKeyLen)
	{
		partPrivKeyLen_ = partPrivKeyLen;
	}


	/*************************************************************************************************
	 * Returns contents of the partPrivKey field.
	 */
	public TcBlobData getPartPrivKey()
	{
		return partPrivKey_;
	}


	/*************************************************************************************************
	 * Sets the partPrivKey field.
	 */
	public void setPartPrivKey(TcBlobData partPrivKey)
	{
		partPrivKey_ = partPrivKey;
	}

}
