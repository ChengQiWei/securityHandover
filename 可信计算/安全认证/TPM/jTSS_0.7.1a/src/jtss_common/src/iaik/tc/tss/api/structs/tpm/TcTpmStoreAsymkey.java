/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.api.structs.tpm;


import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder;
import iaik.tc.utils.misc.Utils;

public class TcTpmStoreAsymkey extends TcCompositeTypeDecoder {
	protected short payload_;

	protected TcTpmSecret usageAuth_;

	protected TcTpmSecret migrationAuth_;

	protected TcTpmDigest pubDataDigest_;

	protected TcTpmStorePrivkey privKey_;


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder()
	 */
	public TcTpmStoreAsymkey()
	{
		super();
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcBlobData)
	 */
	public TcTpmStoreAsymkey(TcBlobData data)
	{
		super(data);
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcBlobData,
	 *      int)
	 */
	public TcTpmStoreAsymkey(TcBlobData data, int offset)
	{
		super(data, offset);
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder)
	 */
	public TcTpmStoreAsymkey(TcCompositeTypeDecoder composite)
	{
		super(composite);
	}


	/*************************************************************************************************
	 * This method decodes the TPM_STORE_ASYMKEY from the byte blob.
	 */
	protected void decode()
	{
		checkBoundaryPreconditions(1 + 3 * 20 + 4);

		payload_ = decodeByte();
		usageAuth_ = new TcTpmSecret(this);
		migrationAuth_ = new TcTpmSecret(this);
		pubDataDigest_ = new TcTpmDigest(this);
		privKey_ = new TcTpmStorePrivkey(this);

	}


	/*************************************************************************************************
	 * This method encodes the TPM_STORE_ASYMKEY as a byte blob.
	 */
	public TcBlobData getEncoded()
	{
		TcBlobData retVal = TcBlobData.newBYTE( payload_);
		if (usageAuth_ != null) {
			retVal.append(usageAuth_.getEncoded());
		}
		if (migrationAuth_ != null) {
			retVal.append(migrationAuth_.getEncoded());
		}
		if (pubDataDigest_ != null) {
			retVal.append(pubDataDigest_.getEncoded());
		}
		if (privKey_ != null) {
			retVal.append(privKey_.getEncoded());
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
		if (migrationAuth_ != null) {
			retVal.append("migrationAuth: ");
			retVal.append(migrationAuth_.toString());
			retVal.append(Utils.getNL());
		}
		if (pubDataDigest_ != null) {
			retVal.append("pubDataDigest: ");
			retVal.append(pubDataDigest_.toString());
			retVal.append(Utils.getNL());
		}
		if (privKey_ != null) {
			retVal.append("privKey: ");
			retVal.append(privKey_.toString());
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
	 * Returns contents of the migrationAuth field.
	 */
	public TcTpmSecret getMigrationAuth()
	{
		return migrationAuth_;
	}


	/*************************************************************************************************
	 * Sets the migrationAuth field.
	 */
	public void setMigrationAuth(TcTpmSecret migrationAuth)
	{
		migrationAuth_ = migrationAuth;
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
	 * Returns contents of the privKey field.
	 */
	public TcTpmStorePrivkey getPrivKey()
	{
		return privKey_;
	}


	/*************************************************************************************************
	 * Sets the privKey field.
	 */
	public void setPrivKey(TcTpmStorePrivkey privKey)
	{
		privKey_ = privKey;
	}

}
