/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.api.structs.tpm;


import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder;
import iaik.tc.utils.misc.Utils;

public class TcTpmMigrationkeyAuth extends TcCompositeTypeDecoder {
	protected TcTpmPubkey migrationKey_;

	protected int migrationScheme_;

	protected TcTpmDigest digest_;


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder()
	 */
	public TcTpmMigrationkeyAuth()
	{
		super();
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcBlobData)
	 */
	public TcTpmMigrationkeyAuth(TcBlobData data)
	{
		super(data);
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcBlobData,
	 *      int)
	 */
	public TcTpmMigrationkeyAuth(TcBlobData data, int offset)
	{
		super(data, offset);
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder)
	 */
	public TcTpmMigrationkeyAuth(TcCompositeTypeDecoder composite)
	{
		super(composite);
	}


	/*************************************************************************************************
	 * This method decodes the TPM_MIGRATIONKEY_AUTH from the byte blob.
	 */
	protected void decode()
	{
		checkBoundaryPreconditions(16 + 2 + 20);

		migrationKey_ = new TcTpmPubkey(this);
		migrationScheme_ = decodeUINT16();
		digest_ = new TcTpmDigest(this);

	}


	/*************************************************************************************************
	 * This method encodes the TPM_MIGRATIONKEY_AUTH as a byte blob.
	 */
	public TcBlobData getEncoded()
	{
		TcBlobData retVal = TcBlobData.newUINT16(migrationScheme_);
		if (migrationKey_ != null) {
			retVal.prepend(migrationKey_.getEncoded());
		}
		if (digest_ != null) {
			retVal.append(digest_.getEncoded());
		}

		return retVal;
	}


	/*************************************************************************************************
	 * This method returns a String representation of the object.
	 */
	public String toString()
	{
		StringBuffer retVal = new StringBuffer();

		if (migrationKey_ != null) {
			retVal.append("migrationKey: ");
			retVal.append(migrationKey_.toString());
			retVal.append(Utils.getNL());
		}
		retVal.append("migrationScheme: ");
		retVal.append(migrationScheme_);
		retVal.append(Utils.getNL());
		if (digest_ != null) {
			retVal.append("digest: ");
			retVal.append(digest_.toString());
			retVal.append(Utils.getNL());
		}

		return retVal.toString();
	}


	/*************************************************************************************************
	 * Returns contents of the migrationKey field.
	 */
	public TcTpmPubkey getMigrationKey()
	{
		return migrationKey_;
	}


	/*************************************************************************************************
	 * Sets the migrationKey field.
	 */
	public void setMigrationKey(TcTpmPubkey migrationKey)
	{
		migrationKey_ = migrationKey;
	}


	/*************************************************************************************************
	 * Returns contents of the migrationScheme field.
	 */
	public int getMigrationScheme()
	{
		return migrationScheme_;
	}


	/*************************************************************************************************
	 * Sets the migrationScheme field.
	 */
	public void setMigrationScheme(int migrationScheme)
	{
		migrationScheme_ = migrationScheme;
	}


	/*************************************************************************************************
	 * Returns contents of the digest field.
	 */
	public TcTpmDigest getDigest()
	{
		return digest_;
	}


	/*************************************************************************************************
	 * Sets the digest field.
	 */
	public void setDigest(TcTpmDigest digest)
	{
		digest_ = digest;
	}

}
