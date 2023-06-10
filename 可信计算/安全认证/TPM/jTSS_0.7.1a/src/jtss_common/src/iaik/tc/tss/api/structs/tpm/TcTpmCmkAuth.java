/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.api.structs.tpm;


import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder;
import iaik.tc.utils.misc.Utils;

public class TcTpmCmkAuth extends TcCompositeTypeDecoder {
	protected TcTpmDigest migrationAuthorityDigest_;

	protected TcTpmDigest destinationKeyDigest_;

	protected TcTpmDigest sourceKeyDigest_;


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder()
	 */
	public TcTpmCmkAuth()
	{
		super();
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcBlobData)
	 */
	public TcTpmCmkAuth(TcBlobData data)
	{
		super(data);
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcBlobData,
	 *      int)
	 */
	public TcTpmCmkAuth(TcBlobData data, int offset)
	{
		super(data, offset);
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder)
	 */
	public TcTpmCmkAuth(TcCompositeTypeDecoder composite)
	{
		super(composite);
	}


	/*************************************************************************************************
	 * This method decodes the TPM_CMK_AUTH from the byte blob.
	 */
	protected void decode()
	{
		checkBoundaryPreconditions(60);

		migrationAuthorityDigest_ = new TcTpmDigest(this);
		destinationKeyDigest_ = new TcTpmDigest(this);
		sourceKeyDigest_ = new TcTpmDigest(this);

	}


	/*************************************************************************************************
	 * This method encodes the TPM_CMK_AUTH as a byte blob.
	 */
	public TcBlobData getEncoded()
	{
		TcBlobData retVal = null;

		if (migrationAuthorityDigest_ != null) {
			retVal = TcBlobData.newBlobData(migrationAuthorityDigest_.getEncoded());
		}
		if (destinationKeyDigest_ != null) {
			if (retVal != null) {
				retVal.append(destinationKeyDigest_.getEncoded());
			} else {
				retVal = TcBlobData.newBlobData(destinationKeyDigest_.getEncoded());
			}
		}
		if (sourceKeyDigest_ != null) {
			if (retVal != null) {
				retVal.append(sourceKeyDigest_.getEncoded());
			} else {
				retVal = TcBlobData.newBlobData(sourceKeyDigest_.getEncoded());
			}
		}

		return retVal;
	}


	/*************************************************************************************************
	 * This method returns a String representation of the object.
	 */
	public String toString()
	{
		StringBuffer retVal = new StringBuffer();

		if (migrationAuthorityDigest_ != null) {
			retVal.append("migrationAuthorityDigest: ");
			retVal.append(migrationAuthorityDigest_.toString());
			retVal.append(Utils.getNL());
		}
		if (destinationKeyDigest_ != null) {
			retVal.append("destinationKeyDigest: ");
			retVal.append(destinationKeyDigest_.toString());
			retVal.append(Utils.getNL());
		}
		if (sourceKeyDigest_ != null) {
			retVal.append("sourceKeyDigest: ");
			retVal.append(sourceKeyDigest_.toString());
			retVal.append(Utils.getNL());
		}

		return retVal.toString();
	}


	/*************************************************************************************************
	 * Returns contents of the migrationAuthorityDigest field.
	 */
	public TcTpmDigest getMigrationAuthorityDigest()
	{
		return migrationAuthorityDigest_;
	}


	/*************************************************************************************************
	 * Sets the migrationAuthorityDigest field.
	 */
	public void setMigrationAuthorityDigest(TcTpmDigest migrationAuthorityDigest)
	{
		migrationAuthorityDigest_ = migrationAuthorityDigest;
	}


	/*************************************************************************************************
	 * Returns contents of the destinationKeyDigest field.
	 */
	public TcTpmDigest getDestinationKeyDigest()
	{
		return destinationKeyDigest_;
	}


	/*************************************************************************************************
	 * Sets the destinationKeyDigest field.
	 */
	public void setDestinationKeyDigest(TcTpmDigest destinationKeyDigest)
	{
		destinationKeyDigest_ = destinationKeyDigest;
	}


	/*************************************************************************************************
	 * Returns contents of the sourceKeyDigest field.
	 */
	public TcTpmDigest getSourceKeyDigest()
	{
		return sourceKeyDigest_;
	}


	/*************************************************************************************************
	 * Sets the sourceKeyDigest field.
	 */
	public void setSourceKeyDigest(TcTpmDigest sourceKeyDigest)
	{
		sourceKeyDigest_ = sourceKeyDigest;
	}

}
