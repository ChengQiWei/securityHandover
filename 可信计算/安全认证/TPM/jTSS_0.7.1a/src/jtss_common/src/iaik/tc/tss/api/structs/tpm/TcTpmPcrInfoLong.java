/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.api.structs.tpm;


import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder;
import iaik.tc.utils.misc.Utils;

public class TcTpmPcrInfoLong extends TcCompositeTypeDecoder implements TcITpmPcrInfo {
	protected int tag_;

	protected short localityAtCreation_;

	protected short localityAtRelease_;

	protected TcTpmPcrSelection creationPCRSelection_;

	protected TcTpmPcrSelection releasePCRSelection_;

	protected TcTpmCompositeHash digestAtCreation_;

	protected TcTpmCompositeHash digestAtRelease_;


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder()
	 */
	public TcTpmPcrInfoLong()
	{
		super();
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcBlobData)
	 */
	public TcTpmPcrInfoLong(TcBlobData data)
	{
		super(data);
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcBlobData,
	 *      int)
	 */
	public TcTpmPcrInfoLong(TcBlobData data, int offset)
	{
		super(data, offset);
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder)
	 */
	public TcTpmPcrInfoLong(TcCompositeTypeDecoder composite)
	{
		super(composite);
	}


	/*************************************************************************************************
	 * This method decodes the TPM_PCR_INFO_LONG from the byte blob.
	 */
	protected void decode()
	{
		checkBoundaryPreconditions(2 + 2 * 2 + 2 * 20);

		tag_ = decodeUINT16();
		localityAtCreation_ = decodeByte();
		localityAtRelease_ = decodeByte();
		creationPCRSelection_ = new TcTpmPcrSelection(this);
		releasePCRSelection_ = new TcTpmPcrSelection(this);
		digestAtCreation_ = new TcTpmCompositeHash(this);
		digestAtRelease_ = new TcTpmCompositeHash(this);

	}


	/*************************************************************************************************
	 * This method encodes the TPM_PCR_INFO_LONG as a byte blob.
	 */
	public TcBlobData getEncoded()
	{
		TcBlobData retVal = TcBlobData.newUINT16( tag_);
		retVal.append(TcBlobData.newBYTE( localityAtCreation_));
		retVal.append(TcBlobData.newBYTE( localityAtRelease_));
		if (creationPCRSelection_ != null) {
			retVal.append(creationPCRSelection_.getEncoded());
		}
		if (releasePCRSelection_ != null) {
			retVal.append(releasePCRSelection_.getEncoded());
		}
		if (digestAtCreation_ != null) {
			retVal.append(digestAtCreation_.getEncoded());
		}
		if (digestAtRelease_ != null) {
			retVal.append(digestAtRelease_.getEncoded());
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
		retVal.append("localityAtCreation: ");
		retVal.append(localityAtCreation_);
		retVal.append(Utils.getNL());
		retVal.append("localityAtRelease: ");
		retVal.append(localityAtRelease_);
		retVal.append(Utils.getNL());
		if (creationPCRSelection_ != null) {
			retVal.append("creationPCRSelection: ");
			retVal.append(creationPCRSelection_.toString());
			retVal.append(Utils.getNL());
		}
		if (releasePCRSelection_ != null) {
			retVal.append("releasePCRSelection: ");
			retVal.append(releasePCRSelection_.toString());
			retVal.append(Utils.getNL());
		}
		if (digestAtCreation_ != null) {
			retVal.append("digestAtCreation: ");
			retVal.append(digestAtCreation_.toString());
			retVal.append(Utils.getNL());
		}
		if (digestAtRelease_ != null) {
			retVal.append("digestAtRelease: ");
			retVal.append(digestAtRelease_.toString());
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
	 * Returns contents of the localityAtCreation field.
	 */
	public short getLocalityAtCreation()
	{
		return localityAtCreation_;
	}


	/*************************************************************************************************
	 * Sets the localityAtCreation field.
	 */
	public void setLocalityAtCreation(short localityAtCreation)
	{
		localityAtCreation_ = localityAtCreation;
	}


	/*************************************************************************************************
	 * Returns contents of the localityAtRelease field.
	 */
	public short getLocalityAtRelease()
	{
		return localityAtRelease_;
	}


	/*************************************************************************************************
	 * Sets the localityAtRelease field.
	 */
	public void setLocalityAtRelease(short localityAtRelease)
	{
		localityAtRelease_ = localityAtRelease;
	}


	/*************************************************************************************************
	 * Returns contents of the creationPCRSelection field.
	 */
	public TcTpmPcrSelection getCreationPCRSelection()
	{
		return creationPCRSelection_;
	}


	/*************************************************************************************************
	 * Sets the creationPCRSelection field.
	 */
	public void setCreationPCRSelection(TcTpmPcrSelection creationPCRSelection)
	{
		creationPCRSelection_ = creationPCRSelection;
	}


	/*************************************************************************************************
	 * Returns contents of the releasePCRSelection field.
	 */
	public TcTpmPcrSelection getReleasePcrSelection()
	{
		return releasePCRSelection_;
	}


	/*************************************************************************************************
	 * Sets the releasePCRSelection field.
	 */
	public void setReleasePCRSelection(TcTpmPcrSelection releasePCRSelection)
	{
		releasePCRSelection_ = releasePCRSelection;
	}


	/*************************************************************************************************
	 * Returns contents of the digestAtCreation field.
	 */
	public TcTpmCompositeHash getDigestAtCreation()
	{
		return digestAtCreation_;
	}


	/*************************************************************************************************
	 * Sets the digestAtCreation field.
	 */
	public void setDigestAtCreation(TcTpmCompositeHash digestAtCreation)
	{
		digestAtCreation_ = digestAtCreation;
	}


	/*************************************************************************************************
	 * Returns contents of the digestAtRelease field.
	 */
	public TcTpmCompositeHash getDigestAtRelease()
	{
		return digestAtRelease_;
	}


	/*************************************************************************************************
	 * Sets the digestAtRelease field.
	 */
	public void setDigestAtRelease(TcTpmCompositeHash digestAtRelease)
	{
		digestAtRelease_ = digestAtRelease;
	}

}
