/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.api.structs.tpm;


import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder;
import iaik.tc.utils.misc.Utils;

public class TcTpmPcrInfoShort extends TcCompositeTypeDecoder {

	protected TcTpmPcrSelection pcrSelection_;

	protected short localityAtRelease_;

	protected TcTpmCompositeHash digestAtRelease_;


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 *
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder()
	 */
	public TcTpmPcrInfoShort()
	{
		super();
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 *
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcBlobData)
	 */
	public TcTpmPcrInfoShort(TcBlobData data)
	{
		super(data);
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 *
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcBlobData,
	 *      int)
	 */
	public TcTpmPcrInfoShort(TcBlobData data, int offset)
	{
		super(data, offset);
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 *
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder)
	 */
	public TcTpmPcrInfoShort(TcCompositeTypeDecoder composite)
	{
		super(composite);
	}


	/*************************************************************************************************
	 * This method decodes the TPM_PCR_INFO_SHORT from the byte blob.
	 */
	protected void decode()
	{
		checkBoundaryPreconditions(2 + 1 + 20);

		pcrSelection_ = new TcTpmPcrSelection(this);
		localityAtRelease_ = decodeByte();
		digestAtRelease_ = new TcTpmCompositeHash(this);
	}


	/*************************************************************************************************
	 * This method encodes the TPM_PCR_INFO_SHORT as a byte blob.
	 */
	public TcBlobData getEncoded()
	{
		TcBlobData retVal = TcBlobData.newBYTE( localityAtRelease_);
		if (pcrSelection_ != null) {
			retVal.prepend(pcrSelection_.getEncoded());
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

		if (pcrSelection_ != null) {
			retVal.append("pcrSelection: ");
			retVal.append(pcrSelection_.toString());
			retVal.append(Utils.getNL());
		}
		retVal.append("localityAtRelease: ");
		retVal.append(localityAtRelease_);
		retVal.append(Utils.getNL());
		if (digestAtRelease_ != null) {
			retVal.append("digestAtRelease: ");
			retVal.append(digestAtRelease_.toString());
			retVal.append(Utils.getNL());
		}

		return retVal.toString();
	}


	/*************************************************************************************************
	 * Returns contents of the pcrSelection field.
	 */
	public TcTpmPcrSelection getPcrSelection()
	{
		return pcrSelection_;
	}


	/*************************************************************************************************
	 * Sets the pcrSelection field.
	 */
	public void setPcrSelection(TcTpmPcrSelection pcrSelection)
	{
		pcrSelection_ = pcrSelection;
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

	/*************************************************************************************************
	 * Set all required members
	 */
	public void init(TcTpmPcrSelection pcrSelection, short localityAtRelease,
			TcTpmCompositeHash digestAtRelease) {
		pcrSelection_      = pcrSelection;
		localityAtRelease_ = localityAtRelease;
		digestAtRelease_   = digestAtRelease;
	}

}
