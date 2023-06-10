/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.api.structs.tpm;


import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder;
import iaik.tc.utils.misc.Utils;

/**
 * The TPM_PCR_INFO structure contains the information related to the wrapping of a key or the
 * sealing of data, to a set of PCRs.
 * 
 * @TPM_V1 62
 */

public class TcTpmPcrInfo extends TcCompositeTypeDecoder implements TcITpmPcrInfo {

	/**
	 * This SHALL be the selection of PCRs to which the data or key is bound.
	 */
	protected TcTpmPcrSelection pcrSelection_;

	/**
	 * This SHALL be the digest of the PCR indices and PCR values to verify when revealing Sealed Data
	 * or using a key that was wrapped to PCRs.
	 */
	protected TcTpmCompositeHash digestAtRelease_;

	/**
	 * This SHALL be the composite digest value of the PCR values, at the time when the sealing is
	 * performed.
	 */
	protected TcTpmCompositeHash digestAtCreation_;


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder()
	 */
	public TcTpmPcrInfo()
	{
		super();
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcBlobData)
	 */
	public TcTpmPcrInfo(TcBlobData data)
	{
		super(data);
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcBlobData,
	 *      int)
	 */
	public TcTpmPcrInfo(TcBlobData data, int offset)
	{
		super(data, offset);
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder)
	 */
	public TcTpmPcrInfo(TcCompositeTypeDecoder composite)
	{
		super(composite);
	}


	/*************************************************************************************************
	 * This method decodes the TPM_PCR_INFO from the byte blob.
	 */
	protected void decode()
	{
		checkBoundaryPreconditions(42);

		pcrSelection_ = new TcTpmPcrSelection(this);
		digestAtRelease_ = new TcTpmCompositeHash(this);
		digestAtCreation_ = new TcTpmCompositeHash(this);
	}


	/*************************************************************************************************
	 * This method encodes the TPM_PCR_INFO as a byte blob.
	 */
	public TcBlobData getEncoded()
	{
		TcBlobData retVal = null;

		if (pcrSelection_ != null) {
			retVal = pcrSelection_.getEncoded();
		}

		if (digestAtRelease_ != null) {
			if (retVal != null) {
				retVal.append(digestAtRelease_.getEncoded());
			} else {
				retVal = digestAtRelease_.getEncoded();
			}
		}

		if (digestAtCreation_ != null) {
			if (retVal != null) {
				retVal.append(digestAtCreation_.getEncoded());
			} else {
				retVal = digestAtCreation_.getEncoded();
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

		if (pcrSelection_ != null) {
			retVal.append("pcrSelection: ");
			retVal.append(pcrSelection_.toString());
			retVal.append(Utils.getNL());
		}
		if (digestAtRelease_ != null) {
			retVal.append("digestAtRelease: ");
			retVal.append(digestAtRelease_.toString());
			retVal.append(Utils.getNL());
		}
		if (digestAtCreation_ != null) {
			retVal.append("digestAtCreation: ");
			retVal.append(digestAtCreation_.toString());
			retVal.append(Utils.getNL());
		}

		return retVal.toString();
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

}
