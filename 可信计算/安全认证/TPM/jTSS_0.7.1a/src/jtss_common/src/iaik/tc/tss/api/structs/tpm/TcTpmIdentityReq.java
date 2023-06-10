/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.api.structs.tpm;


import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder;
import iaik.tc.utils.misc.Utils;

/**
 * This structure is sent by the TSS to the Privacy CA to create the identity credential.
 * 
 * @TPM_V1 78
 */
public class TcTpmIdentityReq extends TcCompositeTypeDecoder {

	/**
	 * The parameters for the asymmetric algorithm used to create the asymBlob.
	 */
	protected TcTpmKeyParms asymAlgorithm_;

	/**
	 * The parameters for the symmetric algorithm used to create the symBlob.
	 */
	protected TcTpmKeyParms symAlgorithm_;

	/**
	 * Asymmetric encrypted area from TSS_CollateIdentityRequest.
	 */
	protected TcBlobData asymBlob_;

	/**
	 * Symmetric encrypted area from TSS_CollateIdentityRequest.
	 */
	protected TcBlobData symBlob_;


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 */
	public TcTpmIdentityReq()
	{
		super();
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 */
	public TcTpmIdentityReq(TcBlobData blob)
	{
		super(blob);
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 */
	public TcTpmIdentityReq(TcBlobData blob, int offset)
	{
		super(blob, offset);
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 */
	public TcTpmIdentityReq(TcCompositeTypeDecoder composite)
	{
		super(composite);
	}


	/*************************************************************************************************
	 * This method decodes the TPM_IDENTITY_REQ from the byte blob.
	 */
	protected void decode()
	{
		checkBoundaryPreconditions(8 + 12 + 12); // minimum size

		long asymSize = decodeUINT32();
		long symSize = decodeUINT32();
		asymAlgorithm_ = new TcTpmKeyParms(this);
		symAlgorithm_ = new TcTpmKeyParms(this);
		asymBlob_ = decodeBytes(asymSize);
		symBlob_ = decodeBytes(symSize);
	}


	/*************************************************************************************************
	 * This method encodes the TPM_IDENTITY_REQ as a byte blob.
	 */
	public TcBlobData getEncoded()
	{
		TcBlobData retVal = TcBlobData.newUINT32( getAsymSize());
		retVal.append(TcBlobData.newUINT32( getSymSize()));
		if (asymAlgorithm_ != null) {
			retVal.append(asymAlgorithm_.getEncoded());
		}
		if (symAlgorithm_ != null) {
			retVal.append(symAlgorithm_.getEncoded());
		}
		if (asymBlob_ != null) {
			retVal.append(asymBlob_);
		}
		if (symBlob_ != null) {
			retVal.append(symBlob_);
		}

		return retVal;
	}


	/*************************************************************************************************
	 * This method returns a String representation of the object.
	 */
	public String toString()
	{
		StringBuffer retVal = new StringBuffer();
		retVal.append("asymSize: ");
		retVal.append(getAsymSize());
		retVal.append(Utils.getNL());
		retVal.append("symSize:  ");
		retVal.append(getSymSize());
		retVal.append(Utils.getNL());
		if (asymAlgorithm_ != null) {
			retVal.append("asymAlgorithm:");
			retVal.append(Utils.getNL());
			retVal.append(asymAlgorithm_.toString());
			retVal.append(Utils.getNL());
		}
		if (symAlgorithm_ != null) {
			retVal.append("symAlgorithm: ");
			retVal.append(Utils.getNL());
			retVal.append(symAlgorithm_.toString());
			retVal.append(Utils.getNL());
		}
		if (asymBlob_ != null) {
			retVal.append("asymBlob: ");
			retVal.append(asymBlob_.toHexString());
			retVal.append(Utils.getNL());
		}
		if (symBlob_ != null) {
			retVal.append("symBlob:  ");
			retVal.append(symBlob_.toHexString());
			retVal.append(Utils.getNL());
		}
		return retVal.toString();
	}


	/*************************************************************************************************
	 * Returns contents of the asymAlgorithm field.
	 */
	public TcTpmKeyParms getAsymAlgorithm()
	{
		return asymAlgorithm_;
	}


	/*************************************************************************************************
	 * Sets the asymAlgorithm field.
	 */
	public void setAsymAlgorithm(TcTpmKeyParms asymAlgorithm)
	{
		asymAlgorithm_ = asymAlgorithm;
	}


	/*************************************************************************************************
	 * Returns contents of the asymBlob field.
	 */
	public TcBlobData getAsymBlob()
	{
		return asymBlob_;
	}


	/*************************************************************************************************
	 * Sets the asymBlob field.
	 */
	public void setAsymBlob(TcBlobData asymBlob)
	{
		asymBlob_ = asymBlob;
	}


	/*************************************************************************************************
	 * Returns contents of the asymSize field.
	 */
	public long getAsymSize()
	{
		if (asymBlob_ == null) {
			return 0;
		} else {
			return asymBlob_.getLengthAsLong();
		}
	}


	/*************************************************************************************************
	 * Returns contents of the symAlgorithm field.
	 */
	public TcTpmKeyParms getSymAlgorithm()
	{
		return symAlgorithm_;
	}


	/*************************************************************************************************
	 * Sets the symAlgorithm field.
	 */
	public void setSymAlgorithm(TcTpmKeyParms symAlgorithm)
	{
		symAlgorithm_ = symAlgorithm;
	}


	/*************************************************************************************************
	 * Returns contents of the symBlob field.
	 */
	public TcBlobData getSymBlob()
	{
		return symBlob_;
	}


	/*************************************************************************************************
	 * Sets the symBlob field.
	 */
	public void setSymBlob(TcBlobData symBlob)
	{
		symBlob_ = symBlob;
	}


	/*************************************************************************************************
	 * Returns contents of the symSize field.
	 */
	public long getSymSize()
	{
		if (symBlob_ == null) {
			return 0;
		} else {
			return symBlob_.getLengthAsLong();
		}
	}


}
