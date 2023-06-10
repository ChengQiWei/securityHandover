/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.api.structs.tpm;


import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder;
import iaik.tc.utils.misc.Utils;

/**
 * This structure is returned by the Privacy CA with the encrypted identity credential.
 * 
 * @TPM_V1 81
 */
public class TcTpmSymCaAttestation extends TcCompositeTypeDecoder {

	protected TcTpmKeyParms algorithm_;

	protected TcBlobData credential_;


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 */
	public TcTpmSymCaAttestation()
	{
		super();
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 */
	public TcTpmSymCaAttestation(TcBlobData data)
	{
		super(data);
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 */
	public TcTpmSymCaAttestation(TcBlobData data, int offset)
	{
		super(data, offset);
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 */
	public TcTpmSymCaAttestation(TcCompositeTypeDecoder composite)
	{
		super(composite);
	}


	/*************************************************************************************************
	 * This method decodes the TPM_SYM_CA_ATTESTATION from the byte blob.
	 */
	protected void decode()
	{
		checkBoundaryPreconditions(4 + 12); // minimum size (credSize_ + algorithm_)

		long credSize = decodeUINT32();
		algorithm_ = new TcTpmKeyParms(this);
		credential_ = decodeBytes(credSize);
	}


	/*************************************************************************************************
	 * This method encodes the TPM_SYM_CA_ATTESTATION as a byte blob.
	 */
	public TcBlobData getEncoded()
	{
		TcBlobData retVal = TcBlobData.newUINT32( getCredSize());
		if (algorithm_ != null) {
			retVal.append(algorithm_.getEncoded());
		}
		if (credential_ != null) {
			retVal.append(credential_);
		}
		return retVal;
	}


	/*************************************************************************************************
	 * This method returns a String representation of the object.
	 */
	public String toString()
	{
		StringBuffer retVal = new StringBuffer();

		retVal.append("credSize: ");
		retVal.append(getCredSize());
		retVal.append(Utils.getNL());
		if (algorithm_ != null) {
			retVal.append("algorithm: ");
			retVal.append(Utils.getNL());
			retVal.append(algorithm_.toString());
			retVal.append(Utils.getNL());
		}
		if (credential_ != null) {
			retVal.append("credential: ");
			retVal.append(credential_.toHexString());
			retVal.append(Utils.getNL());
		}

		return retVal.toString();
	}


	/*************************************************************************************************
	 * Returns contents of the algorithm field.
	 */
	public TcTpmKeyParms getAlgorithm()
	{
		return algorithm_;
	}


	/*************************************************************************************************
	 * Sets the algorithm field.
	 */
	public void setAlgorithm(TcTpmKeyParms algoritm)
	{
		algorithm_ = algoritm;
	}


	/*************************************************************************************************
	 * Returns contents of the credential field.
	 */
	public TcBlobData getCredential()
	{
		return credential_;
	}


	/*************************************************************************************************
	 * Sets the credential field.
	 */
	public void setCredential(TcBlobData credential)
	{
		credential_ = credential;
	}


	/*************************************************************************************************
	 * Returns contents of the credSize field.
	 */
	public long getCredSize()
	{
		if (credential_ == null) {
			return 0;
		} else {
			return credential_.getLengthAsLong();
		}
	}


}
