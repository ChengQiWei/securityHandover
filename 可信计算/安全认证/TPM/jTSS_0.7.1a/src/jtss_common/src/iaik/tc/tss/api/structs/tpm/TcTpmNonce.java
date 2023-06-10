/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.api.structs.tpm;


import iaik.tc.tss.api.constants.tpm.TcTpmConstants;
import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder;
import iaik.tc.utils.misc.Utils;

/**
 * A nonce is a random value that provides protection from replay and other attacks. Many of the
 * commands and protocols in the TCG TPM specification require a nonce represented by this class.
 * 
 * @TPM_V1 27
 */
public class TcTpmNonce extends TcCompositeTypeDecoder {

	/**
	 * The actual nonce.
	 */
	protected TcBlobData nonce_;


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder()
	 */
	public TcTpmNonce()
	{
		super();
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcBlobData)
	 */
	public TcTpmNonce(TcBlobData data)
	{
		super(data);
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcBlobData,
	 *      int)
	 */
	public TcTpmNonce(TcBlobData data, int offset)
	{
		super(data, offset);
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder)
	 */
	public TcTpmNonce(TcCompositeTypeDecoder composite)
	{
		super(composite);
	}


	/*************************************************************************************************
	 * This method decodes the TPM_NONCE from the byte blob.
	 */
	protected void decode()
	{
		checkBoundaryPreconditions((int) TcTpmConstants.TPM_SHA1BASED_NONCE_LEN);
		nonce_ = decodeBytes(TcTpmConstants.TPM_SHA1BASED_NONCE_LEN);
	}


	/*************************************************************************************************
	 * This method encodes the TPM_NONCE as a byte blob.
	 */
	public TcBlobData getEncoded()
	{
		return (TcBlobData)nonce_.clone();
	}


	/*************************************************************************************************
	 * This method returns a String representation of the object.
	 */
	public String toString()
	{
		StringBuffer retVal = new StringBuffer();

		if (nonce_ != null) {
			retVal.append("nonce: ");
			retVal.append(nonce_.toHexString());
			retVal.append(Utils.getNL());
		}

		return retVal.toString();
	}

	
	/*************************************************************************************************
	 * Returns true if the provided object is equal to this object.
	 */
	public boolean equals(Object obj)
	{
		if (!(obj instanceof TcTpmNonce)) {
			return false;
		}
		
		TcTpmNonce other = (TcTpmNonce)obj;
		
		if (getEncoded() == null && other.getEncoded() == null) {
			return true;
		}

		if (getEncoded() == null || other.getEncoded() == null) {
			return false;
		}

		return getEncoded().equals(other.getEncoded());
	}
	
	

	/*************************************************************************************************
	 * Returns contents of the nonce field.
	 */
	public TcBlobData getNonce()
	{
		return nonce_;
	}


	/*************************************************************************************************
	 * Sets the nonce field.
	 */
	public void setDigest(TcBlobData nonce)
	{
		nonce_ = nonce;
	}

}
