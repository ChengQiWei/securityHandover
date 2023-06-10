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
 * The digest value reports the result of a hash operation. In Version 1.0 of this specification the
 * hash algorithm is SHA-1 with a resulting hash result being 160 bits. This lack of flexibility is
 * because the size of a digest has a dramatic effect on the implementation of a hardware TPM.
 * 
 * @TPM_V1 26
 */
public class TcTpmDigest extends TcCompositeTypeDecoder {

	/**
	 * The actual digest information.
	 */
	protected TcBlobData digest_;


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 */
	public TcTpmDigest()
	{
		super();
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 */
	public TcTpmDigest(TcBlobData blob)
	{
		super(blob);
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 */
	public TcTpmDigest(TcBlobData blob, int offset)
	{
		super(blob, offset);
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 */
	public TcTpmDigest(TcCompositeTypeDecoder composite)
	{
		super(composite);
	}


	/*************************************************************************************************
	 * This method decodes the TPM_DIGEST from the byte blob.
	 */
	protected void decode()
	{
		checkBoundaryPreconditions((int) TcTpmConstants.TPM_SHA1_160_HASH_LEN);
		digest_ = decodeBytes(TcTpmConstants.TPM_SHA1_160_HASH_LEN);
	}


	/*************************************************************************************************
	 * This method encodes the TPM_DIGEST as a byte blob.
	 */
	public TcBlobData getEncoded()
	{
		return (TcBlobData)digest_.clone();
	}


	/*************************************************************************************************
	 * This method returns a String representation of the object.
	 */
	public String toString()
	{
		StringBuffer retVal = new StringBuffer();

		if (digest_ != null) {
			retVal.append("digest: ");
			retVal.append(digest_.toHexString());
			retVal.append(Utils.getNL());
		}

		return retVal.toString();
	}


	/*************************************************************************************************
	 * Returns contents of the digest field.
	 */
	public TcBlobData getDigest()
	{
		return digest_;
	}


	/*************************************************************************************************
	 * Sets the digest field.
	 */
	public void setDigest(TcBlobData digest)
	{
		digest_ = digest;
	}
}
