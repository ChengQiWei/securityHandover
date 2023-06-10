/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.api.structs.tpm;


import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder;
import iaik.tc.utils.misc.Utils;

/**
 * This class contains the symmetric key to encrypt the identity credential. <br>
 * 
 * @TPM_V1 90
 */
public class TcTpmAsymCaContents extends TcCompositeTypeDecoder {

	/**
	 * The session key used by the CA to encrypt the TPM_IDENTITY_CREDENTIAL
	 */
	protected TcTpmSymmetricKey sessionKey_;

	/**
	 * The digest of the TPM identity public key that is being certified by the CA.
	 */
	protected TcTpmDigest idDigest_;


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 */
	public TcTpmAsymCaContents()
	{
		super();
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 */
	public TcTpmAsymCaContents(TcBlobData blob)
	{
		super(blob);
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 */
	public TcTpmAsymCaContents(TcBlobData blob, int offset)
	{
		super(blob, offset);
	}


	/*************************************************************************************************
	 * Constructor
	 */
	public TcTpmAsymCaContents(TcCompositeTypeDecoder composite)
	{
		super(composite);
	}


	/*************************************************************************************************
	 * This method decodes the TPM_ASYM_CA_CONTENTS from the byte blob.
	 */
	protected void decode()
	{
		sessionKey_ = new TcTpmSymmetricKey(this);
		idDigest_ = new TcTpmDigest(this);
	}


	/*************************************************************************************************
	 * This method encodes the TPM_ASYM_CA_CONTENTS as a byte blob.
	 */
	public TcBlobData getEncoded()
	{
		TcBlobData retVal = null;

		if (sessionKey_ != null) {
			retVal = TcBlobData.newBlobData((sessionKey_.getEncoded()));
			if (idDigest_ != null) {
				retVal.append(idDigest_.getEncoded());
			}
		} else {
			if (idDigest_ != null) {
				retVal = TcBlobData.newBlobData(idDigest_.getEncoded());
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

		if (sessionKey_ != null) {
			retVal.append("sessionKey: ");
			retVal.append(Utils.getNL());
			retVal.append(sessionKey_.toString());
			retVal.append(Utils.getNL());
		}
		if (idDigest_ != null) {
			retVal.append("idDigest: ");
			retVal.append(Utils.getNL());
			retVal.append(idDigest_.toString());
			retVal.append(Utils.getNL());
		}

		return retVal.toString();
	}


	public TcTpmDigest getIdDigest()
	{
		return idDigest_;
	}


	/*************************************************************************************************
	 * Returns contents of the sessionKey field.
	 */
	public TcTpmSymmetricKey getSessionKey()
	{
		return sessionKey_;
	}


	/*************************************************************************************************
	 * Sets the sessionKey field.
	 */
	public void setSessionKey(TcTpmSymmetricKey sessionKey)
	{
		sessionKey_ = sessionKey;
	}


	/*************************************************************************************************
	 * Sets the idDigest field.
	 */
	public void setIdDigest(TcTpmDigest idDigest)
	{
		idDigest_ = idDigest;
	}
}
