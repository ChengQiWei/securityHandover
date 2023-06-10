/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.api.structs.tpm;


import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder;
import iaik.tc.utils.misc.Utils;

/**
 * The TPM_PUBKEY structure contains the public portion of an asymmetric key pair. It contains all
 * the information necessary for its unambiguous usage. It is possible to construct this structure
 * from a TPM_KEY, using the algorithmParms and pubKey fields.
 * 
 * @TPM_V1 70
 */
public class TcTpmPubkey extends TcCompositeTypeDecoder {

	/**
	 * The information regarding this key.
	 */
	protected TcTpmKeyParms algorithmParms_;

	/**
	 * The public key object.
	 */
	protected TcTpmStorePubkey pubKey_;


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 */
	public TcTpmPubkey()
	{
		super();
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 */
	public TcTpmPubkey(TcBlobData blob)
	{
		super(blob);
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 */
	public TcTpmPubkey(TcBlobData blob, int offset)
	{
		super(blob, offset);
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 */
	public TcTpmPubkey(TcCompositeTypeDecoder composite)
	{
		super(composite);
	}


	/*************************************************************************************************
	 * This method decodes the TPM_PUBKEY from the byte blob.
	 */
	protected void decode()
	{
		checkBoundaryPreconditions(12 + 4); // minimum size (algorithmParms_ + pubKey_)
		algorithmParms_ = new TcTpmKeyParms(this);
		pubKey_ = new TcTpmStorePubkey(this);
	}


	/*************************************************************************************************
	 * This method encodes the TPM_PUBKEY as a byte blob.
	 */
	public TcBlobData getEncoded()
	{
		TcBlobData retVal = null;
		if (algorithmParms_ != null) {
			retVal = algorithmParms_.getEncoded();
		}
		if (pubKey_ != null) {
			if (retVal == null) {
				retVal = pubKey_.getEncoded();
			} else {
				retVal.append(pubKey_.getEncoded());
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

		if (algorithmParms_ != null) {
			retVal.append("algorithmParms: ");
			retVal.append(Utils.getNL());
			retVal.append(algorithmParms_.toString());
			retVal.append(Utils.getNL());
		}
		if (pubKey_ != null) {
			retVal.append("pubKey: ");
			retVal.append(Utils.getNL());
			retVal.append(pubKey_.toString());
			retVal.append(Utils.getNL());
		}

		return retVal.toString();
	}


	/*************************************************************************************************
	 * Returns contents of the algorithmParms field.
	 */
	public TcTpmKeyParms getAlgorithmParms()
	{
		return algorithmParms_;
	}


	/*************************************************************************************************
	 * Sets the algorithmParms field.
	 */
	public void setAlgorithmParms(TcTpmKeyParms algorithmParms)
	{
		algorithmParms_ = algorithmParms;
	}


	/*************************************************************************************************
	 * Returns contents of the pubKey field.
	 */
	public TcTpmStorePubkey getPubKey()
	{
		return pubKey_;
	}


	/*************************************************************************************************
	 * Sets the pubKey field.
	 */
	public void setPubKey(TcTpmStorePubkey pubKey)
	{
		pubKey_ = pubKey;
	}
}
