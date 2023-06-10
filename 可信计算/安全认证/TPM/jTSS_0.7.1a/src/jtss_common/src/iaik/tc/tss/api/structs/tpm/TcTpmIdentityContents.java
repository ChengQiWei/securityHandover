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
 * TPM_MakeIdentity uses this structure and the signature of this structure goes to a privacy CA
 * during the certification process.
 * 
 * @TPM_V1 77
 */
public class TcTpmIdentityContents extends TcCompositeTypeDecoder {

	/**
	 * The structure version.
	 */
	protected TcTpmStructVer ver_;

	/**
	 * The ordinal of the TPM_MakeIdentity command.
	 */
	protected long ordinal_;

	/**
	 * The result of hashing the chosen identityLabel and PrivacyCA for the new TPM identity.
	 */
	protected TcTpmDigest labelPrivCADigest_;

	/**
	 * The public key structure of the identity key.
	 */
	protected TcTpmPubkey identityPubKey_;


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 */
	public TcTpmIdentityContents()
	{
		super();
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 */
	public TcTpmIdentityContents(TcBlobData blob)
	{
		super(blob);
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 */
	public TcTpmIdentityContents(TcBlobData blob, int offset)
	{
		super(blob, offset);
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 */
	public TcTpmIdentityContents(TcCompositeTypeDecoder composite)
	{
		super(composite);
	}


	/*************************************************************************************************
	 * This method decodes the TPM_IDENTITY_CONTENTS from the byte blob.
	 */
	protected void decode()
	{
		checkBoundaryPreconditions(4 + (int) TcTpmConstants.TPM_SHA1_160_HASH_LEN);

		ver_ = new TcTpmStructVer(this);
		ordinal_ = decodeUINT32();
		labelPrivCADigest_ = new TcTpmDigest(this);
	}


	/*************************************************************************************************
	 * This method encodes the TPM_IDENTITY_CONTENTS as a byte blob.
	 */
	public TcBlobData getEncoded()
	{
		TcBlobData retVal = TcBlobData.newUINT32( ordinal_);
		if (ver_ != null) {
			retVal.prepend(ver_.getEncoded());
		}
		if (labelPrivCADigest_ != null) {
			retVal.append(labelPrivCADigest_.getEncoded());
		}
		if (identityPubKey_ != null) {
			retVal.append(identityPubKey_.getEncoded());
		}
		return retVal;
	}


	/*************************************************************************************************
	 * This method returns a String representation of the object.
	 */
	public String toString()
	{
		StringBuffer retVal = new StringBuffer();

		if (ver_ != null) {
			retVal.append("ver: ");
			retVal.append(Utils.getNL());
			retVal.append(ver_.toString());
			retVal.append(Utils.getNL());
		}
		retVal.append("ordinal: ");
		retVal.append(ordinal_);
		retVal.append(Utils.getNL());
		if (labelPrivCADigest_ != null) {
			retVal.append("labelPrivCADigest: ");
			retVal.append(Utils.getNL());
			retVal.append(labelPrivCADigest_.toString());
			retVal.append(Utils.getNL());
		}
		if (identityPubKey_ != null) {
			retVal.append("identityPubKey: ");
			retVal.append(Utils.getNL());
			retVal.append(identityPubKey_.toString());
			retVal.append(Utils.getNL());
		}

		return retVal.toString();
	}


	/*************************************************************************************************
	 * Returns contents of the identityPubKey field.
	 */
	public TcTpmPubkey getIdentityPubKey()
	{
		return identityPubKey_;
	}


	/*************************************************************************************************
	 * Sets the identityPubKey field.
	 */
	public void setIdentityPubKey(TcTpmPubkey identityPubKey)
	{
		identityPubKey_ = identityPubKey;
	}


	/*************************************************************************************************
	 * Returns contents of the labelPrivCADigest field.
	 */
	public TcTpmDigest getLabelPrivCADigest()
	{
		return labelPrivCADigest_;
	}


	/*************************************************************************************************
	 * Sets the labelPrivCADigest field.
	 */
	public void setLabelPrivCADigest(TcTpmDigest labelPrivCADigest)
	{
		labelPrivCADigest_ = labelPrivCADigest;
	}


	/*************************************************************************************************
	 * Returns contents of the ordinal field.
	 */
	public long getOrdinal()
	{
		return ordinal_;
	}


	/*************************************************************************************************
	 * Sets the ordinal field.
	 */
	public void setOrdinal(long ordinal)
	{
		ordinal_ = ordinal;
	}


	/*************************************************************************************************
	 * Returns contents of the ver field.
	 */
	public TcTpmVersion getVer()
	{
		return ver_;
	}


	/*************************************************************************************************
	 * Sets the ver field.
	 */
	public void setVer(TcTpmStructVer ver)
	{
		ver_ = ver;
	}

}
