/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.api.structs.tpm;


import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder;
import iaik.tc.utils.misc.Utils;

/**
 * This structure contains fields that a privacy-CA requires in order to decide whether to attest to
 * the given TPM identity.
 * 
 * @TPM_V1 79
 */
public class TcTpmIdentityProof extends TcCompositeTypeDecoder {

	/**
	 * Structure version.
	 */
	protected TcTpmStructVer version_;

	/**
	 * The public key of the new identity.
	 */
	protected TcTpmPubkey identityKey_;

	/**
	 * The text label for the new identity.
	 */
	protected TcBlobData labelArea_;

	/**
	 * The signature value of TPM_IDENTITY_CONTENTS structure from the TPM_MakeIdentity command.
	 */
	protected TcBlobData identityBinding_;

	/**
	 * The TPM endorsement credential
	 */
	protected TcBlobData endorsementCredential_;

	/**
	 * The TPM platform credential
	 */
	protected TcBlobData platformCredential_;

	/**
	 * The TPM conformance credential
	 */
	protected TcBlobData conformanceCredential_;


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 */
	public TcTpmIdentityProof()
	{
		super();
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 */
	public TcTpmIdentityProof(TcBlobData blob)
	{
		super(blob);
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 */
	public TcTpmIdentityProof(TcBlobData blob, int offset)
	{
		super(blob, offset);
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 */
	public TcTpmIdentityProof(TcCompositeTypeDecoder composite)
	{
		super(composite);
	}


	/*************************************************************************************************
	 * This method decodes the TPM_IDENTITY_PROOF from the byte blob.
	 */
	protected void decode()
	{
		checkBoundaryPreconditions(24); // minimum size

		version_ = new TcTpmStructVer(this);
		long labelSize = decodeUINT32();
		long identityBindingSize = decodeUINT32();
		long endorsementSize = decodeUINT32();
		long platformSize = decodeUINT32();
		long conformanceSize = decodeUINT32();
		identityKey_ = new TcTpmPubkey(this);
		labelArea_ = decodeBytes(labelSize);
		identityBinding_ = decodeBytes(identityBindingSize);
		endorsementCredential_ = decodeBytes(endorsementSize);
		platformCredential_ = decodeBytes(platformSize);
		conformanceCredential_ = decodeBytes(conformanceSize);
	}


	/*************************************************************************************************
	 * This method encodes the TPM_IDENTITY_PROOF as a byte blob.
	 */
	public TcBlobData getEncoded()
	{
		TcBlobData retVal = TcBlobData.newUINT32( getLabelSize());
		if (version_ != null) {
			retVal.prepend(version_.getEncoded());
		}
		retVal.append(TcBlobData.newUINT32( getIdentityBindingSize()));
		retVal.append(TcBlobData.newUINT32( getEndorsementSize()));
		retVal.append(TcBlobData.newUINT32( getPlatformSize()));
		retVal.append(TcBlobData.newUINT32( getConformanceSize()));
		if (identityKey_ != null) {
			retVal.append(identityKey_.getEncoded());
		}
		if (labelArea_ != null) {
			retVal.append(labelArea_);
		}
		if (identityBinding_ != null) {
			retVal.append(identityBinding_);
		}
		if (endorsementCredential_ != null) {
			retVal.append(endorsementCredential_);
		}
		if (platformCredential_ != null) {
			retVal.append(platformCredential_);
		}
		if (conformanceCredential_ != null) {
			retVal.append(conformanceCredential_);
		}

		return retVal;
	}


	/*************************************************************************************************
	 * This method returns a String representation of the object.
	 */
	public String toString()
	{
		StringBuffer retVal = new StringBuffer();
		if (version_ != null) {
			retVal.append("version: ");
			retVal.append(Utils.getNL());
			retVal.append(version_.toString());
			retVal.append(Utils.getNL());
		}
		retVal.append("labelSize: ");
		retVal.append(getLabelSize());
		retVal.append(Utils.getNL());
		retVal.append("identityBindingSize: ");
		retVal.append(getIdentityBindingSize());
		retVal.append(Utils.getNL());
		retVal.append("endorsementSize: ");
		retVal.append(getEndorsementSize());
		retVal.append(Utils.getNL());
		retVal.append("platformSize: ");
		retVal.append(getPlatformSize());
		retVal.append(Utils.getNL());
		retVal.append("conformanceSize: ");
		retVal.append(getConformanceSize());
		retVal.append(Utils.getNL());
		if (identityKey_ != null) {
			retVal.append("identityKey:");
			retVal.append(Utils.getNL());
			retVal.append(identityKey_.toString());
			retVal.append(Utils.getNL());
		}
		if (labelArea_ != null) {
			retVal.append("labelArea:");
			retVal.append(Utils.getNL());
			retVal.append(labelArea_.toString());
			retVal.append(Utils.getNL());
		}
		if (identityBinding_ != null) {
			retVal.append("identityBinding: ");
			retVal.append(identityBinding_.toHexString());
			retVal.append(Utils.getNL());
		}
		if (endorsementCredential_ != null) {
			retVal.append("endorsementCredential: ");
			retVal.append(endorsementCredential_.toHexString());
			retVal.append(Utils.getNL());
		}
		if (platformCredential_ != null) {
			retVal.append("platformCredential: ");
			retVal.append(platformCredential_.toHexString());
			retVal.append(Utils.getNL());
		}
		if (conformanceCredential_ != null) {
			retVal.append("conformanceCredential: ");
			retVal.append(conformanceCredential_.toHexString());
			retVal.append(Utils.getNL());
		}

		return retVal.toString();
	}


	/*************************************************************************************************
	 * Returns contents of the conformanceCredential field.
	 */
	public TcBlobData getConformanceCredential()
	{
		return conformanceCredential_;
	}


	/*************************************************************************************************
	 * Sets the conformanceCredential field.
	 */
	public void setConformanceCredential(TcBlobData conformanceCredential)
	{
		conformanceCredential_ = conformanceCredential;
	}


	/*************************************************************************************************
	 * Returns contents of the conformanceSize field.
	 */
	public long getConformanceSize()
	{
		if (conformanceCredential_ == null) {
			return 0;
		} else {
			return conformanceCredential_.getLengthAsLong();
		}
	}


	/*************************************************************************************************
	 * Returns contents of the endorsementCredential field.
	 */
	public TcBlobData getEndorsementCredential()
	{
		return endorsementCredential_;
	}


	/*************************************************************************************************
	 * Sets the endorsementCredential field.
	 */
	public void setEndorsementCredential(TcBlobData endorsementCredential)
	{
		endorsementCredential_ = endorsementCredential;
	}


	/*************************************************************************************************
	 * Returns contents of the endorsementSize field.
	 */
	public long getEndorsementSize()
	{
		if (endorsementCredential_ == null) {
			return 0; 
		} else {
			return endorsementCredential_.getLengthAsLong();
		}
	}


	/*************************************************************************************************
	 * Returns contents of the identityBinding field.
	 */
	public TcBlobData getIdentityBinding()
	{
		return identityBinding_;
	}


	/*************************************************************************************************
	 * Sets the identityBinding field.
	 */
	public void setIdentityBinding(TcBlobData identityBinding)
	{
		identityBinding_ = identityBinding;
	}


	/*************************************************************************************************
	 * Returns contents of the identityBindingSize field.
	 */
	public long getIdentityBindingSize()
	{
		if (identityBinding_ == null) {
			return 0;
		} else {
			return identityBinding_.getLengthAsLong();
		}
	}


	/*************************************************************************************************
	 * Returns contents of the identityKey field.
	 */
	public TcTpmPubkey getIdentityKey()
	{
		return identityKey_;
	}


	/*************************************************************************************************
	 * Sets the identityKey field.
	 */
	public void setIdentityKey(TcTpmPubkey identityKey)
	{
		identityKey_ = identityKey;
	}


	/*************************************************************************************************
	 * Returns contents of the labelArea field.
	 */
	public TcBlobData getLabelArea()
	{
		return labelArea_;
	}


	/*************************************************************************************************
	 * Sets the labelArea field.
	 */
	public void setLabelArea(TcBlobData labelArea)
	{
		labelArea_ = labelArea;
	}


	/*************************************************************************************************
	 * Returns contents of the labelSize field.
	 */
	public long getLabelSize()
	{
		if (labelArea_ == null) {
			return 0;
		} else {
			return labelArea_.getLengthAsLong();
		}
	}


	/*************************************************************************************************
	 * Returns contents of the platformCredential field.
	 */
	public TcBlobData getPlatformCredential()
	{
		return platformCredential_;
	}


	/*************************************************************************************************
	 * Sets the platformCredential field.
	 */
	public void setPlatformCredential(TcBlobData platformCredential)
	{
		platformCredential_ = platformCredential;
	}


	/*************************************************************************************************
	 * Returns contents of the platformSize field.
	 */
	public long getPlatformSize()
	{
		if (platformCredential_ == null) {
			return 0;
		} else {
			return platformCredential_.getLengthAsLong();
		}
	}


	/*************************************************************************************************
	 * Returns contents of the version field.
	 */
	public TcTpmVersion getVersion()
	{
		return version_;
	}


	/*************************************************************************************************
	 * Sets the version field.
	 */
	public void setVersion(TcTpmStructVer version)
	{
		version_ = version;
	}
}
