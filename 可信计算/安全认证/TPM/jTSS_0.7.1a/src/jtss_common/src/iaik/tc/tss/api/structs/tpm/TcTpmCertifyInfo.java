/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.api.structs.tpm;


import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder;
import iaik.tc.utils.misc.Utils;

/**
 * When the TPM certifies a key, it must provide a signature with a TPM identity key on information
 * that describes that key. This structure provides the mechanism to do so.
 * 
 * @TPM_V1 75
 */
public class TcTpmCertifyInfo extends TcCompositeTypeDecoder {

	/**
	 * structure version
	 */
	protected TcTpmStructVer version_;

	/**
	 * This SHALL be the same value that would be set in a TPM_KEY representation of the key to be
	 * certified.
	 */
	protected int keyUsage_; // TPM_KEY_USAGE (UINT16)

	/**
	 * This SHALL be set to the same value as the corresponding parameter in the TPM_KEY structure
	 * that describes the public key that is being certified.
	 */
	protected long keyFlags_; // TPM_KEY_FLAGS (UINT32)

	/**
	 * This SHALL be the same value that would be set in a TPM_KEY representation of the key to be
	 * certified.
	 */
	protected short authDataUsage_; // TPM_AUTH_DATA_USAGE (BYTE)

	/**
	 * This SHALL be the same value that would be set in a TPM_KEY representation of the key to be
	 * certified.
	 */
	protected TcTpmKeyParms algorithmParms_;

	/**
	 * This SHALL be a digest of the value TPM_KEY -> pubKey -> key in a TPM_KEY representation of
	 * the key to be certified.
	 */
	protected TcTpmDigest pubKeyDigest_;

	/**
	 * This SHALL be externally provided data.
	 */
	protected TcTpmNonce data_;

	/**
	 * This SHALL indicate if any parent key was wrapped to a PCR.
	 */
	protected boolean parentPcrStatus_;

	/**
	 * This SHALL be the TPM_PCR_INFO structure.
	 */
	protected TcBlobData pcrInfo_;


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder()
	 */
	public TcTpmCertifyInfo()
	{
		super();
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcBlobData)
	 */
	public TcTpmCertifyInfo(TcBlobData data)
	{
		super(data);
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcBlobData,
	 *      int)
	 */
	public TcTpmCertifyInfo(TcBlobData data, int offset)
	{
		super(data, offset);
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder)
	 */
	public TcTpmCertifyInfo(TcCompositeTypeDecoder composite)
	{
		super(composite);
	}


	/*************************************************************************************************
	 * This method decodes the TPM_CERTIFY_INFO from the byte blob.
	 */
	protected void decode()
	{
		checkBoundaryPreconditions(28);

		version_ = new TcTpmStructVer(this);
		keyUsage_ = decodeTpmKeyUsage();
		keyFlags_ = decodeTpmKeyFlags();
		authDataUsage_ = decodeTpmAuthDataUsage();
		algorithmParms_ = new TcTpmKeyParms(this);
		pubKeyDigest_ = new TcTpmDigest(this);
		data_ = new TcTpmNonce(this);
		parentPcrStatus_ = decodeBoolean();
		long pcrInfoSize = decodeUINT32();
		pcrInfo_ = decodeBytes(pcrInfoSize);
	}


	/*************************************************************************************************
	 * This method encodes the TPM_CERTIFY_INFO as a byte blob.
	 */
	public TcBlobData getEncoded()
	{
		TcBlobData retVal = null;
		if (version_ != null) {
			retVal = version_.getEncoded();
			retVal.append(TcBlobData.newUINT16( keyUsage_));
		} else {
			retVal = TcBlobData.newUINT16( keyUsage_);
		}

		retVal.append(TcBlobData.newUINT32( keyFlags_));
		retVal.append(TcBlobData.newBYTE( authDataUsage_));
		retVal.append(algorithmParms_.getEncoded());
		retVal.append(pubKeyDigest_.getEncoded());
		retVal.append(data_.getEncoded());
		retVal.append(TcBlobData.newBYTE(Utils.booleanToByte(parentPcrStatus_)));
		retVal.append(TcBlobData.newUINT32( getPcrInfoSize()));
		if (pcrInfo_ != null) {
			retVal.append(pcrInfo_);
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
			retVal.append(version_.toString());
			retVal.append(Utils.getNL());
		}
		retVal.append("keyUsage: ");
		retVal.append(keyUsage_);
		retVal.append(Utils.getNL());
		retVal.append("keyFlags: ");
		retVal.append(keyFlags_);
		retVal.append(Utils.getNL());
		retVal.append("authDataUsage: ");
		retVal.append(authDataUsage_);
		retVal.append(Utils.getNL());
		if (algorithmParms_ != null) {
			retVal.append("algorithmParms: ");
			retVal.append(algorithmParms_.toString());
			retVal.append(Utils.getNL());
		}
		if (pubKeyDigest_ != null) {
			retVal.append("pubKeyDigest: ");
			retVal.append(pubKeyDigest_.toString());
			retVal.append(Utils.getNL());
		}

		if (data_ != null) {
			retVal.append("data: ");
			retVal.append(data_.toString());
			retVal.append(Utils.getNL());
		}
		retVal.append("parentPcrStatus: ");
		retVal.append(Utils.booleanToString(parentPcrStatus_));
		retVal.append(Utils.getNL());
		retVal.append("pcrInfoSize: ");
		retVal.append(getPcrInfoSize());
		retVal.append(Utils.getNL());
		if (pcrInfo_ != null) {
			retVal.append("pcrInfo: ");
			retVal.append(pcrInfo_.toString());
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
	 * Returns contents of the authDataUsage field.
	 */
	public short getAuthDataUsage()
	{
		return authDataUsage_;
	}


	/*************************************************************************************************
	 * Sets the authDataUsage field.
	 */
	public void setAuthDataUsage(short authDataUsage)
	{
		authDataUsage_ = authDataUsage;
	}


	/*************************************************************************************************
	 * Returns contents of the data field.
	 */
	public TcTpmNonce getData()
	{
		return data_;
	}


	/*************************************************************************************************
	 * Sets the data field.
	 */
	public void setData(TcTpmNonce data)
	{
		data_ = data;
	}


	/*************************************************************************************************
	 * Returns contents of the keyFlags field.
	 */
	public long getKeyFlags()
	{
		return keyFlags_;
	}


	/*************************************************************************************************
	 * Sets the keyFlags field.
	 */
	public void setKeyFlags(long keyFlags)
	{
		keyFlags_ = keyFlags;
	}


	/*************************************************************************************************
	 * Returns contents of the keyUsage field.
	 */
	public int getKeyUsage()
	{
		return keyUsage_;
	}


	/*************************************************************************************************
	 * Sets the keyUsage field.
	 */
	public void setKeyUsage(int keyUsage)
	{
		keyUsage_ = keyUsage;
	}


	/*************************************************************************************************
	 * Returns contents of the parentPcrStatus field.
	 */
	public boolean isParentPcrStatus()
	{
		return parentPcrStatus_;
	}


	/*************************************************************************************************
	 * Sets the parentPcrStatus field.
	 */
	public void setParentPcrStatus(boolean parentPcrStatus)
	{
		parentPcrStatus_ = parentPcrStatus;
	}


	/*************************************************************************************************
	 * Returns contents of the pcrInfo field.
	 */
	public TcBlobData getPcrInfo()
	{
		return pcrInfo_;
	}


	/*************************************************************************************************
	 * Sets the pcrInfo field.
	 */
	public void setPcrInfo(TcBlobData pcrInfo)
	{
		pcrInfo_ = pcrInfo;
	}


	/*************************************************************************************************
	 * Returns contents of the pcrInfoSize field.
	 */
	public long getPcrInfoSize()
	{
		if (pcrInfo_ == null) {
			return 0;
		} else {
			return pcrInfo_.getLengthAsLong();
		}
	}


	/*************************************************************************************************
	 * Returns contents of the pubKeyDigest field.
	 */
	public TcTpmDigest getPubKeyDigest()
	{
		return pubKeyDigest_;
	}


	/*************************************************************************************************
	 * Sets the pubKeyDigest field.
	 */
	public void setPubKeyDigest(TcTpmDigest pubKeyDigest)
	{
		pubKeyDigest_ = pubKeyDigest;
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
