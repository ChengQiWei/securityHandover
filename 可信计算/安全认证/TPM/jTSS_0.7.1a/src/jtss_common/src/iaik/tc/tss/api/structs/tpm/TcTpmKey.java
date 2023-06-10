/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.api.structs.tpm;


import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder;
import iaik.tc.utils.misc.Utils;

/**
 * The TPM_KEY structure provides a mechanism to transport the entire asymmetric key pair. The
 * private portion of the key is always encrypted.
 * 
 * @TPM_V1 68
 */
public class TcTpmKey extends TcCompositeTypeDecoder implements TcITpmKey {

	/**
	 * Version number.
	 */
	protected TcTpmStructVer ver_;

	/**
	 * Key usage flag that determines the operations permitted with this key.
	 */
	protected int keyUsage_;

	/**
	 * Flags related to migration, redirection etc.
	 */
	protected long keyFlags_;

	/**
	 * Indicates the conditions where it is required that authorization is presented.
	 */
	protected short authDataUsage_;

	/**
	 * Information regarding the algorithm for this key.
	 */
	protected TcTpmKeyParms algorithmParms_;

	/**
	 * The pcrInfo content.
	 */
	protected TcBlobData pcrInfo_;

	/**
	 * The public key.
	 */
	protected TcTpmStorePubkey pubKey_;

	/**
	 * The encrypted data.
	 */
	protected TcBlobData encData_;


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 */
	public TcTpmKey()
	{
		super();
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 */
	public TcTpmKey(TcBlobData blob)
	{
		super(blob);
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 */
	public TcTpmKey(TcBlobData blob, int offset)
	{
		super(blob, offset);
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 */
	public TcTpmKey(TcCompositeTypeDecoder composite)
	{
		super(composite);
	}


	/*************************************************************************************************
	 * This method decodes the TPM_KEY from the byte blob.
	 */
	protected void decode()
	{
		checkBoundaryPreconditions(35); // minimum size

		ver_ = new TcTpmStructVer(this);
		keyUsage_ = decodeTpmKeyUsage();
		keyFlags_ = decodeTpmKeyFlags();
		authDataUsage_ = decodeTpmAuthDataUsage();
		algorithmParms_ = new TcTpmKeyParms(this);
		long pcrInfoSize = decodeUINT32();
		pcrInfo_ = decodeBytes(pcrInfoSize);
		pubKey_ = new TcTpmStorePubkey(this);
		long encSize = decodeUINT32();
		encData_ = decodeBytes(encSize);
	}


	/*************************************************************************************************
	 * This method encodes the TPM_KEY_PARMS as a byte blob.
	 */
	public TcBlobData getEncoded()
	{
		TcBlobData retVal = null;
		if (ver_ != null) {
			retVal = TcBlobData.newBlobData(ver_.getEncoded());
			retVal.append(TcBlobData.newUINT16( keyUsage_));
		} else {
			retVal = TcBlobData.newUINT16( keyUsage_);
		}
		retVal.append(TcBlobData.newUINT32( keyFlags_));
		retVal.append(TcBlobData.newBYTE( authDataUsage_));
		if (algorithmParms_ != null) {
			retVal.append(algorithmParms_.getEncoded());
		}
		retVal.append(TcBlobData.newUINT32( getPcrInfoSize()));
		if (pcrInfo_ != null) {
			retVal.append(pcrInfo_);
		}
		if (pubKey_ != null) {
			retVal.append(pubKey_.getEncoded());
		}
		retVal.append(TcBlobData.newUINT32(getEncSize()));
		if (encData_ != null) {
			retVal.append(encData_);
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
			retVal.append(Utils.getNL());
			retVal.append(algorithmParms_.toString());
			retVal.append(Utils.getNL());
		}
		retVal.append("pcrInfoSize: ");
		retVal.append(getPcrInfoSize());
		retVal.append(Utils.getNL());
		if (pcrInfo_ != null) {
			retVal.append("pcrInfo: ");
			retVal.append(pcrInfo_.toHexString());
			retVal.append(Utils.getNL());
		}
		if (pubKey_ != null) {
			retVal.append("pubKey: ");
			retVal.append(Utils.getNL());
			retVal.append(pubKey_.toString());
			retVal.append(Utils.getNL());
		}
		retVal.append("encSize: ");
		retVal.append(getEncSize());
		retVal.append(Utils.getNL());
		if (encData_ != null) {
			retVal.append("encData: ");
			retVal.append(encData_.toHexString());
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
	 * Returns contents of the encData field.
	 */
	public TcBlobData getEncData()
	{
		return encData_;
	}


	/*************************************************************************************************
	 * Sets the encData field.
	 */
	public void setEncData(TcBlobData encData)
	{
		encData_ = encData;
	}


	/*************************************************************************************************
	 * Returns contents of the encSize field.
	 */
	public long getEncSize()
	{
		if (encData_ == null) {
			return 0;
		} else {
			return encData_.getLengthAsLong();
		}
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
