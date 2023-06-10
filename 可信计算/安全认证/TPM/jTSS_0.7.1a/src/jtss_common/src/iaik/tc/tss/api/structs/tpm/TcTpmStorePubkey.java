/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.api.structs.tpm;


import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder;
import iaik.tc.utils.misc.Utils;

/**
 * This structure can be used in conjunction with a corresponding TPM_KEY_PARMS to construct a
 * public key which can be unambiguously used.
 * 
 * @TPM_V1 69
 */
public class TcTpmStorePubkey extends TcCompositeTypeDecoder {

	/**
	 * length of the key field.
	 */
	long keyLength_;

	/**
	 * Structure interpreted according to the algorithm Id in the corresponding TPM_KEY_PARMS
	 * structure.
	 */
	TcBlobData key_;


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 */
	public TcTpmStorePubkey()
	{
		super();
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 */
	public TcTpmStorePubkey(TcBlobData blob)
	{
		super(blob);
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 */
	public TcTpmStorePubkey(TcBlobData blob, int offset)
	{
		super(blob, offset);
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 */
	public TcTpmStorePubkey(TcCompositeTypeDecoder composite)
	{
		super(composite);
	}


	/*************************************************************************************************
	 * This method decodes the TPM_STORE_PUBKEY from the byte blob.
	 */
	protected void decode()
	{
		checkBoundaryPreconditions(4); // minimum size

		keyLength_ = decodeUINT32();
		key_ = decodeBytes(keyLength_);
	}


	/*************************************************************************************************
	 * This method encodes the TPM_STORE_PUBKEY as a byte blob.
	 */
	public TcBlobData getEncoded()
	{
		TcBlobData retVal = TcBlobData.newUINT32( keyLength_);
		if (keyLength_ > 0 && key_ != null) {
			retVal.append(key_);
		}
		return retVal;
	}


	/*************************************************************************************************
	 * This method returns a String representation of the object.
	 */
	public String toString()
	{
		StringBuffer retVal = new StringBuffer();

		retVal.append("keyLength: ");
		retVal.append(keyLength_);
		retVal.append(Utils.getNL());
		if (keyLength_ > 0 && key_ != null) {
			retVal.append("key: ");
			retVal.append(key_.toHexString());
			retVal.append(Utils.getNL());
		}

		return retVal.toString();
	}


	/*************************************************************************************************
	 * Returns contents of the key field.
	 */
	public TcBlobData getKey()
	{
		return key_;
	}


	/*************************************************************************************************
	 * Sets the key field.
	 */
	public void setKey(TcBlobData key)
	{
		key_ = key;
	}


	/*************************************************************************************************
	 * Returns contents of the keyLength field.
	 */
	public long getKeyLength()
	{
		return keyLength_;
	}


	/*************************************************************************************************
	 * Sets the keyLength field.
	 */
	public void setKeyLength(long keyLength)
	{
		keyLength_ = keyLength;
	}

}
