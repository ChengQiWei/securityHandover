/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.api.structs.tpm;

import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder;

/**
 * This class describes the parameters of an RSA key.
 * 
 * @TPM_V1 50
 */
public class TcTpmRsaKeyParms extends TcCompositeTypeDecoder {

	
	/**
	 * This field specifies the size of the RSA key in bits. 
	 */
	protected long keyLength_;
	
	
	/**
	 * This field specifies the number of prime factors used by this RSA key.
	 */
	protected long numPrimes_;
	
	
	/**
	 * The public exponent of the key.
	 */
	protected TcBlobData exponent_;
	
	
	/*************************************************************************************************
	 * Constructor - see superclass for details
	 */
	public TcTpmRsaKeyParms()
	{
		super();
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 */
	public TcTpmRsaKeyParms(TcBlobData data)
	{
		super(data);
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 */
	public TcTpmRsaKeyParms(TcBlobData data, int offset)
	{
		super(data, offset);
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 */
	public TcTpmRsaKeyParms(TcCompositeTypeDecoder composite)
	{
		super(composite);
	}


	/*************************************************************************************************
	 * This method decodes the TPM_RSA_KEY_PARMS from the byte blob.
	 */
	protected void decode()
	{
		checkBoundaryPreconditions(12);

		keyLength_ = decodeUINT32();
		numPrimes_ = decodeUINT32();
		long exponentSize = decodeUINT32();
		if (exponentSize > 0) {
			exponent_ = decodeBytes(exponentSize);
		}
	}

	
	/*************************************************************************************************
	 * This method encodes the TPM_RSA_KEY_PARMS as a byte blob.
	 */
	public TcBlobData getEncoded()
	{
		TcBlobData retVal = TcBlobData.newUINT32(keyLength_);
		retVal.append(TcBlobData.newUINT32(numPrimes_));
		retVal.append(TcBlobData.newUINT32(getExponentSize()));
		if (exponent_ != null) {
			retVal.append(exponent_);
		}
		return retVal;
	}


	/************************************************************************************************
	 * Returns contents of the exponent field.
	 */
	public TcBlobData getExponent()
	{
		return exponent_;
	}


	/************************************************************************************************
	 * Sets the exponent field.
	 * If the key is using the default exponent (2^16 + 1 = 65537) then the exponent MUST be set to
	 * null (resulting in an exponentSize of 0).
	
	 */
	public void setExponent(TcBlobData exponent)
	{
		exponent_ = exponent;
	}


	/************************************************************************************************
	 * Returns contents of the exponentSize field.
	 */
	public long getExponentSize()
	{
		if (exponent_ == null) {
			return 0;
		} else {
			return exponent_.getLengthAsLong();
		}
	}


	/************************************************************************************************
	 * Returns contents of the keyLength field.
	 */
	public long getKeyLength()
	{
		return keyLength_;
	}


	/************************************************************************************************
	 * Sets the keyLength field.
	 */
	public void setKeyLength(long keyLength)
	{
		keyLength_ = keyLength;
	}


	/************************************************************************************************
	 * Returns contents of the numPrimes field.
	 */
	public long getNumPrimes()
	{
		return numPrimes_;
	}


	/************************************************************************************************
	 * Sets the numPrimes field.
	 */
	public void setNumPrimes(long numPrimes)
	{
		numPrimes_ = numPrimes;
	}

}
