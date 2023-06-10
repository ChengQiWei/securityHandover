/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.api.structs.tsp;


import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.utils.misc.Utils;

/***************************************************************************************************
 * The TcTssValidation structure provides the ability to verify signatures and validation digests
 * built over certain TPM command parameters. These parameters (i.e. structures) are defined in
 * TPM 1.2 specification. The caller must provide some random data (externalData_) as input, which 
 * is included in the signature/digest calculation.<br>
 * 
 * The following TSP functions use this structure:
 * <ul>
 * 	<li> TPM_CertifySelfTest
 * 	<li> TPM_GetCapabiltiySigned
 *  <li> TPM_LoadMaintenancePubKey
 *  <li> TPM_CheckMaintenancePubKey
 *  <li> TPM_CertifyKey
 *  <li> TPM_CreateEndoresementKey
 *  <li> TPM_GetPubEndorsementKey
 *  <li> TPM_CreateRevocableEndorsementKey
 *  <li> TPM_Quote
 *  <li> TPM_Quote2
 *  <li> Context_CloseSignTransport
 * </ul> 
 *
 * If the validation of the signature/digest should be done by the TSP itself, a null pointer must
 * be passed to these methods. In this case the TSP generates its own random data to be included
 * in the signature/digest (externalData_).
 *
 * @TSS_V1 50
 *
 * @TSS_1_2_EA 110
 */
public class TcTssValidation {

	/**
	 * Version data.
	 */
	protected TcTssVersion versionInfo_;
	
	
	/**
	 * Random data supplied to the TPM used to avoid replay attacks.
	 */
	protected TcBlobData externalData_ = null;
	

	/**
	 * Data which was used to calculate the validation.
	 */
	protected TcBlobData data_ = null; // BYTE*

	/**
	 * The validation data.
	 */
	protected TcBlobData validationData_ = null; // BYTE*


	/*************************************************************************************************
	 * Default constructor.
	 */
	public TcTssValidation()
	{
	}

	
	/*************************************************************************************************
	 * Initialization method taking and setting all parameters at once.
	 */
	public TcTssValidation init(final TcBlobData externalData, final TcBlobData data,
			final TcBlobData validationData)
	{
		externalData_ = externalData;
		data_ = data;
		validationData_ = validationData;
		
		return this;
	}


	/*************************************************************************************************
	 * Returns contents of the version info field.
	 */
	public TcTssVersion getVersionInfo()
	{
		return versionInfo_;
	}


	/*************************************************************************************************
	 * Sets the version info field.
	 */
	public void setVersionInfo(final TcTssVersion versionInfo)
	{
		versionInfo_ = versionInfo;
	}

	
	/*************************************************************************************************
	 * Returns contents of the data field (i.e. the raw data that was used to compute the validation).
	 */
	public TcBlobData getData()
	{
		return data_;
	}


	/*************************************************************************************************
	 * Sets the data field (i.e. the raw data that was used to compute the validation).
	 */
	public void setData(final TcBlobData data)
	{
		data_ = data;
	}


	/*************************************************************************************************
	 * Returns the data length.
	 */
	public long getDataLength()
	{
		if (data_ == null) {
			return 0;
		} else {
			return data_.getLengthAsLong();
		}
	}

	
	/*************************************************************************************************
	 * Returns the data length.
	 */
	public long getExternalDataLength()
	{
		if (externalData_ == null) {
			return 0;
		} else {
			return externalData_.getLengthAsLong();
		}
	}


	/*************************************************************************************************
	 * Returns contents of the externalData field.
	 */
	public TcBlobData getExternalData()
	{
		return externalData_;
	}


	/*************************************************************************************************
	 * Sets the externalData field.
	 */
	public void setExternalData(final TcBlobData externalData)
	{
		externalData_ = externalData;
	}


	/*************************************************************************************************
	 * Returns contents of the validationData field.
	 */
	public TcBlobData getValidationData()
	{
		return validationData_;
	}


	/*************************************************************************************************
	 * Sets the validationData field.
	 */
	public void setValidationData(final TcBlobData validationData)
	{
		validationData_ = validationData;
	}


	/*************************************************************************************************
	 * Returns the validationData length.
	 */
	public long getValidationDataLength()
	{
		if (validationData_ == null) {
			return 0;
		} else {
			return validationData_.getLengthAsLong();
		}
	}


	/*************************************************************************************************
	 * This method returns a String representation of the object.
	 */
	public String toString()
	{
		StringBuffer retVal = new StringBuffer();

		if (getVersionInfo() != null) {
			retVal.append(getVersionInfo().toString());
			retVal.append(Utils.getNL());
		}
		
		if (getExternalData() != null) {
			retVal.append("external data (nonce): ");
			retVal.append(getExternalData().toHexString());
		} else {
			retVal.append("external data (nonce): not set");
		}
		retVal.append(Utils.getNL());

		retVal.append("data length: ");
		retVal.append(getDataLength());
		retVal.append(Utils.getNL());
		if (getDataLength() > 0 && getData() != null) {
			retVal.append("data (hex string): ");
			retVal.append(getData().toHexString());
			retVal.append(Utils.getNL());
		}

		retVal.append("validation data length: ");
		retVal.append(getValidationDataLength());
		retVal.append(Utils.getNL());
		if (getValidationDataLength() > 0 && getValidationData() != null) {
			retVal.append("validation data: ");
			retVal.append(getValidationData().toHexString());
		}

		return retVal.toString();
	}
}
