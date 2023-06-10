/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.api.structs.tpm;


import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder;
import iaik.tc.utils.misc.Utils;

/**
 * This class provides the mechanism for the TPM to quote the current values of a list of PCRs. The
 * data returned by the TPM as a result of a quote operation is formated as such a struct.
 * 
 * @TPM_V1 76
 */
public class TcTpmQuoteInfo extends TcCompositeTypeDecoder {

	/**
	 * The TPM version structure.
	 */
	protected TcTpmStructVer version_;

	/**
	 * This field SHALL always be the string 'QUOT'.
	 */
	protected String fixed_;

	/**
	 * This field holds the result of the composite hash algorithm using the current values of the
	 * requested PCR indices.
	 */
	protected TcTpmCompositeHash digestValue_;

	/**
	 * 160 bits of externally supplied data.
	 */
	protected TcTpmNonce externalData_;


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder()
	 */
	public TcTpmQuoteInfo()
	{
		super();
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcBlobData)
	 */
	public TcTpmQuoteInfo(TcBlobData data)
	{
		super(data);
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcBlobData,
	 *      int)
	 */
	public TcTpmQuoteInfo(TcBlobData data, int offset)
	{
		super(data, offset);
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder)
	 */
	public TcTpmQuoteInfo(TcCompositeTypeDecoder composite)
	{
		super(composite);
	}


	/*************************************************************************************************
	 * This method decodes the TPM_QUOTE_INFO from the byte blob.
	 */
	protected void decode()
	{
		checkBoundaryPreconditions(48);

		version_ = new TcTpmStructVer(this);
		fixed_ = decodeBytes(4).toStringASCII();
		digestValue_ = new TcTpmCompositeHash(this);
		externalData_ = new TcTpmNonce(this);
	}


	/*************************************************************************************************
	 * This method encodes the TPM_QUOTE_INFO as a byte blob.
	 */
	public TcBlobData getEncoded()
	{
		TcBlobData retVal = null;
		if (version_ != null) {
			retVal = TcBlobData.newBlobData(version_.getEncoded());
		}
		if (fixed_ != null) {
			if (retVal == null) {
				retVal = TcBlobData.newStringASCII(fixed_);
			} else {
				retVal.append(TcBlobData.newStringASCII(fixed_));
			}
		}
		if (digestValue_ != null) {
			if (retVal == null) {
				retVal = digestValue_.getEncoded();
			} else {
				retVal.append(digestValue_.getEncoded());
			}
		}
		if (externalData_ != null) {
			if (retVal == null) {
				retVal = externalData_.getEncoded();
			} else {
				retVal.append(externalData_.getEncoded());
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

		if (version_ != null) {
			retVal.append("version: ");
			retVal.append(version_.toString());
			retVal.append(Utils.getNL());
		}
		if (fixed_ != null) {
			retVal.append("fixed: ");
			retVal.append(fixed_.toString());
			retVal.append(Utils.getNL());
		}
		if (digestValue_ != null) {
			retVal.append("digestValue/");
			retVal.append(digestValue_.toString());
		}
		if (externalData_ != null) {
			retVal.append("externalData/");
			retVal.append(externalData_.toString());
		}

		return retVal.toString();
	}


	/*************************************************************************************************
	 * Returns contents of the digestValue field (i.e. the hashed PCR values).
	 */
	public TcTpmCompositeHash getDigestValue()
	{
		return digestValue_;
	}


	/*************************************************************************************************
	 * Sets the digestValue field.
	 */
	public void setDigestValue(TcTpmCompositeHash digestValue)
	{
		digestValue_ = digestValue;
	}


	/*************************************************************************************************
	 * Returns contents of the externalData field.
	 */
	public TcTpmNonce getExternalData()
	{
		return externalData_;
	}


	/*************************************************************************************************
	 * Sets the externalData field.
	 */
	public void setExternalData(TcTpmNonce externalData)
	{
		externalData_ = externalData;
	}


	/*************************************************************************************************
	 * Returns contents of the fixed field.
	 */
	public String getFixed()
	{
		return fixed_;
	}


	/*************************************************************************************************
	 * Sets the fixed field.
	 */
	public void setFixed(String fixed)
	{
		fixed_ = fixed;
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
