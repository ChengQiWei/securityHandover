/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.api.structs.tpm;

import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder;
import iaik.tc.utils.misc.Utils;

public class TcTpmStoredData extends TcCompositeTypeDecoder implements TcITpmStoredData {

	
	/**
	 * Version number.
	 */
	protected TcTpmStructVer ver_; 
	

	/**
	 * This SHALL be a structure of type TPM_PCR_INFO or a 0 length array if the data is not bound to PCRs.
	 */
	protected TcBlobData sealInfo_;  // BYTE*
	
	
	/**
	 * This shall be an encrypted TPM_SEALED_DATA structure containing the confidential part of the data.
	 */
	protected TcBlobData encData_;  // BYTE*
	
	
	
	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder()
	 */
	public TcTpmStoredData()
	{
		super();
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcBlobData)
	 */
	public TcTpmStoredData(TcBlobData data)
	{
		super(data);
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcBlobData,
	 *      int)
	 */
	public TcTpmStoredData(TcBlobData data, int offset)
	{
		super(data, offset);
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder)
	 */
	public TcTpmStoredData(TcCompositeTypeDecoder composite)
	{
		super(composite);
	}


	/*************************************************************************************************
	 * This method decodes the TPM_STORED_DATA from the byte blob.
	 */
	protected void decode()
	{
		checkBoundaryPreconditions(12); // minimum size: 4 + 4 + 4 (ver, uint32, uint32) 

		ver_ = new TcTpmStructVer(this);
		long sealInfoSize = decodeUINT32();
		if (sealInfoSize > 0) {
			sealInfo_	= decodeBytes(sealInfoSize);
		} else {
			sealInfo_ = null;
		}
		long encDataSize = decodeUINT32();
		if (encDataSize > 0) {
			encData_	= decodeBytes(encDataSize);
		} else {
			encData_ = null;
		}
	}


	/*************************************************************************************************
	 * This method encodes the TPM_STORED_DATA as a byte blob.
	 */
	public TcBlobData getEncoded()
	{
		TcBlobData retVal = ver_.getEncoded();
		retVal.append(TcBlobData.newUINT32( getSealInfoSize()));
		if (sealInfo_ != null) {
			retVal.append(sealInfo_);	
		}
		retVal.append(TcBlobData.newUINT32( getEncDataSize()));
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

		retVal.append(ver_.toString());
		retVal.append(Utils.getNL());
		retVal.append("sealInfoSize: ");
		retVal.append(getSealInfoSize());
		retVal.append(Utils.getNL());
		if (sealInfo_ != null) {
			retVal.append("sealInfo: ");
			retVal.append(sealInfo_.toHexString());
			retVal.append(Utils.getNL());
		}
		retVal.append("encDataSize: ");
		retVal.append(getEncDataSize());
		retVal.append(Utils.getNL());
		if (encData_ != null) {
			retVal.append("encData: ");
			retVal.append(encData_.toHexString());
			retVal.append(Utils.getNL());
		}

		return retVal.toString();
	}


	/************************************************************************************************
	 * Returns contents of the encData field.
	 */
	public TcBlobData getEncData()
	{
		return encData_;
	}


	/************************************************************************************************
	 * Sets the encData field.
	 */
	public void setEncData(TcBlobData encData)
	{
		encData_ = encData;
	}


	/************************************************************************************************
	 * Returns contents of the encDataSize field.
	 */
	public long getEncDataSize()
	{
		if (encData_ == null) {
			return 0;
		} else {
			return encData_.getLengthAsLong();
		}
	}


	/************************************************************************************************
	 * Returns contents of the sealInfo field.
	 */
	public TcBlobData getSealInfo()
	{
		return sealInfo_;
	}


	/************************************************************************************************
	 * Sets the sealInfo field.
	 */
	public void setSealInfo(TcBlobData sealInfo)
	{
		sealInfo_ = sealInfo;
	}


	/************************************************************************************************
	 * Returns contents of the sealInfoSize field.
	 */
	public long getSealInfoSize()
	{
		if (sealInfo_ == null) {
			return 0;
		} else {
			return sealInfo_.getLengthAsLong();
		}
	}


	/************************************************************************************************
	 * Returns contents of the ver field.
	 */
	public TcTpmVersion getVer()
	{
		return ver_;
	}


	/************************************************************************************************
	 * Sets the ver field.
	 */
	public void setVer(TcTpmStructVer ver)
	{
		ver_ = ver;
	}

	
	
}
