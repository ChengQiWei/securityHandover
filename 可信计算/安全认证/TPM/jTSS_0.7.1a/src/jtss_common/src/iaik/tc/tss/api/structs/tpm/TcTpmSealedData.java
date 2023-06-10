/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.api.structs.tpm;


import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder;
import iaik.tc.utils.misc.Utils;

public class TcTpmSealedData extends TcCompositeTypeDecoder {
	protected short payload_;

	protected TcTpmSecret authData_;

	protected TcTpmNonce tpmProof_;

	protected TcTpmDigest storedDigest_;

	protected TcBlobData data_;


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder()
	 */
	public TcTpmSealedData()
	{
		super();
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcBlobData)
	 */
	public TcTpmSealedData(TcBlobData data)
	{
		super(data);
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcBlobData,
	 *      int)
	 */
	public TcTpmSealedData(TcBlobData data, int offset)
	{
		super(data, offset);
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder)
	 */
	public TcTpmSealedData(TcCompositeTypeDecoder composite)
	{
		super(composite);
	}


	/*************************************************************************************************
	 * This method decodes the TPM_SEALED_DATA from the byte blob.
	 */
	protected void decode()
	{
		checkBoundaryPreconditions(1 + 3 * 20 + 4);

		payload_ = decodeByte();
		authData_ = new TcTpmSecret(this);
		tpmProof_ = new TcTpmNonce(this);
		storedDigest_ = new TcTpmDigest(this);
		long dataSize = decodeUINT32();
		if (dataSize > 0) {
			data_ = decodeBytes(dataSize);
		}

	}


	/*************************************************************************************************
	 * This method encodes the TPM_SEALED_DATA as a byte blob.
	 */
	public TcBlobData getEncoded()
	{
		TcBlobData retVal = TcBlobData.newBYTE( payload_);
		if (authData_ != null) {
			retVal.append(authData_.getEncoded());
		}
		if (tpmProof_ != null) {
			retVal.append(tpmProof_.getEncoded());
		}
		if (storedDigest_ != null) {
			retVal.append(storedDigest_.getEncoded());
		}
		retVal.append(TcBlobData.newUINT32(getDataSize()));
		if (data_ != null) {
			retVal.append(data_);
		}

		return retVal;
	}


	/*************************************************************************************************
	 * This method returns a String representation of the object.
	 */
	public String toString()
	{
		StringBuffer retVal = new StringBuffer();

		retVal.append("payload: ");
		retVal.append(payload_);
		retVal.append(Utils.getNL());
		if (authData_ != null) {
			retVal.append("authData: ");
			retVal.append(authData_.toString());
			retVal.append(Utils.getNL());
		}
		if (tpmProof_ != null) {
			retVal.append("tpmProof: ");
			retVal.append(tpmProof_.toString());
			retVal.append(Utils.getNL());
		}
		if (storedDigest_ != null) {
			retVal.append("storedDigest: ");
			retVal.append(storedDigest_.toString());
			retVal.append(Utils.getNL());
		}
		retVal.append("dataSize: ");
		retVal.append(getDataSize());
		retVal.append(Utils.getNL());
		if (data_ != null) {
			retVal.append("data: ");
			retVal.append(data_.toHexString());
			retVal.append(Utils.getNL());
		}

		return retVal.toString();
	}


	/*************************************************************************************************
	 * Returns contents of the payload field.
	 */
	public short getPayload()
	{
		return payload_;
	}


	/*************************************************************************************************
	 * Sets the payload field.
	 */
	public void setPayload(short payload)
	{
		payload_ = payload;
	}


	/*************************************************************************************************
	 * Returns contents of the authData field.
	 */
	public TcTpmSecret getAuthData()
	{
		return authData_;
	}


	/*************************************************************************************************
	 * Sets the authData field.
	 */
	public void setAuthData(TcTpmSecret authData)
	{
		authData_ = authData;
	}


	/*************************************************************************************************
	 * Returns contents of the tpmProof field.
	 */
	public TcTpmNonce getTpmProof()
	{
		return tpmProof_;
	}


	/*************************************************************************************************
	 * Sets the tpmProof field.
	 */
	public void setTpmProof(TcTpmNonce tpmProof)
	{
		tpmProof_ = tpmProof;
	}


	/*************************************************************************************************
	 * Returns contents of the storedDigest field.
	 */
	public TcTpmDigest getStoredDigest()
	{
		return storedDigest_;
	}


	/*************************************************************************************************
	 * Sets the storedDigest field.
	 */
	public void setStoredDigest(TcTpmDigest storedDigest)
	{
		storedDigest_ = storedDigest;
	}


	/*************************************************************************************************
	 * Returns contents of the dataSize field.
	 */
	public long getDataSize()
	{
		if (data_ == null) {
			return 0;
		} else {
			return data_.getLengthAsLong();
		}
	}


	/*************************************************************************************************
	 * Returns contents of the data field.
	 */
	public TcBlobData getData()
	{
		return data_;
	}


	/*************************************************************************************************
	 * Sets the data field.
	 */
	public void setData(TcBlobData data)
	{
		data_ = data;
	}

}
