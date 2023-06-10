/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.api.structs.tpm;


import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder;
import iaik.tc.utils.misc.Utils;

/**
 * This structure describes a symmetric key, used during the ColalteIdentityRequest process.
 * 
 * @TPM_V1 65
 */
public class TcTpmSymmetricKey extends TcCompositeTypeDecoder {

	/**
	 * The algorithm identifier of the symmetric key.
	 */
	protected long algId_;

	/**
	 * the manner in which the key will be used for encryption operations.
	 */
	protected int encScheme_;

	/**
	 * The symmetric key data.
	 */
	protected TcBlobData data_;


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 */
	public TcTpmSymmetricKey()
	{
		super();
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 */
	public TcTpmSymmetricKey(TcBlobData blob)
	{
		super(blob);
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 */
	public TcTpmSymmetricKey(TcBlobData blob, int offset)
	{
		super(blob, offset);
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 */
	public TcTpmSymmetricKey(TcCompositeTypeDecoder composite)
	{
		super(composite);
	}


	/*************************************************************************************************
	 * This method decodes the TPM_SYMMETRIC_KEY from the byte blob.
	 */
	protected void decode()
	{
		checkBoundaryPreconditions(8); // minimum size if no data

		algId_ = decodeTpmAlgorithmId();
		encScheme_ = decodeTpmEncScheme();
		int size = decodeUINT16();
		if (size > 0) {
			data_ = decodeBytes(size);
		}
	}


	/*************************************************************************************************
	 * This method encodes the TPM_SYMMETRIC_KEY as a byte blob.
	 */
	public TcBlobData getEncoded()
	{
		TcBlobData retVal = TcBlobData.newUINT32( algId_);
		retVal.append(TcBlobData.newUINT16( encScheme_));
		retVal.append(TcBlobData.newUINT16( getSize()));
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

		retVal.append("algId: ");
		retVal.append(algId_);
		retVal.append(Utils.getNL());
		retVal.append("encScheme: ");
		retVal.append(encScheme_);
		retVal.append(Utils.getNL());
		retVal.append("size: ");
		retVal.append(getSize());
		retVal.append(Utils.getNL());
		if (data_ != null) {
			retVal.append("data: ");
			retVal.append(data_.toHexString());
			retVal.append(Utils.getNL());
		}

		return retVal.toString();
	}


	/*************************************************************************************************
	 * Returns contents of the algId field.
	 */
	public long getAlgId()
	{
		return algId_;
	}


	/*************************************************************************************************
	 * Sets the algId field.
	 */
	public void setAlgId(long algId)
	{
		algId_ = algId;
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


	/*************************************************************************************************
	 * Returns contents of the encScheme field.
	 */
	public int getEncScheme()
	{
		return encScheme_;
	}


	/*************************************************************************************************
	 * Sets the encScheme field.
	 */
	public void setEncScheme(int encScheme)
	{
		encScheme_ = encScheme;
	}


	/*************************************************************************************************
	 * Returns contents of the size field.
	 */
	public int getSize()
	{
		return data_.getLength();
	}
}
