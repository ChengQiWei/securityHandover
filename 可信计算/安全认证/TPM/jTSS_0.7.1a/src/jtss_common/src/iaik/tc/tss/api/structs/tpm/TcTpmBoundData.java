/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.api.structs.tpm;


import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder;
import iaik.tc.utils.misc.Utils;

public class TcTpmBoundData extends TcCompositeTypeDecoder {
	protected TcTpmStructVer ver_;

	protected short payload_;

	protected TcBlobData payloadData_;


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder()
	 */
	public TcTpmBoundData()
	{
		super();
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcBlobData)
	 */
	public TcTpmBoundData(TcBlobData data)
	{
		super(data);
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcBlobData,
	 *      int)
	 */
	public TcTpmBoundData(TcBlobData data, int offset)
	{
		super(data, offset);
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder)
	 */
	public TcTpmBoundData(TcCompositeTypeDecoder composite)
	{
		super(composite);
	}


	/*************************************************************************************************
	 * This method decodes the TPM_BOUND_DATA from the byte blob.
	 */
	protected void decode()
	{
		checkBoundaryPreconditions(4 + 1);

		ver_ = new TcTpmStructVer(this);
		payload_ = decodeByte();
		// note: there is no length field given in the TPM spec
		// we are taking the rest of the blob
		payloadData_ = decodeBytes(blob_.getLength() - 5); // TcTpmStructVer + Byte = 4 + 1

	}


	/*************************************************************************************************
	 * This method encodes the TPM_BOUND_DATA as a byte blob.
	 */
	public TcBlobData getEncoded()
	{
		TcBlobData retVal = TcBlobData.newBYTE( payload_);

		if (ver_ != null) {
			retVal.prepend(ver_.getEncoded());
		}
		if (payloadData_ != null) {
			retVal.append(payloadData_);
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
			retVal.append(ver_.toString());
			retVal.append(Utils.getNL());
		}
		retVal.append("payload: ");
		retVal.append(payload_);
		retVal.append(Utils.getNL());
		if (payloadData_ != null) {
			retVal.append("payloadData: ");
			retVal.append(payloadData_.toHexString());
			retVal.append(Utils.getNL());
		}

		return retVal.toString();
	}


	/*************************************************************************************************
	 * Returns contents of the ver field.
	 */
	public TcTpmStructVer getVer()
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
	 * Returns contents of the payloadData field.
	 */
	public TcBlobData getPayloadData()
	{
		return payloadData_;
	}


	/*************************************************************************************************
	 * Sets the payloadData field.
	 */
	public void setPayloadData(TcBlobData payloadData)
	{
		payloadData_ = payloadData;
	}

}
