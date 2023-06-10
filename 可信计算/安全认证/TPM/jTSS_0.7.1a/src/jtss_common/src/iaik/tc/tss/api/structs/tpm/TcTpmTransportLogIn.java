/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.api.structs.tpm;


import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder;
import iaik.tc.utils.misc.Utils;

public class TcTpmTransportLogIn extends TcCompositeTypeDecoder {
	protected int tag_;

	protected TcTpmDigest parameters_;

	protected TcTpmDigest pubKeyHash_;


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder()
	 */
	public TcTpmTransportLogIn()
	{
		super();
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcBlobData)
	 */
	public TcTpmTransportLogIn(TcBlobData data)
	{
		super(data);
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcBlobData,
	 *      int)
	 */
	public TcTpmTransportLogIn(TcBlobData data, int offset)
	{
		super(data, offset);
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder)
	 */
	public TcTpmTransportLogIn(TcCompositeTypeDecoder composite)
	{
		super(composite);
	}


	/*************************************************************************************************
	 * This method decodes the TPM_TRANSPORT_LOG_IN from the byte blob.
	 */
	protected void decode()
	{
		checkBoundaryPreconditions(2 + 2 * 20);

		tag_ = decodeUINT16();
		parameters_ = new TcTpmDigest(this);
		pubKeyHash_ = new TcTpmDigest(this);

	}


	/*************************************************************************************************
	 * This method encodes the TPM_TRANSPORT_LOG_IN as a byte blob.
	 */
	public TcBlobData getEncoded()
	{
		TcBlobData retVal = TcBlobData.newUINT16( tag_);
		if (parameters_ != null) {
			retVal.append(parameters_.getEncoded());
		}
		if (pubKeyHash_ != null) {
			retVal.append(pubKeyHash_.getEncoded());
		}

		return retVal;
	}


	/*************************************************************************************************
	 * This method returns a String representation of the object.
	 */
	public String toString()
	{
		StringBuffer retVal = new StringBuffer();

		retVal.append("tag: ");
		retVal.append(tag_);
		retVal.append(Utils.getNL());
		if (parameters_ != null) {
			retVal.append("parameters: ");
			retVal.append(parameters_.toString());
			retVal.append(Utils.getNL());
		}
		if (pubKeyHash_ != null) {
			retVal.append("pubKeyHash: ");
			retVal.append(pubKeyHash_.toString());
			retVal.append(Utils.getNL());
		}

		return retVal.toString();
	}


	/*************************************************************************************************
	 * Returns contents of the tag field.
	 */
	public int getTag()
	{
		return tag_;
	}


	/*************************************************************************************************
	 * Sets the tag field.
	 */
	public void setTag(int tag)
	{
		tag_ = tag;
	}


	/*************************************************************************************************
	 * Returns contents of the parameters field.
	 */
	public TcTpmDigest getParameters()
	{
		return parameters_;
	}


	/*************************************************************************************************
	 * Sets the parameters field.
	 */
	public void setParameters(TcTpmDigest parameters)
	{
		parameters_ = parameters;
	}


	/*************************************************************************************************
	 * Returns contents of the pubKeyHash field.
	 */
	public TcTpmDigest getPubKeyHash()
	{
		return pubKeyHash_;
	}


	/*************************************************************************************************
	 * Sets the pubKeyHash field.
	 */
	public void setPubKeyHash(TcTpmDigest pubKeyHash)
	{
		pubKeyHash_ = pubKeyHash;
	}

}
