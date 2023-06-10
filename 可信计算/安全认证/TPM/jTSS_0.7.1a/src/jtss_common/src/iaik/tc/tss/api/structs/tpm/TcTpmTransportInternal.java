/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.api.structs.tpm;


import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder;
import iaik.tc.utils.misc.Utils;

public class TcTpmTransportInternal extends TcCompositeTypeDecoder {
	protected int tag_;

	protected TcTpmDigest authData_;

	protected TcTpmTransportPublic transPublic_;

	protected long transHandle_;

	protected TcTpmNonce transNonceEven_;

	protected TcTpmDigest transDigest_;


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder()
	 */
	public TcTpmTransportInternal()
	{
		super();
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcBlobData)
	 */
	public TcTpmTransportInternal(TcBlobData data)
	{
		super(data);
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcBlobData,
	 *      int)
	 */
	public TcTpmTransportInternal(TcBlobData data, int offset)
	{
		super(data, offset);
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder)
	 */
	public TcTpmTransportInternal(TcCompositeTypeDecoder composite)
	{
		super(composite);
	}


	/*************************************************************************************************
	 * This method decodes the TPM_TRANSPORT_INTERNAL from the byte blob.
	 */
	protected void decode()
	{
		checkBoundaryPreconditions(2 + 20 + 12 + 4 + 2 * 20);

		tag_ = decodeUINT16();
		authData_ = new TcTpmDigest(this);
		transPublic_ = new TcTpmTransportPublic(this);
		transHandle_ = decodeUINT32();
		transNonceEven_ = new TcTpmNonce(this);
		transDigest_ = new TcTpmDigest(this);

	}


	/*************************************************************************************************
	 * This method encodes the TPM_TRANSPORT_INTERNAL as a byte blob.
	 */
	public TcBlobData getEncoded()
	{
		TcBlobData retVal = TcBlobData.newUINT16( tag_);
		if (authData_ != null) {
			retVal.append(authData_.getEncoded());
		}
		if (transPublic_ != null) {
			retVal.append(transPublic_.getEncoded());
		}
		retVal.append(TcBlobData.newUINT32( transHandle_));
		if (transNonceEven_ != null) {
			retVal.append(transNonceEven_.getEncoded());
		}
		if (transDigest_ != null) {
			retVal.append(transDigest_.getEncoded());
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
		if (authData_ != null) {
			retVal.append("authData: ");
			retVal.append(authData_.toString());
			retVal.append(Utils.getNL());
		}
		if (transPublic_ != null) {
			retVal.append("transPublic: ");
			retVal.append(transPublic_.toString());
			retVal.append(Utils.getNL());
		}
		retVal.append("transHandle: ");
		retVal.append(transHandle_);
		retVal.append(Utils.getNL());
		if (transNonceEven_ != null) {
			retVal.append("transNonceEven: ");
			retVal.append(transNonceEven_.toString());
			retVal.append(Utils.getNL());
		}
		if (transDigest_ != null) {
			retVal.append("transDigest: ");
			retVal.append(transDigest_.toString());
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
	 * Returns contents of the authData field.
	 */
	public TcTpmDigest getAuthData()
	{
		return authData_;
	}


	/*************************************************************************************************
	 * Sets the authData field.
	 */
	public void setAuthData(TcTpmDigest authData)
	{
		authData_ = authData;
	}


	/*************************************************************************************************
	 * Returns contents of the transPublic field.
	 */
	public TcTpmTransportPublic getTransPublic()
	{
		return transPublic_;
	}


	/*************************************************************************************************
	 * Sets the transPublic field.
	 */
	public void setTransPublic(TcTpmTransportPublic transPublic)
	{
		transPublic_ = transPublic;
	}


	/*************************************************************************************************
	 * Returns contents of the transHandle field.
	 */
	public long getTransHandle()
	{
		return transHandle_;
	}


	/*************************************************************************************************
	 * Sets the transHandle field.
	 */
	public void setTransHandle(long transHandle)
	{
		transHandle_ = transHandle;
	}


	/*************************************************************************************************
	 * Returns contents of the transNonceEven field.
	 */
	public TcTpmNonce getTransNonceEven()
	{
		return transNonceEven_;
	}


	/*************************************************************************************************
	 * Sets the transNonceEven field.
	 */
	public void setTransNonceEven(TcTpmNonce transNonceEven)
	{
		transNonceEven_ = transNonceEven;
	}


	/*************************************************************************************************
	 * Returns contents of the transDigest field.
	 */
	public TcTpmDigest getTransDigest()
	{
		return transDigest_;
	}


	/*************************************************************************************************
	 * Sets the transDigest field.
	 */
	public void setTransDigest(TcTpmDigest transDigest)
	{
		transDigest_ = transDigest;
	}

}
