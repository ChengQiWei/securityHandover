/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.api.structs.tpm;


import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder;
import iaik.tc.utils.misc.Utils;

public class TcTpmDelegateKeyBlob extends TcCompositeTypeDecoder {
	protected int tag_;

	protected TcTpmDelegatePublic pub_;

	protected TcTpmDigest integrityDigest_;

	protected TcTpmDigest pubKeyDigest_;

	protected TcBlobData additionalArea_;

	protected TcBlobData sensitiveArea_;


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder()
	 */
	public TcTpmDelegateKeyBlob()
	{
		super();
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcBlobData)
	 */
	public TcTpmDelegateKeyBlob(TcBlobData data)
	{
		super(data);
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcBlobData,
	 *      int)
	 */
	public TcTpmDelegateKeyBlob(TcBlobData data, int offset)
	{
		super(data, offset);
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder)
	 */
	public TcTpmDelegateKeyBlob(TcCompositeTypeDecoder composite)
	{
		super(composite);
	}


	/*************************************************************************************************
	 * This method decodes the TPM_DELEGATE_KEY_BLOB from the byte blob.
	 */
	protected void decode()
	{
		checkBoundaryPreconditions(2 + 48 + 20 + 20 + 4 + 4);

		tag_ = decodeUINT16();
		pub_ = new TcTpmDelegatePublic(this);
		integrityDigest_ = new TcTpmDigest(this);
		pubKeyDigest_ = new TcTpmDigest(this);
		long additionalSize = decodeUINT32();
		if (additionalSize > 0) {
			additionalArea_ = decodeBytes(additionalSize);
		}
		long sensitiveSize = decodeUINT32();
		if (sensitiveSize > 0) {
			sensitiveArea_ = decodeBytes(sensitiveSize);
		}
	}


	/*************************************************************************************************
	 * This method encodes the TPM_DELEGATE_KEY_BLOB as a byte blob.
	 */
	public TcBlobData getEncoded()
	{
		TcBlobData retVal = TcBlobData.newUINT16( tag_);
		if (pub_ != null) {
			retVal.append(pub_.getEncoded());
		}
		if (integrityDigest_ != null) {
			retVal.append(integrityDigest_.getEncoded());
		}
		if (pubKeyDigest_ != null) {
			retVal.append(pubKeyDigest_.getEncoded());
		}
		retVal.append(TcBlobData.newUINT32(getAdditionalSize()));
		if (additionalArea_ != null) {
			retVal.append(additionalArea_);
		}
		retVal.append(TcBlobData.newUINT32(getSensitiveSize()));
		if (sensitiveArea_ != null) {
			retVal.append(sensitiveArea_);
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
		if (pub_ != null) {
			retVal.append("pub: ");
			retVal.append(pub_.toString());
			retVal.append(Utils.getNL());
		}
		if (integrityDigest_ != null) {
			retVal.append("integrityDigest: ");
			retVal.append(integrityDigest_.toString());
			retVal.append(Utils.getNL());
		}
		if (pubKeyDigest_ != null) {
			retVal.append("pubKeyDigest: ");
			retVal.append(pubKeyDigest_.toString());
			retVal.append(Utils.getNL());
		}
		retVal.append("additionalSize: ");
		retVal.append(getAdditionalSize());
		retVal.append(Utils.getNL());
		if (additionalArea_ != null) {
			retVal.append("additionalArea: ");
			retVal.append(additionalArea_.toHexString());
			retVal.append(Utils.getNL());
		}
		retVal.append("sensitiveSize: ");
		retVal.append(getSensitiveArea());
		retVal.append(Utils.getNL());
		if (sensitiveArea_ != null) {
			retVal.append("sensitiveArea: ");
			retVal.append(sensitiveArea_.toHexString());
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
	 * Returns contents of the pub field.
	 */
	public TcTpmDelegatePublic getPub()
	{
		return pub_;
	}


	/*************************************************************************************************
	 * Sets the pub field.
	 */
	public void setPub(TcTpmDelegatePublic pub)
	{
		pub_ = pub;
	}


	/*************************************************************************************************
	 * Returns contents of the integrityDigest field.
	 */
	public TcTpmDigest getIntegrityDigest()
	{
		return integrityDigest_;
	}


	/*************************************************************************************************
	 * Sets the integrityDigest field.
	 */
	public void setIntegrityDigest(TcTpmDigest integrityDigest)
	{
		integrityDigest_ = integrityDigest;
	}


	/*************************************************************************************************
	 * Returns contents of the pubKeyDigest field.
	 */
	public TcTpmDigest getPubKeyDigest()
	{
		return pubKeyDigest_;
	}


	/*************************************************************************************************
	 * Sets the pubKeyDigest field.
	 */
	public void setPubKeyDigest(TcTpmDigest pubKeyDigest)
	{
		pubKeyDigest_ = pubKeyDigest;
	}


	/*************************************************************************************************
	 * Returns contents of the additionalSize field.
	 */
	public long getAdditionalSize()
	{
		if (additionalArea_ == null) {
			return 0;
		} else {
			return additionalArea_.getLengthAsLong();
		}
	}


	/*************************************************************************************************
	 * Returns contents of the additionalArea field.
	 */
	public TcBlobData getAdditionalArea()
	{
		return additionalArea_;
	}


	/*************************************************************************************************
	 * Sets the additionalArea field.
	 */
	public void setAdditionalArea(TcBlobData additionalArea)
	{
		additionalArea_ = additionalArea;
	}


	/*************************************************************************************************
	 * Returns contents of the sensitiveSize field.
	 */
	public long getSensitiveSize()
	{
		if (sensitiveArea_ == null) {
			return 0;
		} else {
			return sensitiveArea_.getLengthAsLong();
		}
	}


	/*************************************************************************************************
	 * Returns contents of the sensitiveArea field.
	 */
	public TcBlobData getSensitiveArea()
	{
		return sensitiveArea_;
	}


	/*************************************************************************************************
	 * Sets the sensitiveArea field.
	 */
	public void setSensitiveArea(TcBlobData sensitiveArea)
	{
		sensitiveArea_ = sensitiveArea;
	}

}
