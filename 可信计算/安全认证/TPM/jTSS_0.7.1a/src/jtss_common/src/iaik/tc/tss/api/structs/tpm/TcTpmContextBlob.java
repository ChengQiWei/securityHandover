/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.api.structs.tpm;


import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder;
import iaik.tc.utils.misc.Utils;

public class TcTpmContextBlob extends TcCompositeTypeDecoder {
	protected int tag_;

	protected long resourceType_;

	protected long handle_;

	protected TcBlobData label_; // 16 bytes

	protected long contextCount_;

	protected TcTpmDigest integrityDigest_;

	protected TcBlobData additionalData_;

	protected TcBlobData sensitiveData_;


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder()
	 */
	public TcTpmContextBlob()
	{
		super();
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcBlobData)
	 */
	public TcTpmContextBlob(TcBlobData data)
	{
		super(data);
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcBlobData,
	 *      int)
	 */
	public TcTpmContextBlob(TcBlobData data, int offset)
	{
		super(data, offset);
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder)
	 */
	public TcTpmContextBlob(TcCompositeTypeDecoder composite)
	{
		super(composite);
	}


	/*************************************************************************************************
	 * This method decodes the TPM_CONTEXT_BLOB from the byte blob.
	 */
	protected void decode()
	{
		checkBoundaryPreconditions(2 + 4 + 4 + 16 + 4 + 20 + 4 + 4);

		tag_ = decodeUINT16();
		resourceType_ = decodeUINT32();
		handle_ = decodeUINT32();
		label_ = decodeBytes(16);
		contextCount_ = decodeUINT32();
		integrityDigest_ = new TcTpmDigest(this);
		long additionalSize = decodeUINT32();
		if (additionalSize > 0) {
			additionalData_ = decodeBytes(additionalSize);
		}
		long sensitiveDataSize = decodeUINT32();
		if (sensitiveDataSize > 0) {
			sensitiveData_ = decodeBytes(sensitiveDataSize);
		}

	}


	/*************************************************************************************************
	 * This method encodes the TPM_CONTEXT_BLOB as a byte blob.
	 */
	public TcBlobData getEncoded()
	{
		TcBlobData retVal = TcBlobData.newUINT16( tag_);
		retVal.append(TcBlobData.newUINT32( resourceType_));
		retVal.append(TcBlobData.newUINT32( handle_));
		if (label_ != null) {
			retVal.append(label_);
		}
		retVal.append(TcBlobData.newUINT32( contextCount_));
		if (integrityDigest_ != null) {
			retVal.append(integrityDigest_.getEncoded());
		}
		retVal.append(TcBlobData.newUINT32( getAdditionalSize()));
		if (additionalData_ != null) {
			retVal.append(additionalData_);
		}
		retVal.append(TcBlobData.newUINT32( getSensitiveSize()));
		if (sensitiveData_ != null) {
			retVal.append(sensitiveData_);
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
		retVal.append("resourceType: ");
		retVal.append(resourceType_);
		retVal.append(Utils.getNL());
		retVal.append("handle: ");
		retVal.append(handle_);
		retVal.append(Utils.getNL());
		if (label_ != null) {
			retVal.append("label: ");
			retVal.append(label_.toHexString());
			retVal.append(Utils.getNL());
		}
		retVal.append("contextCount: ");
		retVal.append(contextCount_);
		retVal.append(Utils.getNL());
		retVal.append("integrityDigest: ");
		retVal.append(integrityDigest_);
		retVal.append(Utils.getNL());
		if (integrityDigest_ != null) {
			retVal.append("integrityDigest: ");
			retVal.append(integrityDigest_.toString());
			retVal.append(Utils.getNL());
		}
		retVal.append("additionalSize: ");
		retVal.append(getAdditionalSize());
		retVal.append(Utils.getNL());
		if (additionalData_ != null) {
			retVal.append("additionalData: ");
			retVal.append(additionalData_.toHexString());
			retVal.append(Utils.getNL());
		}
		retVal.append("sensitiveSize: ");
		retVal.append(getSensitiveSize());
		retVal.append(Utils.getNL());
		if (sensitiveData_ != null) {
			retVal.append("sensitiveData: ");
			retVal.append(sensitiveData_.toHexString());
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
	 * Returns contents of the resourceType field.
	 */
	public long getResourceType()
	{
		return resourceType_;
	}


	/*************************************************************************************************
	 * Sets the resourceType field.
	 */
	public void setResourceType(long resourceType)
	{
		resourceType_ = resourceType;
	}


	/*************************************************************************************************
	 * Returns contents of the handle field.
	 */
	public long getHandle()
	{
		return handle_;
	}


	/*************************************************************************************************
	 * Sets the handle field.
	 */
	public void setHandle(long handle)
	{
		handle_ = handle;
	}


	/*************************************************************************************************
	 * Returns contents of the label field.
	 */
	public TcBlobData getLabel()
	{
		return label_;
	}


	/*************************************************************************************************
	 * Sets the label field.
	 */
	public void setLabel(TcBlobData label)
	{
		label_ = label;
	}


	/*************************************************************************************************
	 * Returns contents of the contextCount field.
	 */
	public long getContextCount()
	{
		return contextCount_;
	}


	/*************************************************************************************************
	 * Sets the contextCount field.
	 */
	public void setContextCount(long contextCount)
	{
		contextCount_ = contextCount;
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
	 * Returns contents of the additionalSize field.
	 */
	public long getAdditionalSize()
	{
		if (additionalData_ == null) {
			return 0;
		} else {
			return additionalData_.getLengthAsLong();
		}
			
	}


	/*************************************************************************************************
	 * Returns contents of the additionalData field.
	 */
	public TcBlobData getAdditionalData()
	{
		return additionalData_;
	}


	/*************************************************************************************************
	 * Sets the additionalData field.
	 */
	public void setAdditionalData(TcBlobData additionalData)
	{
		additionalData_ = additionalData;
	}


	/*************************************************************************************************
	 * Returns contents of the sensitiveSize field.
	 */
	public long getSensitiveSize()
	{
		if (sensitiveData_ == null) {
			return 0;
		} else {
			return sensitiveData_.getLengthAsLong();
		}
	}


	/*************************************************************************************************
	 * Returns contents of the sensitiveData field.
	 */
	public TcBlobData getSensitiveData()
	{
		return sensitiveData_;
	}


	/*************************************************************************************************
	 * Sets the sensitiveData field.
	 */
	public void setSensitiveData(TcBlobData sensitiveData)
	{
		sensitiveData_ = sensitiveData;
	}

}
