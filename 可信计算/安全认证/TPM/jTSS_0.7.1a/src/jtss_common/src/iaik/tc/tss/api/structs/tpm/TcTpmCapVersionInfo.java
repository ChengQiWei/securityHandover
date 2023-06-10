/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.api.structs.tpm;


import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder;
import iaik.tc.utils.misc.Utils;

public class TcTpmCapVersionInfo extends TcCompositeTypeDecoder {
	protected int tag_;

	protected TcTpmVersion version_;

	protected int specLevel_;

	protected short errataRev_;

	protected TcBlobData tpmVendorID_; // 4 bytes

	protected TcBlobData vendorSpecific_;


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder()
	 */
	public TcTpmCapVersionInfo()
	{
		super();
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcBlobData)
	 */
	public TcTpmCapVersionInfo(TcBlobData data)
	{
		super(data);
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcBlobData,
	 *      int)
	 */
	public TcTpmCapVersionInfo(TcBlobData data, int offset)
	{
		super(data, offset);
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder)
	 */
	public TcTpmCapVersionInfo(TcCompositeTypeDecoder composite)
	{
		super(composite);
	}


	/*************************************************************************************************
	 * This method decodes the TPM_CAP_VERSION_INFO from the byte blob.
	 */
	protected void decode()
	{
		checkBoundaryPreconditions(2 + 4 + 2 + 1 + 4 + 2);

		tag_ = decodeUINT16();
		version_ = new TcTpmVersion(this);
		specLevel_ = decodeUINT16();
		errataRev_ = decodeByte();
		tpmVendorID_ = decodeBytes(4);
		int vendorSpecificSize = decodeUINT16();
		if (vendorSpecificSize > 0) {
			vendorSpecific_ = decodeBytes(vendorSpecificSize);
		}

	}


	/*************************************************************************************************
	 * This method encodes the TPM_CAP_VERSION_INFO as a byte blob.
	 */
	public TcBlobData getEncoded()
	{
		TcBlobData retVal = TcBlobData.newUINT16( tag_);
		if (version_ != null) {
			retVal.append(version_.getEncoded());
		}

		retVal.append(TcBlobData.newUINT16( specLevel_));

		retVal.append(TcBlobData.newBYTE( errataRev_));
		if (tpmVendorID_ != null) {
			retVal.append(tpmVendorID_);
		}
		retVal.append(TcBlobData.newUINT16( getVendorSpecificSize()));
		if (vendorSpecific_ != null) {
			retVal.append(vendorSpecific_);
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
		if (version_ != null) {
			retVal.append("version: ");
			retVal.append(version_.toString());
			retVal.append(Utils.getNL());
		}
		retVal.append("specLevel: ");
		retVal.append(specLevel_);
		retVal.append(Utils.getNL());
		retVal.append("errataRev: ");
		retVal.append(errataRev_);
		retVal.append(Utils.getNL());
		if (tpmVendorID_ != null) {
			retVal.append("tpmVendorID: ");
			retVal.append(tpmVendorID_.toHexString());
			retVal.append(Utils.getNL());
		}
		retVal.append("vendorSpecificSize: ");
		retVal.append(getVendorSpecificSize());
		retVal.append(Utils.getNL());
		if (vendorSpecific_ != null) {
			retVal.append("vendorSpecific: ");
			retVal.append(vendorSpecific_.toHexString());
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
	 * Returns contents of the version field.
	 */
	public TcTpmVersion getVersion()
	{
		return version_;
	}


	/*************************************************************************************************
	 * Sets the version field.
	 */
	public void setVersion(TcTpmVersion version)
	{
		version_ = version;
	}


	/*************************************************************************************************
	 * Returns contents of the specLevel field.
	 */
	public int getSpecLevel()
	{
		return specLevel_;
	}


	/*************************************************************************************************
	 * Sets the specLevel field.
	 */
	public void setSpecLevel(int specLevel)
	{
		specLevel_ = specLevel;
	}


	/*************************************************************************************************
	 * Returns contents of the errataRev field.
	 */
	public short getErrataRev()
	{
		return errataRev_;
	}


	/*************************************************************************************************
	 * Sets the errataRev field.
	 */
	public void setErrataRev(short errataRev)
	{
		errataRev_ = errataRev;
	}


	/*************************************************************************************************
	 * Returns contents of the tpmVendorID field.
	 */
	public TcBlobData getTpmVendorID()
	{
		return tpmVendorID_;
	}


	/*************************************************************************************************
	 * Sets the tpmVendorID field.
	 */
	public void setTpmVendorID(TcBlobData tpmVendorID)
	{
		tpmVendorID_ = tpmVendorID;
	}


	/*************************************************************************************************
	 * Returns contents of the vendorSpecificSize field.
	 */
	public int getVendorSpecificSize()
	{
		if (vendorSpecific_ == null) {
			return 0;
		} else {
			return vendorSpecific_.getLength();
		}
	}


	/*************************************************************************************************
	 * Returns contents of the vendorSpecific field.
	 */
	public TcBlobData getVendorSpecific()
	{
		return vendorSpecific_;
	}


	/*************************************************************************************************
	 * Sets the vendorSpecific field.
	 */
	public void setVendorSpecific(TcBlobData vendorSpecific)
	{
		vendorSpecific_ = vendorSpecific;
	}

}
