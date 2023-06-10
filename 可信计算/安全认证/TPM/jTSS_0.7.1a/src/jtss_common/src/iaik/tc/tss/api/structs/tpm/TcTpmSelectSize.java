/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.api.structs.tpm;


import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder;
import iaik.tc.utils.misc.Utils;

public class TcTpmSelectSize extends TcCompositeTypeDecoder {
	protected short major_;

	protected short minor_;

	protected int reqSize_;


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder()
	 */
	public TcTpmSelectSize()
	{
		super();
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcBlobData)
	 */
	public TcTpmSelectSize(TcBlobData data)
	{
		super(data);
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcBlobData,
	 *      int)
	 */
	public TcTpmSelectSize(TcBlobData data, int offset)
	{
		super(data, offset);
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder)
	 */
	public TcTpmSelectSize(TcCompositeTypeDecoder composite)
	{
		super(composite);
	}


	/*************************************************************************************************
	 * This method decodes the TPM_SELECT_SIZE from the byte blob.
	 */
	protected void decode()
	{
		checkBoundaryPreconditions(1 + 1 + 2);

		major_ = decodeByte();
		minor_ = decodeByte();
		reqSize_ = decodeUINT16();

	}


	/*************************************************************************************************
	 * This method encodes the TPM_SELECT_SIZE as a byte blob.
	 */
	public TcBlobData getEncoded()
	{
		TcBlobData retVal = TcBlobData.newBYTE( major_);
		retVal.append(TcBlobData.newBYTE( minor_));
		retVal.append(TcBlobData.newUINT16( reqSize_));

		return retVal;
	}


	/*************************************************************************************************
	 * This method returns a String representation of the object.
	 */
	public String toString()
	{
		StringBuffer retVal = new StringBuffer();

		retVal.append("major: ");
		retVal.append(major_);
		retVal.append(Utils.getNL());
		retVal.append("minor: ");
		retVal.append(minor_);
		retVal.append(Utils.getNL());
		retVal.append("reqSize: ");
		retVal.append(reqSize_);
		retVal.append(Utils.getNL());

		return retVal.toString();
	}


	/*************************************************************************************************
	 * Returns contents of the major field.
	 */
	public short getMajor()
	{
		return major_;
	}


	/*************************************************************************************************
	 * Sets the major field.
	 */
	public void setMajor(short major)
	{
		major_ = major;
	}


	/*************************************************************************************************
	 * Returns contents of the minor field.
	 */
	public short getMinor()
	{
		return minor_;
	}


	/*************************************************************************************************
	 * Sets the minor field.
	 */
	public void setMinor(short minor)
	{
		minor_ = minor;
	}


	/*************************************************************************************************
	 * Returns contents of the reqSize field.
	 */
	public int getReqSize()
	{
		return reqSize_;
	}


	/*************************************************************************************************
	 * Sets the reqSize field.
	 */
	public void setReqSize(int reqSize)
	{
		reqSize_ = reqSize;
	}

}
