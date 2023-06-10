/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.api.structs.tpm;


import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder;
import iaik.tc.utils.misc.Utils;

public class TcTpmKeyHandleList extends TcCompositeTypeDecoder {

	protected int loaded_;

	protected long[] handle_;


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder()
	 */
	public TcTpmKeyHandleList()
	{
		super();
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcBlobData)
	 */
	public TcTpmKeyHandleList(TcBlobData data)
	{
		super(data);
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcBlobData,
	 *      int)
	 */
	public TcTpmKeyHandleList(TcBlobData data, int offset)
	{
		super(data, offset);
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder)
	 */
	public TcTpmKeyHandleList(TcCompositeTypeDecoder composite)
	{
		super(composite);
	}


	/*************************************************************************************************
	 * This method decodes the TPM_KEY_HANDLE_LIST from the byte blob.
	 */
	protected void decode()
	{
		// Note: In case of an empty TPM_KEY_HANDLE_LIST STM TPMs return null while e.g. IFX TPMs return
		// an empty list (that is: a 2 byte structure where loaded is set to 0).

		if (blob_ == null) {
			loaded_ = 0;
		} else {
			checkBoundaryPreconditions(2);
			loaded_ = decodeUINT16();
			if (loaded_ > 0) {
				handle_ = new long[loaded_];
				for (int i = 0; i < loaded_; i++) {
					handle_[i] = decodeUINT32();
				}
			}
		}
	}


	/*************************************************************************************************
	 * This method encodes the TPM_KEY_HANDLE_LIST as a byte blob.
	 */
	/*************************************************************************************************
	 * This method encodes the TPM_KEY_HANDLE_LIST as a byte blob.
	 */
	public TcBlobData getEncoded()
	{
		TcBlobData retVal = TcBlobData.newUINT16( loaded_);
		for (int i = 0; i < loaded_ - 1; i++) {
			retVal.append(TcBlobData.newUINT32( handle_[i]));
		}

		return retVal;
	}


	/*************************************************************************************************
	 * This method returns a String representation of the object.
	 */
	/*************************************************************************************************
	 * This method returns a String representation of the object.
	 */
	public String toString()
	{
		StringBuffer retVal = new StringBuffer();

		retVal.append("loaded: ");
		retVal.append(loaded_);
		retVal.append(Utils.getNL());

		retVal.append("handles: ");
		if (loaded_ > 0) {
			for (int i = 0; i < loaded_ - 1; i++) {
				retVal.append(Utils.longToHex(handle_[i]) + ",");
			}
			retVal.append(Utils.longToHex(handle_[loaded_ - 1]));
		}
		retVal.append(Utils.getNL());

		return retVal.toString();
	}


	/*************************************************************************************************
	 * Returns contents of the loaded field.
	 */
	public int getLoaded()
	{
		return loaded_;
	}


	/*************************************************************************************************
	 * Sets the loaded field.
	 */
	public void setLoaded(int loaded)
	{
		loaded_ = loaded;
	}


	/*************************************************************************************************
	 * Returns contents of the handle field.
	 */
	public long[] getHandle()
	{
		if (handle_ == null) {
			return new long[] { };
		} else {
			return handle_;
		}
	}


	/*************************************************************************************************
	 * Sets the handle field.
	 */
	public void setHandle(long[] handle)
	{
		handle_ = handle;
	}

}
