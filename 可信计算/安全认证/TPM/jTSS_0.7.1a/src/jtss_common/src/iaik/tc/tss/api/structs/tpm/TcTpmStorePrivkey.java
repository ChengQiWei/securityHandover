/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.api.structs.tpm;


import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder;
import iaik.tc.utils.misc.Utils;

public class TcTpmStorePrivkey extends TcCompositeTypeDecoder {
	protected long keyLength_;

	protected TcBlobData key_;


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder()
	 */
	public TcTpmStorePrivkey()
	{
		super();
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcBlobData)
	 */
	public TcTpmStorePrivkey(TcBlobData data)
	{
		super(data);
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcBlobData,
	 *      int)
	 */
	public TcTpmStorePrivkey(TcBlobData data, int offset)
	{
		super(data, offset);
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder)
	 */
	public TcTpmStorePrivkey(TcCompositeTypeDecoder composite)
	{
		super(composite);
	}


	/*************************************************************************************************
	 * This method decodes the TPM_STORE_PRIVKEY from the byte blob.
	 */
	protected void decode()
	{
		checkBoundaryPreconditions(4);

		keyLength_ = decodeUINT32();
		if (keyLength_ > 0) {
			key_ = decodeBytes(keyLength_);
		}

	}


	/*************************************************************************************************
	 * This method encodes the TPM_STORE_PRIVKEY as a byte blob.
	 */
	public TcBlobData getEncoded()
	{
		TcBlobData retVal = TcBlobData.newUINT32( keyLength_);
		if (key_ != null) {
			retVal.append(key_);
		}

		return retVal;
	}


	/*************************************************************************************************
	 * This method returns a String representation of the object.
	 */
	public String toString()
	{
		StringBuffer retVal = new StringBuffer();

		retVal.append("keyLength: ");
		retVal.append(keyLength_);
		retVal.append(Utils.getNL());
		if (key_ != null) {
			retVal.append("key: ");
			retVal.append(key_.toHexString());
			retVal.append(Utils.getNL());
		}

		return retVal.toString();
	}


	/*************************************************************************************************
	 * Returns contents of the keyLength field.
	 */
	public long getKeyLength()
	{
		return keyLength_;
	}


	/*************************************************************************************************
	 * Sets the keyLength field.
	 */
	public void setKeyLength(long keyLength)
	{
		keyLength_ = keyLength;
	}


	/*************************************************************************************************
	 * Returns contents of the key field.
	 */
	public TcBlobData getKey()
	{
		return key_;
	}


	/*************************************************************************************************
	 * Sets the key field.
	 */
	public void setKey(TcBlobData key)
	{
		key_ = key;
	}

}
