/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.api.structs.tpm;


import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder;
import iaik.tc.utils.misc.Utils;

public class TcTpmStClearFlags extends TcCompositeTypeDecoder {
	protected int tag_;

	protected boolean deactivated_;

	protected boolean disableForceClear_;

	protected boolean physicalPresence_;

	protected boolean physicalPresenceLock_;

	protected boolean bGlobalLock_;


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder()
	 */
	public TcTpmStClearFlags()
	{
		super();
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcBlobData)
	 */
	public TcTpmStClearFlags(TcBlobData data)
	{
		super(data);
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcBlobData,
	 *      int)
	 */
	public TcTpmStClearFlags(TcBlobData data, int offset)
	{
		super(data, offset);
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder)
	 */
	public TcTpmStClearFlags(TcCompositeTypeDecoder composite)
	{
		super(composite);
	}


	/*************************************************************************************************
	 * This method decodes the TPM_ST_CLEAR_FLAGS from the byte blob.
	 */
	protected void decode()
	{
		checkBoundaryPreconditions(2 + 5);

		tag_ = decodeUINT16();
		deactivated_ = decodeBoolean();
		disableForceClear_ = decodeBoolean();
		physicalPresence_ = decodeBoolean();
		physicalPresenceLock_ = decodeBoolean();
		bGlobalLock_ = decodeBoolean();

	}


	/*************************************************************************************************
	 * This method encodes the TPM_ST_CLEAR_FLAGS as a byte blob.
	 */
	public TcBlobData getEncoded()
	{
		TcBlobData retVal = TcBlobData.newUINT16( tag_);
		retVal.append(TcBlobData.newBYTE(Utils.booleanToByte(deactivated_)));
		retVal.append(TcBlobData.newBYTE(Utils.booleanToByte(disableForceClear_)));
		retVal
				.append(TcBlobData.newBYTE(Utils.booleanToByte(physicalPresence_)));
		retVal.append(TcBlobData.newBYTE(
				Utils.booleanToByte(physicalPresenceLock_)));
		retVal.append(TcBlobData.newBYTE(Utils.booleanToByte(bGlobalLock_)));

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
		retVal.append("deactivated: ");
		retVal.append(deactivated_);
		retVal.append(Utils.getNL());
		retVal.append("disableForceClear: ");
		retVal.append(disableForceClear_);
		retVal.append(Utils.getNL());
		retVal.append("physicalPresence: ");
		retVal.append(physicalPresence_);
		retVal.append(Utils.getNL());
		retVal.append("physicalPresenceLock: ");
		retVal.append(physicalPresenceLock_);
		retVal.append(Utils.getNL());
		retVal.append("bGlobalLock: ");
		retVal.append(bGlobalLock_);
		retVal.append(Utils.getNL());

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
	 * Returns contents of the deactivated field.
	 */
	public boolean getDeactivated()
	{
		return deactivated_;
	}


	/*************************************************************************************************
	 * Sets the deactivated field.
	 */
	public void setDeactivated(boolean deactivated)
	{
		deactivated_ = deactivated;
	}


	/*************************************************************************************************
	 * Returns contents of the disableForceClear field.
	 */
	public boolean getDisableForceClear()
	{
		return disableForceClear_;
	}


	/*************************************************************************************************
	 * Sets the disableForceClear field.
	 */
	public void setDisableForceClear(boolean disableForceClear)
	{
		disableForceClear_ = disableForceClear;
	}


	/*************************************************************************************************
	 * Returns contents of the physicalPresence field.
	 */
	public boolean getPhysicalPresence()
	{
		return physicalPresence_;
	}


	/*************************************************************************************************
	 * Sets the physicalPresence field.
	 */
	public void setPhysicalPresence(boolean physicalPresence)
	{
		physicalPresence_ = physicalPresence;
	}


	/*************************************************************************************************
	 * Returns contents of the physicalPresenceLock field.
	 */
	public boolean getPhysicalPresenceLock()
	{
		return physicalPresenceLock_;
	}


	/*************************************************************************************************
	 * Sets the physicalPresenceLock field.
	 */
	public void setPhysicalPresenceLock(boolean physicalPresenceLock)
	{
		physicalPresenceLock_ = physicalPresenceLock;
	}


	/*************************************************************************************************
	 * Returns contents of the bGlobalLock field.
	 */
	public boolean getBGlobalLock()
	{
		return bGlobalLock_;
	}


	/*************************************************************************************************
	 * Sets the bGlobalLock field.
	 */
	public void setBGlobalLock(boolean bGlobalLock)
	{
		bGlobalLock_ = bGlobalLock;
	}

}
