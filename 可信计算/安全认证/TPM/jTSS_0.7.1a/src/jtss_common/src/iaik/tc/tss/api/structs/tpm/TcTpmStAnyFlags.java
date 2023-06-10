/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.api.structs.tpm;


import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder;
import iaik.tc.utils.misc.Utils;

public class TcTpmStAnyFlags extends TcCompositeTypeDecoder {
	protected int tag_;

	protected boolean postInitialise_;

	protected long localityModifier_;

	protected boolean transportExclusive_;

	protected boolean TOSPresent_;


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder()
	 */
	public TcTpmStAnyFlags()
	{
		super();
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcBlobData)
	 */
	public TcTpmStAnyFlags(TcBlobData data)
	{
		super(data);
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcBlobData,
	 *      int)
	 */
	public TcTpmStAnyFlags(TcBlobData data, int offset)
	{
		super(data, offset);
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder)
	 */
	public TcTpmStAnyFlags(TcCompositeTypeDecoder composite)
	{
		super(composite);
	}


	/*************************************************************************************************
	 * This method decodes the TPM_ST_ANY_FLAGS from the byte blob.
	 */
	protected void decode()
	{
		checkBoundaryPreconditions(2 + 1 + 4 + 1 + 1);

		tag_ = decodeUINT16();
		postInitialise_ = decodeBoolean();
		localityModifier_ = decodeUINT32();
		transportExclusive_ = decodeBoolean();
		TOSPresent_ = decodeBoolean();

	}


	/*************************************************************************************************
	 * This method encodes the TPM_ST_ANY_FLAGS as a byte blob.
	 */
	public TcBlobData getEncoded()
	{
		TcBlobData retVal = TcBlobData.newUINT16( tag_);
		retVal.append(TcBlobData.newBYTE(Utils.booleanToByte(postInitialise_)));
		retVal.append(TcBlobData.newUINT32( localityModifier_));
		retVal.append(TcBlobData.newBYTE(
				Utils.booleanToByte(transportExclusive_)));
		retVal.append(TcBlobData.newBYTE(Utils.booleanToByte(TOSPresent_)));

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
		retVal.append("postInitialise: ");
		retVal.append(postInitialise_);
		retVal.append(Utils.getNL());
		retVal.append("localityModifier: ");
		retVal.append(localityModifier_);
		retVal.append(Utils.getNL());
		retVal.append("transportExclusive: ");
		retVal.append(transportExclusive_);
		retVal.append(Utils.getNL());
		retVal.append("TOSPresent: ");
		retVal.append(TOSPresent_);
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
	 * Returns contents of the postInitialise field.
	 */
	public boolean getPostInitialise()
	{
		return postInitialise_;
	}


	/*************************************************************************************************
	 * Sets the postInitialise field.
	 */
	public void setPostInitialise(boolean postInitialise)
	{
		postInitialise_ = postInitialise;
	}


	/*************************************************************************************************
	 * Returns contents of the localityModifier field.
	 */
	public long getLocalityModifier()
	{
		return localityModifier_;
	}


	/*************************************************************************************************
	 * Sets the localityModifier field.
	 */
	public void setLocalityModifier(long localityModifier)
	{
		localityModifier_ = localityModifier;
	}


	/*************************************************************************************************
	 * Returns contents of the transportExclusive field.
	 */
	public boolean getTransportExclusive()
	{
		return transportExclusive_;
	}


	/*************************************************************************************************
	 * Sets the transportExclusive field.
	 */
	public void setTransportExclusive(boolean transportExclusive)
	{
		transportExclusive_ = transportExclusive;
	}


	/*************************************************************************************************
	 * Returns contents of the TOSPresent field.
	 */
	public boolean getTOSPresent()
	{
		return TOSPresent_;
	}


	/*************************************************************************************************
	 * Sets the TOSPresent field.
	 */
	public void setTOSPresent(boolean TOSPresent)
	{
		TOSPresent_ = TOSPresent;
	}

}
