/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.api.structs.tpm;


import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder;
import iaik.tc.utils.misc.Utils;

public class TcTpmDelegations extends TcCompositeTypeDecoder {
	protected int tag_;

	protected long delegateType_;

	protected long per1_;

	protected long per2_;


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder()
	 */
	public TcTpmDelegations()
	{
		super();
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcBlobData)
	 */
	public TcTpmDelegations(TcBlobData data)
	{
		super(data);
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcBlobData,
	 *      int)
	 */
	public TcTpmDelegations(TcBlobData data, int offset)
	{
		super(data, offset);
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder)
	 */
	public TcTpmDelegations(TcCompositeTypeDecoder composite)
	{
		super(composite);
	}


	/*************************************************************************************************
	 * This method decodes the TPM_DELEGATIONS from the byte blob.
	 */
	protected void decode()
	{
		checkBoundaryPreconditions(2 + 3 * 4);

		tag_ = decodeUINT16();
		delegateType_ = decodeUINT32();
		per1_ = decodeUINT32();
		per2_ = decodeUINT32();

	}


	/*************************************************************************************************
	 * This method encodes the TPM_DELEGATIONS as a byte blob.
	 */
	public TcBlobData getEncoded()
	{
		TcBlobData retVal = TcBlobData.newUINT16( tag_);
		retVal.append(TcBlobData.newUINT32( delegateType_));
		retVal.append(TcBlobData.newUINT32( per1_));
		retVal.append(TcBlobData.newUINT32( per2_));

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
		retVal.append("delegateType: ");
		retVal.append(delegateType_);
		retVal.append(Utils.getNL());
		retVal.append("per1: ");
		retVal.append(per1_);
		retVal.append(Utils.getNL());
		retVal.append("per2: ");
		retVal.append(per2_);
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
	 * Returns contents of the delegateType field.
	 */
	public long getDelegateType()
	{
		return delegateType_;
	}


	/*************************************************************************************************
	 * Sets the delegateType field.
	 */
	public void setDelegateType(long delegateType)
	{
		delegateType_ = delegateType;
	}


	/*************************************************************************************************
	 * Returns contents of the per1 field.
	 */
	public long getPer1()
	{
		return per1_;
	}


	/*************************************************************************************************
	 * Sets the per1 field.
	 */
	public void setPer1(long per1)
	{
		per1_ = per1;
	}


	/*************************************************************************************************
	 * Returns contents of the per2 field.
	 */
	public long getPer2()
	{
		return per2_;
	}


	/*************************************************************************************************
	 * Sets the per2 field.
	 */
	public void setPer2(long per2)
	{
		per2_ = per2;
	}

}
