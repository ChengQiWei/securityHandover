/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.api.structs.tpm;


import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder;
import iaik.tc.utils.misc.Utils;

public class TcTpmAuditEventIn extends TcCompositeTypeDecoder {
	protected int tag_;

	protected TcTpmDigest inputParms_;

	protected TcTpmCounterValue auditCount_;


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder()
	 */
	public TcTpmAuditEventIn()
	{
		super();
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcBlobData)
	 */
	public TcTpmAuditEventIn(TcBlobData data)
	{
		super(data);
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcBlobData,
	 *      int)
	 */
	public TcTpmAuditEventIn(TcBlobData data, int offset)
	{
		super(data, offset);
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder)
	 */
	public TcTpmAuditEventIn(TcCompositeTypeDecoder composite)
	{
		super(composite);
	}


	/*************************************************************************************************
	 * This method decodes the TPM_AUDIT_EVENT_IN from the byte blob.
	 */
	protected void decode()
	{
		checkBoundaryPreconditions(2 + 20 + 10);

		tag_ = decodeUINT16();
		inputParms_ = new TcTpmDigest(this);
		auditCount_ = new TcTpmCounterValue(this);

	}


	/*************************************************************************************************
	 * This method encodes the TPM_AUDIT_EVENT_IN as a byte blob.
	 */
	public TcBlobData getEncoded()
	{
		TcBlobData retVal = TcBlobData.newUINT16( tag_);
		if (inputParms_ != null) {
			retVal.append(inputParms_.getEncoded());
		}
		if (auditCount_ != null) {
			retVal.append(auditCount_.getEncoded());
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
		if (inputParms_ != null) {
			retVal.append("inputParms: ");
			retVal.append(inputParms_.toString());
			retVal.append(Utils.getNL());
		}
		if (auditCount_ != null) {
			retVal.append("auditCount: ");
			retVal.append(auditCount_.toString());
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
	 * Returns contents of the inputParms field.
	 */
	public TcTpmDigest getInputParms()
	{
		return inputParms_;
	}


	/*************************************************************************************************
	 * Sets the inputParms field.
	 */
	public void setInputParms(TcTpmDigest inputParms)
	{
		inputParms_ = inputParms;
	}


	/*************************************************************************************************
	 * Returns contents of the auditCount field.
	 */
	public TcTpmCounterValue getAuditCount()
	{
		return auditCount_;
	}


	/*************************************************************************************************
	 * Sets the auditCount field.
	 */
	public void setAuditCount(TcTpmCounterValue auditCount)
	{
		auditCount_ = auditCount;
	}

}
