/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.api.structs.tpm;


import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder;
import iaik.tc.utils.misc.Utils;

public class TcTpmAuditEventOut extends TcCompositeTypeDecoder {
	protected int tag_;

	protected long ordinal_;

	protected TcTpmDigest outputParms_;

	protected TcTpmCounterValue auditCount_;

	protected long returnCode_;


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder()
	 */
	public TcTpmAuditEventOut()
	{
		super();
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcBlobData)
	 */
	public TcTpmAuditEventOut(TcBlobData data)
	{
		super(data);
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcBlobData,
	 *      int)
	 */
	public TcTpmAuditEventOut(TcBlobData data, int offset)
	{
		super(data, offset);
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder)
	 */
	public TcTpmAuditEventOut(TcCompositeTypeDecoder composite)
	{
		super(composite);
	}


	/*************************************************************************************************
	 * This method decodes the TPM_AUDIT_EVENT_OUT from the byte blob.
	 */
	protected void decode()
	{
		checkBoundaryPreconditions(2 + 4 + 20 + 10 + 4);

		tag_ = decodeUINT16();
		ordinal_ = decodeUINT32();
		outputParms_ = new TcTpmDigest(this);
		auditCount_ = new TcTpmCounterValue(this);
		returnCode_ = decodeUINT32();
	}


	/*************************************************************************************************
	 * This method encodes the TPM_AUDIT_EVENT_OUT as a byte blob.
	 */
	public TcBlobData getEncoded()
	{
		TcBlobData retVal = TcBlobData.newUINT16( tag_);
		retVal.append(TcBlobData.newUINT32( ordinal_));
		if (outputParms_ != null) {
			retVal.append(outputParms_.getEncoded());
		}
		if (auditCount_ != null) {
			retVal.append(auditCount_.getEncoded());
		}
		retVal.append(TcBlobData.newUINT32( returnCode_));

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
		retVal.append("ordinal: ");
		retVal.append(ordinal_);
		retVal.append(Utils.getNL());
		if (outputParms_ != null) {
			retVal.append("outputParms: ");
			retVal.append(outputParms_.toString());
			retVal.append(Utils.getNL());
		}
		if (auditCount_ != null) {
			retVal.append("auditCount: ");
			retVal.append(auditCount_.toString());
			retVal.append(Utils.getNL());
		}
		retVal.append("returnCode: ");
		retVal.append(returnCode_);
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
	 * Returns contents of the ordinal field.
	 */
	public long getOrdinal()
	{
		return ordinal_;
	}


	/*************************************************************************************************
	 * Sets the ordinal field.
	 */
	public void setOrdinal(long ordinal)
	{
		ordinal_ = ordinal;
	}


	/*************************************************************************************************
	 * Returns contents of the outputParms field.
	 */
	public TcTpmDigest getOutputParms()
	{
		return outputParms_;
	}


	/*************************************************************************************************
	 * Sets the outputParms field.
	 */
	public void setOutputParms(TcTpmDigest outputParms)
	{
		outputParms_ = outputParms;
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


	/*************************************************************************************************
	 * Returns contents of the returnCode field.
	 */
	public long getReturnCode()
	{
		return returnCode_;
	}


	/*************************************************************************************************
	 * Sets the returnCode field.
	 */
	public void setReturnCode(long returnCode)
	{
		returnCode_ = returnCode;
	}

}
