/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.api.structs.tpm;


import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder;
import iaik.tc.utils.misc.Utils;

public class TcTpmDaaTpm extends TcCompositeTypeDecoder {
	protected int tag_;

	protected TcTpmDigest DAA_digestIssuer_;

	protected TcTpmDigest DAA_digest_v0_;

	protected TcTpmDigest DAA_digest_v1_;

	protected TcTpmDigest DAA_rekey_;

	protected long DAA_count_;


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder()
	 */
	public TcTpmDaaTpm()
	{
		super();
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcBlobData)
	 */
	public TcTpmDaaTpm(TcBlobData data)
	{
		super(data);
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcBlobData,
	 *      int)
	 */
	public TcTpmDaaTpm(TcBlobData data, int offset)
	{
		super(data, offset);
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder)
	 */
	public TcTpmDaaTpm(TcCompositeTypeDecoder composite)
	{
		super(composite);
	}


	/*************************************************************************************************
	 * This method decodes the TPM_DAA_TPM from the byte blob.
	 */
	protected void decode()
	{
		checkBoundaryPreconditions(2 + 4 * 20 + 4);

		tag_ = decodeUINT16();
		DAA_digestIssuer_ = new TcTpmDigest(this);
		DAA_digest_v0_ = new TcTpmDigest(this);
		DAA_digest_v1_ = new TcTpmDigest(this);
		DAA_rekey_ = new TcTpmDigest(this);
		DAA_count_ = decodeUINT32();

	}


	/*************************************************************************************************
	 * This method encodes the TPM_DAA_TPM as a byte blob.
	 */
	public TcBlobData getEncoded()
	{
		TcBlobData retVal = TcBlobData.newUINT16( tag_);
		if (DAA_digestIssuer_ != null) {
			retVal.append(DAA_digestIssuer_.getEncoded());
		}
		if (DAA_digest_v0_ != null) {
			retVal.append(DAA_digest_v0_.getEncoded());
		}
		if (DAA_digest_v1_ != null) {
			retVal.append(DAA_digest_v1_.getEncoded());
		}
		if (DAA_rekey_ != null) {
			retVal.append(DAA_rekey_.getEncoded());
		}
		retVal.append(TcBlobData.newUINT32( DAA_count_));

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
		if (DAA_digestIssuer_ != null) {
			retVal.append("DAAdigestIssuer: ");
			retVal.append(DAA_digestIssuer_.toString());
			retVal.append(Utils.getNL());
		}
		if (DAA_digest_v0_ != null) {
			retVal.append("DAAdigestv0: ");
			retVal.append(DAA_digest_v0_.toString());
			retVal.append(Utils.getNL());
		}
		if (DAA_digest_v1_ != null) {
			retVal.append("DAAdigestv1: ");
			retVal.append(DAA_digest_v1_.toString());
			retVal.append(Utils.getNL());
		}
		if (DAA_rekey_ != null) {
			retVal.append("DAArekey: ");
			retVal.append(DAA_rekey_.toString());
			retVal.append(Utils.getNL());
		}
		retVal.append("DAAcount: ");
		retVal.append(DAA_count_);
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
	 * Returns contents of the DAAdigestIssuer field.
	 */
	public TcTpmDigest getDAAdigestIssuer()
	{
		return DAA_digestIssuer_;
	}


	/*************************************************************************************************
	 * Sets the DAAdigestIssuer field.
	 */
	public void setDAAdigestIssuer(TcTpmDigest DAAdigestIssuer)
	{
		DAA_digestIssuer_ = DAAdigestIssuer;
	}


	/*************************************************************************************************
	 * Returns contents of the DAAdigestv0 field.
	 */
	public TcTpmDigest getDAAdigestv0()
	{
		return DAA_digest_v0_;
	}


	/*************************************************************************************************
	 * Sets the DAAdigestv0 field.
	 */
	public void setDAAdigestv0(TcTpmDigest DAAdigestv0)
	{
		DAA_digest_v0_ = DAAdigestv0;
	}


	/*************************************************************************************************
	 * Returns contents of the DAAdigestv1 field.
	 */
	public TcTpmDigest getDAAdigestv1()
	{
		return DAA_digest_v1_;
	}


	/*************************************************************************************************
	 * Sets the DAAdigestv1 field.
	 */
	public void setDAAdigestv1(TcTpmDigest DAAdigestv1)
	{
		DAA_digest_v1_ = DAAdigestv1;
	}


	/*************************************************************************************************
	 * Returns contents of the DAArekey field.
	 */
	public TcTpmDigest getDAArekey()
	{
		return DAA_rekey_;
	}


	/*************************************************************************************************
	 * Sets the DAArekey field.
	 */
	public void setDAArekey(TcTpmDigest DAArekey)
	{
		DAA_rekey_ = DAArekey;
	}


	/*************************************************************************************************
	 * Returns contents of the DAAcount field.
	 */
	public long getDAAcount()
	{
		return DAA_count_;
	}


	/*************************************************************************************************
	 * Sets the DAAcount field.
	 */
	public void setDAAcount(long DAAcount)
	{
		DAA_count_ = DAAcount;
	}

}
