/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.api.structs.tpm;


import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder;
import iaik.tc.utils.misc.Utils;

public class TcTpmDaaIssuer extends TcCompositeTypeDecoder {
	protected int tag_;

	protected TcTpmDigest DAA_digest_R0_;

	protected TcTpmDigest DAA_digest_R1_;

	protected TcTpmDigest DAA_digest_S0_;

	protected TcTpmDigest DAA_digest_S1_;

	protected TcTpmDigest DAA_digest_n_;

	protected TcTpmDigest DAA_digest_gamma_;

	protected TcBlobData DAA_generic_q_; // 26 bytes


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder()
	 */
	public TcTpmDaaIssuer()
	{
		super();
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcBlobData)
	 */
	public TcTpmDaaIssuer(TcBlobData data)
	{
		super(data);
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcBlobData,
	 *      int)
	 */
	public TcTpmDaaIssuer(TcBlobData data, int offset)
	{
		super(data, offset);
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder)
	 */
	public TcTpmDaaIssuer(TcCompositeTypeDecoder composite)
	{
		super(composite);
	}


	/*************************************************************************************************
	 * This method decodes the TPM_DAA_ISSUER from the byte blob.
	 */
	protected void decode()
	{
		checkBoundaryPreconditions(2 + 6 * 20 + 26);

		tag_ = decodeUINT16();
		DAA_digest_R0_ = new TcTpmDigest(this);
		DAA_digest_R1_ = new TcTpmDigest(this);
		DAA_digest_S0_ = new TcTpmDigest(this);
		DAA_digest_S1_ = new TcTpmDigest(this);
		DAA_digest_n_ = new TcTpmDigest(this);
		DAA_digest_gamma_ = new TcTpmDigest(this);
		DAA_generic_q_ = decodeBytes(26);

	}


	/*************************************************************************************************
	 * This method encodes the TPM_DAA_ISSUER as a byte blob.
	 */
	public TcBlobData getEncoded()
	{
		TcBlobData retVal = TcBlobData.newUINT16( tag_);
		if (DAA_digest_R0_ != null) {
			retVal.append(DAA_digest_R0_.getEncoded());
		}
		if (DAA_digest_R1_ != null) {
			retVal.append(DAA_digest_R1_.getEncoded());
		}
		if (DAA_digest_S0_ != null) {
			retVal.append(DAA_digest_S0_.getEncoded());
		}
		if (DAA_digest_S1_ != null) {
			retVal.append(DAA_digest_S1_.getEncoded());
		}
		if (DAA_digest_n_ != null) {
			retVal.append(DAA_digest_n_.getEncoded());
		}
		if (DAA_digest_gamma_ != null) {
			retVal.append(DAA_digest_gamma_.getEncoded());
		}
		if (DAA_generic_q_ != null) {
			retVal.append(DAA_generic_q_);
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
		if (DAA_digest_R0_ != null) {
			retVal.append("DAAdigestR0: ");
			retVal.append(DAA_digest_R0_.toString());
			retVal.append(Utils.getNL());
		}
		if (DAA_digest_R1_ != null) {
			retVal.append("DAAdigestR1: ");
			retVal.append(DAA_digest_R1_.toString());
			retVal.append(Utils.getNL());
		}
		if (DAA_digest_S0_ != null) {
			retVal.append("DAAdigestS0: ");
			retVal.append(DAA_digest_S0_.toString());
			retVal.append(Utils.getNL());
		}
		if (DAA_digest_S1_ != null) {
			retVal.append("DAAdigestS1: ");
			retVal.append(DAA_digest_S1_.toString());
			retVal.append(Utils.getNL());
		}
		if (DAA_digest_n_ != null) {
			retVal.append("DAAdigestn: ");
			retVal.append(DAA_digest_n_.toString());
			retVal.append(Utils.getNL());
		}
		if (DAA_digest_gamma_ != null) {
			retVal.append("DAAdigestgamma: ");
			retVal.append(DAA_digest_gamma_.toString());
			retVal.append(Utils.getNL());
		}
		if (DAA_generic_q_ != null) {
			retVal.append("DAAgenericq  // 26 bytes: ");
			retVal.append(DAA_generic_q_.toHexString());
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
	 * Returns contents of the DAAdigestR0 field.
	 */
	public TcTpmDigest getDAAdigestR0()
	{
		return DAA_digest_R0_;
	}


	/*************************************************************************************************
	 * Sets the DAAdigestR0 field.
	 */
	public void setDAAdigestR0(TcTpmDigest DAAdigestR0)
	{
		DAA_digest_R0_ = DAAdigestR0;
	}


	/*************************************************************************************************
	 * Returns contents of the DAAdigestR1 field.
	 */
	public TcTpmDigest getDAAdigestR1()
	{
		return DAA_digest_R1_;
	}


	/*************************************************************************************************
	 * Sets the DAAdigestR1 field.
	 */
	public void setDAAdigestR1(TcTpmDigest DAAdigestR1)
	{
		DAA_digest_R1_ = DAAdigestR1;
	}


	/*************************************************************************************************
	 * Returns contents of the DAAdigestS0 field.
	 */
	public TcTpmDigest getDAAdigestS0()
	{
		return DAA_digest_S0_;
	}


	/*************************************************************************************************
	 * Sets the DAAdigestS0 field.
	 */
	public void setDAAdigestS0(TcTpmDigest DAAdigestS0)
	{
		DAA_digest_S0_ = DAAdigestS0;
	}


	/*************************************************************************************************
	 * Returns contents of the DAAdigestS1 field.
	 */
	public TcTpmDigest getDAAdigestS1()
	{
		return DAA_digest_S1_;
	}


	/*************************************************************************************************
	 * Sets the DAAdigestS1 field.
	 */
	public void setDAAdigestS1(TcTpmDigest DAAdigestS1)
	{
		DAA_digest_S1_ = DAAdigestS1;
	}


	/*************************************************************************************************
	 * Returns contents of the DAAdigestn field.
	 */
	public TcTpmDigest getDAAdigestn()
	{
		return DAA_digest_n_;
	}


	/*************************************************************************************************
	 * Sets the DAAdigestn field.
	 */
	public void setDAAdigestn(TcTpmDigest DAAdigestn)
	{
		DAA_digest_n_ = DAAdigestn;
	}


	/*************************************************************************************************
	 * Returns contents of the DAAdigestgamma field.
	 */
	public TcTpmDigest getDAAdigestgamma()
	{
		return DAA_digest_gamma_;
	}


	/*************************************************************************************************
	 * Sets the DAAdigestgamma field.
	 */
	public void setDAAdigestgamma(TcTpmDigest DAAdigestgamma)
	{
		DAA_digest_gamma_ = DAAdigestgamma;
	}


	/*************************************************************************************************
	 * Returns contents of the DAAgenericq field.
	 */
	public TcBlobData getDAAgenericq()
	{
		return DAA_generic_q_;
	}


	/*************************************************************************************************
	 * Sets the DAAgenericq field.
	 */
	public void setDAAgenericq(TcBlobData DAAgenericq)
	{
		DAA_generic_q_ = DAAgenericq;
	}

}
