/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.api.structs.tpm;


import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder;
import iaik.tc.utils.misc.Utils;

public class TcTpmDaaJoindata extends TcCompositeTypeDecoder {
	protected TcBlobData DAA_join_u0_; // 128 bytes

	protected TcBlobData DAA_join_u1_; // 138 bytes

	protected TcTpmDigest DAA_digest_n0_;


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder()
	 */
	public TcTpmDaaJoindata()
	{
		super();
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcBlobData)
	 */
	public TcTpmDaaJoindata(TcBlobData data)
	{
		super(data);
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcBlobData,
	 *      int)
	 */
	public TcTpmDaaJoindata(TcBlobData data, int offset)
	{
		super(data, offset);
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder)
	 */
	public TcTpmDaaJoindata(TcCompositeTypeDecoder composite)
	{
		super(composite);
	}


	/*************************************************************************************************
	 * This method decodes the TPM_DAA_JOINDATA from the byte blob.
	 */
	protected void decode()
	{
		checkBoundaryPreconditions(128 + 138 + 20);

		DAA_join_u0_ = decodeBytes(128);
		DAA_join_u1_ = decodeBytes(138);
		DAA_digest_n0_ = new TcTpmDigest(this);

	}


	/*************************************************************************************************
	 * This method encodes the TPM_DAA_JOINDATA as a byte blob.
	 */
	public TcBlobData getEncoded()
	{
		TcBlobData retVal =  null;
		if (DAA_join_u0_ != null) {
			retVal =  (TcBlobData)DAA_join_u0_.clone();
		}
		if (DAA_join_u1_ != null) {
			if (retVal == null) {
				retVal =  (TcBlobData)DAA_join_u1_.clone();
			} else {
				retVal.append(DAA_join_u1_);
			}
		}
		if (DAA_digest_n0_ != null) {
			if (retVal == null) {
				retVal =  DAA_digest_n0_.getEncoded();
			} else {
				retVal.append(DAA_digest_n0_.getEncoded());
			}
		}

		return retVal;
	}


	/*************************************************************************************************
	 * This method returns a String representation of the object.
	 */
	public String toString()
	{
		StringBuffer retVal = new StringBuffer();

		if (DAA_join_u0_ != null) {
			retVal.append("DAAjoinu0  // 128 bytes: ");
			retVal.append(DAA_join_u0_.toHexString());
			retVal.append(Utils.getNL());
		}
		if (DAA_join_u1_ != null) {
			retVal.append("DAAjoinu1  // 138 bytes: ");
			retVal.append(DAA_join_u1_.toHexString());
			retVal.append(Utils.getNL());
		}
		if (DAA_digest_n0_ != null) {
			retVal.append("DAAdigestn0: ");
			retVal.append(DAA_digest_n0_.toString());
			retVal.append(Utils.getNL());
		}

		return retVal.toString();
	}


	/*************************************************************************************************
	 * Returns contents of the DAAjoinu0 field.
	 */
	public TcBlobData getDAAjoinu0()
	{
		return DAA_join_u0_;
	}


	/*************************************************************************************************
	 * Sets the DAAjoinu0 field.
	 */
	public void setDAAjoinu0(TcBlobData DAAjoinu0)
	{
		DAA_join_u0_ = DAAjoinu0;
	}


	/*************************************************************************************************
	 * Returns contents of the DAAjoinu1 field.
	 */
	public TcBlobData getDAAjoinu1()
	{
		return DAA_join_u1_;
	}


	/*************************************************************************************************
	 * Sets the DAAjoinu1 field.
	 */
	public void setDAAjoinu1(TcBlobData DAAjoinu1)
	{
		DAA_join_u1_ = DAAjoinu1;
	}


	/*************************************************************************************************
	 * Returns contents of the DAAdigestn0 field.
	 */
	public TcTpmDigest getDAAdigestn0()
	{
		return DAA_digest_n0_;
	}


	/*************************************************************************************************
	 * Sets the DAAdigestn0 field.
	 */
	public void setDAAdigestn0(TcTpmDigest DAAdigestn0)
	{
		DAA_digest_n0_ = DAAdigestn0;
	}

}
