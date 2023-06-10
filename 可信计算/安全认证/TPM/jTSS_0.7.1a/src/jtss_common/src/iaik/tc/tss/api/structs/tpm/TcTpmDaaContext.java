/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.api.structs.tpm;


import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder;
import iaik.tc.utils.misc.Utils;

public class TcTpmDaaContext extends TcCompositeTypeDecoder {
	protected int tag_;

	protected TcTpmDigest DAA_digestContext_;

	protected TcTpmDigest DAA_digest_;

	protected TcTpmNonce DAA_contextSeed_;

	protected TcBlobData DAA_scratch_; // 256 bytes

	protected short DAA_stage_;


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder()
	 */
	public TcTpmDaaContext()
	{
		super();
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcBlobData)
	 */
	public TcTpmDaaContext(TcBlobData data)
	{
		super(data);
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcBlobData,
	 *      int)
	 */
	public TcTpmDaaContext(TcBlobData data, int offset)
	{
		super(data, offset);
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder)
	 */
	public TcTpmDaaContext(TcCompositeTypeDecoder composite)
	{
		super(composite);
	}


	/*************************************************************************************************
	 * This method decodes the TPM_DAA_CONTEXT from the byte blob.
	 */
	protected void decode()
	{
		checkBoundaryPreconditions(2 + 20 + 20 + 20 + 256 + 1);

		tag_ = decodeUINT16();
		DAA_digestContext_ = new TcTpmDigest(this);
		DAA_digest_ = new TcTpmDigest(this);
		DAA_contextSeed_ = new TcTpmNonce(this);
		DAA_scratch_ = decodeBytes(256);
		DAA_stage_ = decodeByte();

	}


	/*************************************************************************************************
	 * This method encodes the TPM_DAA_CONTEXT as a byte blob.
	 */
	public TcBlobData getEncoded()
	{
		TcBlobData retVal = TcBlobData.newUINT16( tag_);
		if (DAA_digestContext_ != null) {
			retVal.append(DAA_digestContext_.getEncoded());
		}
		if (DAA_digest_ != null) {
			retVal.append(DAA_digest_.getEncoded());
		}
		if (DAA_contextSeed_ != null) {
			retVal.append(DAA_contextSeed_.getEncoded());
		}
		if (DAA_scratch_ != null) {
			retVal.append(DAA_scratch_);
		}
		retVal.append(TcBlobData.newBYTE( DAA_stage_));

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
		if (DAA_digestContext_ != null) {
			retVal.append("DAAdigestContext: ");
			retVal.append(DAA_digestContext_.toString());
			retVal.append(Utils.getNL());
		}
		if (DAA_digest_ != null) {
			retVal.append("DAAdigest: ");
			retVal.append(DAA_digest_.toString());
			retVal.append(Utils.getNL());
		}
		if (DAA_contextSeed_ != null) {
			retVal.append("DAAcontextSeed: ");
			retVal.append(DAA_contextSeed_.toString());
			retVal.append(Utils.getNL());
		}
		if (DAA_scratch_ != null) {
			retVal.append("DAAscratch: ");
			retVal.append(DAA_scratch_.toHexString());
			retVal.append(Utils.getNL());
		}
		retVal.append("DAAstage: ");
		retVal.append(DAA_stage_);
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
	 * Returns contents of the DAAdigestContext field.
	 */
	public TcTpmDigest getDAAdigestContext()
	{
		return DAA_digestContext_;
	}


	/*************************************************************************************************
	 * Sets the DAAdigestContext field.
	 */
	public void setDAAdigestContext(TcTpmDigest DAAdigestContext)
	{
		DAA_digestContext_ = DAAdigestContext;
	}


	/*************************************************************************************************
	 * Returns contents of the DAAdigest field.
	 */
	public TcTpmDigest getDAAdigest()
	{
		return DAA_digest_;
	}


	/*************************************************************************************************
	 * Sets the DAAdigest field.
	 */
	public void setDAAdigest(TcTpmDigest DAAdigest)
	{
		DAA_digest_ = DAAdigest;
	}


	/*************************************************************************************************
	 * Returns contents of the DAAcontextSeed field.
	 */
	public TcTpmNonce getDAAcontextSeed()
	{
		return DAA_contextSeed_;
	}


	/*************************************************************************************************
	 * Sets the DAAcontextSeed field.
	 */
	public void setDAAcontextSeed(TcTpmNonce DAAcontextSeed)
	{
		DAA_contextSeed_ = DAAcontextSeed;
	}


	/*************************************************************************************************
	 * Returns contents of the DAAscratch field.
	 */
	public TcBlobData getDAAscratch()
	{
		return DAA_scratch_;
	}


	/*************************************************************************************************
	 * Sets the DAAscratch field.
	 */
	public void setDAAscratch(TcBlobData DAAscratch)
	{
		DAA_scratch_ = DAAscratch;
	}


	/*************************************************************************************************
	 * Returns contents of the DAAstage field.
	 */
	public short getDAAstage()
	{
		return DAA_stage_;
	}


	/*************************************************************************************************
	 * Sets the DAAstage field.
	 */
	public void setDAAstage(short DAAstage)
	{
		DAA_stage_ = DAAstage;
	}

}
