/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.api.structs.tpm;


import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder;
import iaik.tc.utils.misc.Utils;
import java.math.BigInteger;

public class TcTpmCurrentTicks extends TcCompositeTypeDecoder {
	protected int tag_;

	protected BigInteger currentTicks_; // UINT64 - use BigInteger?

	protected int tickRate_;

	protected TcTpmNonce tickNonce_;


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder()
	 */
	public TcTpmCurrentTicks()
	{
		super();
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcBlobData)
	 */
	public TcTpmCurrentTicks(TcBlobData data)
	{
		super(data);
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcBlobData,
	 *      int)
	 */
	public TcTpmCurrentTicks(TcBlobData data, int offset)
	{
		super(data, offset);
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder)
	 */
	public TcTpmCurrentTicks(TcCompositeTypeDecoder composite)
	{
		super(composite);
	}


	/*************************************************************************************************
	 * This method decodes the TPM_CURRENT_TICKS from the byte blob.
	 */
	protected void decode()
	{
		checkBoundaryPreconditions(2 + 8 + 2 + 20);

		tag_ = decodeUINT16();
		currentTicks_ = decodeUINT64(); //fixxxme64
		tickRate_ = decodeUINT16();
		tickNonce_ = new TcTpmNonce(this);

	}


	/*************************************************************************************************
	 * This method encodes the TPM_CURRENT_TICKS as a byte blob.
	 */
	public TcBlobData getEncoded()
	{
		TcBlobData retVal = TcBlobData.newUINT16( tag_);
		retVal.append(TcBlobData.newUINT64( currentTicks_));
		retVal.append(TcBlobData.newUINT16( tickRate_));
		if (tickNonce_ != null) {
			retVal.append(tickNonce_.getEncoded());
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
		retVal.append("currentTicks: ");
		retVal.append(currentTicks_);
		retVal.append(Utils.getNL());
		retVal.append("tickRate: ");
		retVal.append(tickRate_);
		retVal.append(Utils.getNL());
		if (tickNonce_ != null) {
			retVal.append("tickNonce: ");
			retVal.append(tickNonce_.toString());
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
	 * Returns contents of the tickRate field.
	 */
	public int getTickRate()
	{
		return tickRate_;
	}


	/*************************************************************************************************
	 * Sets the tickRate field.
	 */
	public void setTickRate(int tickRate)
	{
		tickRate_ = tickRate;
	}


	/*************************************************************************************************
	 * Returns contents of the tickNonce field.
	 */
	public TcTpmNonce getTickNonce()
	{
		return tickNonce_;
	}


	/*************************************************************************************************
	 * Sets the tickNonce field.
	 */
	public void setTickNonce(TcTpmNonce tickNonce)
	{
		tickNonce_ = tickNonce;
	}

	
	/**
	 * Returns the current ticks value  from the TPM internal tick counter
	 * @return Current value (a TPM UINT64) as BigInteger
	 */
	public BigInteger getCurrentTicks()
	{
		return currentTicks_;
	}

	/*************************************************************************************************
	 * Sets the currentTicks field.
	 */
	public void setCurrentTicks(BigInteger currentTicks)
	{
		currentTicks_ = currentTicks;
	}

}
