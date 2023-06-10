/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.api.structs.tpm;


import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder;
import iaik.tc.utils.misc.Utils;

public class TcTpmTransportLogOut extends TcCompositeTypeDecoder {
	protected int tag_;

	protected TcTpmCurrentTicks currentTicks_;

	protected TcTpmDigest parameters_;

	protected long locality_;


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder()
	 */
	public TcTpmTransportLogOut()
	{
		super();
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcBlobData)
	 */
	public TcTpmTransportLogOut(TcBlobData data)
	{
		super(data);
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcBlobData,
	 *      int)
	 */
	public TcTpmTransportLogOut(TcBlobData data, int offset)
	{
		super(data, offset);
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder)
	 */
	public TcTpmTransportLogOut(TcCompositeTypeDecoder composite)
	{
		super(composite);
	}


	/*************************************************************************************************
	 * This method decodes the TPM_TRANSPORT_LOG_OUT from the byte blob.
	 */
	protected void decode()
	{
		checkBoundaryPreconditions(2 + 28 + 20 + 4);

		tag_ = decodeUINT16();
		currentTicks_ = new TcTpmCurrentTicks(this);
		parameters_ = new TcTpmDigest(this);
		locality_ = decodeUINT32();

	}


	/*************************************************************************************************
	 * This method encodes the TPM_TRANSPORT_LOG_OUT as a byte blob.
	 */
	public TcBlobData getEncoded()
	{
		TcBlobData retVal = TcBlobData.newUINT16( tag_);
		if (currentTicks_ != null) {
			retVal.append(currentTicks_.getEncoded());
		}
		if (parameters_ != null) {
			retVal.append(parameters_.getEncoded());
		}
		retVal.append(TcBlobData.newUINT32( locality_));

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
		if (currentTicks_ != null) {
			retVal.append("currentTicks: ");
			retVal.append(currentTicks_.toString());
			retVal.append(Utils.getNL());
		}
		if (parameters_ != null) {
			retVal.append("parameters: ");
			retVal.append(parameters_.toString());
			retVal.append(Utils.getNL());
		}
		retVal.append("locality: ");
		retVal.append(locality_);
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
	 * Returns contents of the currentTicks field.
	 */
	public TcTpmCurrentTicks getCurrentTicks()
	{
		return currentTicks_;
	}


	/*************************************************************************************************
	 * Sets the currentTicks field.
	 */
	public void setCurrentTicks(TcTpmCurrentTicks currentTicks)
	{
		currentTicks_ = currentTicks;
	}


	/*************************************************************************************************
	 * Returns contents of the parameters field.
	 */
	public TcTpmDigest getParameters()
	{
		return parameters_;
	}


	/*************************************************************************************************
	 * Sets the parameters field.
	 */
	public void setParameters(TcTpmDigest parameters)
	{
		parameters_ = parameters;
	}


	/*************************************************************************************************
	 * Returns contents of the locality field.
	 */
	public long getLocality()
	{
		return locality_;
	}


	/*************************************************************************************************
	 * Sets the locality field.
	 */
	public void setLocality(long locality)
	{
		locality_ = locality;
	}

}
