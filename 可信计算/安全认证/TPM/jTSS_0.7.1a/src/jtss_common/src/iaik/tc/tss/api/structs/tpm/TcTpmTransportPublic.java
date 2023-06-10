/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.api.structs.tpm;


import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder;
import iaik.tc.utils.misc.Utils;

public class TcTpmTransportPublic extends TcCompositeTypeDecoder {
	protected int tag_;

	protected long transAttributes_;

	protected long algId_;

	protected int encScheme_;


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder()
	 */
	public TcTpmTransportPublic()
	{
		super();
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcBlobData)
	 */
	public TcTpmTransportPublic(TcBlobData data)
	{
		super(data);
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcBlobData,
	 *      int)
	 */
	public TcTpmTransportPublic(TcBlobData data, int offset)
	{
		super(data, offset);
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder)
	 */
	public TcTpmTransportPublic(TcCompositeTypeDecoder composite)
	{
		super(composite);
	}


	/*************************************************************************************************
	 * This method decodes the TPM_TRANSPORT_PUBLIC from the byte blob.
	 */
	protected void decode()
	{
		checkBoundaryPreconditions(2 + 4 + 4 + 2);

		tag_ = decodeUINT16();
		transAttributes_ = decodeUINT32();
		algId_ = decodeUINT32();
		encScheme_ = decodeUINT16();

	}


	/*************************************************************************************************
	 * This method encodes the TPM_TRANSPORT_PUBLIC as a byte blob.
	 */
	public TcBlobData getEncoded()
	{
		TcBlobData retVal = TcBlobData.newUINT16( tag_);
		retVal.append(TcBlobData.newUINT32( transAttributes_));
		retVal.append(TcBlobData.newUINT32( algId_));
		retVal.append(TcBlobData.newUINT16( encScheme_));

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
		retVal.append("transAttributes: ");
		retVal.append(transAttributes_);
		retVal.append(Utils.getNL());
		retVal.append("algId: ");
		retVal.append(algId_);
		retVal.append(Utils.getNL());
		retVal.append("encScheme: ");
		retVal.append(encScheme_);
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
	 * Returns contents of the transAttributes field.
	 */
	public long getTransAttributes()
	{
		return transAttributes_;
	}


	/*************************************************************************************************
	 * Sets the transAttributes field.
	 */
	public void setTransAttributes(long transAttributes)
	{
		transAttributes_ = transAttributes;
	}


	/*************************************************************************************************
	 * Returns contents of the algId field.
	 */
	public long getAlgId()
	{
		return algId_;
	}


	/*************************************************************************************************
	 * Sets the algId field.
	 */
	public void setAlgId(long algId)
	{
		algId_ = algId;
	}


	/*************************************************************************************************
	 * Returns contents of the encScheme field.
	 */
	public int getEncScheme()
	{
		return encScheme_;
	}


	/*************************************************************************************************
	 * Sets the encScheme field.
	 */
	public void setEncScheme(int encScheme)
	{
		encScheme_ = encScheme;
	}

}
