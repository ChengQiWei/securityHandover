/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.api.structs.tpm;


import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder;
import iaik.tc.utils.misc.Utils;

public class TcTpmPcrAttributes extends TcCompositeTypeDecoder {
	protected short pcrReset_;

	protected short pcrExtendLocal_;

	protected short pcrResetLocal_;


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder()
	 */
	public TcTpmPcrAttributes()
	{
		super();
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcBlobData)
	 */
	public TcTpmPcrAttributes(TcBlobData data)
	{
		super(data);
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcBlobData,
	 *      int)
	 */
	public TcTpmPcrAttributes(TcBlobData data, int offset)
	{
		super(data, offset);
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder)
	 */
	public TcTpmPcrAttributes(TcCompositeTypeDecoder composite)
	{
		super(composite);
	}


	/*************************************************************************************************
	 * This method decodes the TPM_PCR_ATTRIBUTES from the byte blob.
	 */
	protected void decode()
	{
		checkBoundaryPreconditions(3);

		pcrReset_ = decodeByte();
		pcrExtendLocal_ = decodeByte();
		pcrResetLocal_ = decodeByte();
	}


	/*************************************************************************************************
	 * This method encodes the TPM_PCR_ATTRIBUTES as a byte blob.
	 */
	public TcBlobData getEncoded()
	{
		TcBlobData retVal = TcBlobData.newBYTE( pcrReset_);
		retVal.append(TcBlobData.newBYTE( pcrExtendLocal_));
		retVal.append(TcBlobData.newBYTE( pcrResetLocal_));

		return retVal;
	}


	/*************************************************************************************************
	 * This method returns a String representation of the object.
	 */
	public String toString()
	{
		StringBuffer retVal = new StringBuffer();

		retVal.append("pcrReset: ");
		retVal.append(pcrReset_);
		retVal.append(Utils.getNL());
		retVal.append("pcrExtendLocal: ");
		retVal.append(pcrExtendLocal_);
		retVal.append(Utils.getNL());
		retVal.append("pcrResetLocal: ");
		retVal.append(pcrResetLocal_);
		retVal.append(Utils.getNL());

		return retVal.toString();
	}


	/*************************************************************************************************
	 * Returns contents of the pcrReset field.
	 */
	public short getPcrReset()
	{
		return pcrReset_;
	}


	/*************************************************************************************************
	 * Sets the pcrReset field.
	 */
	public void setPcrReset(short pcrReset)
	{
		pcrReset_ = pcrReset;
	}


	/*************************************************************************************************
	 * Returns contents of the pcrExtendLocal field.
	 */
	public short getPcrExtendLocal()
	{
		return pcrExtendLocal_;
	}


	/*************************************************************************************************
	 * Sets the pcrExtendLocal field.
	 */
	public void setPcrExtendLocal(short pcrExtendLocal)
	{
		pcrExtendLocal_ = pcrExtendLocal;
	}


	/*************************************************************************************************
	 * Returns contents of the pcrResetLocal field.
	 */
	public short getPcrResetLocal()
	{
		return pcrResetLocal_;
	}


	/*************************************************************************************************
	 * Sets the pcrResetLocal field.
	 */
	public void setPcrResetLocal(short pcrResetLocal)
	{
		pcrResetLocal_ = pcrResetLocal;
	}

}
