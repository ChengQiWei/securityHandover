/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.api.structs.tpm;


import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder;
import iaik.tc.utils.misc.Utils;

/**
 * This structure provides a standard method of specifying a list of PCR registers.
 * 
 * @TPM_V1 60
 */
public class TcTpmPcrSelection extends TcCompositeTypeDecoder {

	/**
	 * A bit map that indicates if a PCR is active or not.
	 */
	protected TcBlobData pcrSelect_;


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder()
	 */
	public TcTpmPcrSelection()
	{
		super();
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcBlobData)
	 */
	public TcTpmPcrSelection(TcBlobData data)
	{
		super(data);
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcBlobData,
	 *      int)
	 */
	public TcTpmPcrSelection(TcBlobData data, int offset)
	{
		super(data, offset);
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder)
	 */
	public TcTpmPcrSelection(TcCompositeTypeDecoder composite)
	{
		super(composite);
	}


	/*************************************************************************************************
	 * This method decodes the TPM_PCR_SELECTION from the byte blob.
	 */
	protected void decode()
	{
		checkBoundaryPreconditions(2);
		
		int sizeOfSelection = decodeUINT16();
		pcrSelect_ = decodeBytes(sizeOfSelection);
	}


	/*************************************************************************************************
	 * This method encodes the TPM_PCR_SELECTION as a byte blob.
	 */
	public TcBlobData getEncoded()
	{
		TcBlobData retVal = TcBlobData.newUINT16( getSizeOfSelection());
		if (pcrSelect_ != null) {
			retVal.append(pcrSelect_);
		}
		return retVal;
	}


	/*************************************************************************************************
	 * This method returns a String representation of the object.
	 */
	public String toString()
	{
		StringBuffer retVal = new StringBuffer();

		retVal.append("sizeOfSelection: ");
		retVal.append(getSizeOfSelection());
		retVal.append(Utils.getNL());
		retVal.append("pcrSelect: ");
		if (pcrSelect_ != null) {
			retVal.append(pcrSelect_.toHexString());
		}
		retVal.append(Utils.getNL());

		return retVal.toString();
	}


	/*************************************************************************************************
	 * Returns contents of the pcrSelect field.
	 */
	public TcBlobData getPcrSelect()
	{
		return pcrSelect_;
	}


	/*************************************************************************************************
	 * Sets the pcrSelect field.
	 */
	public void setPcrSelect(TcBlobData pcrSelect)
	{
		pcrSelect_ = pcrSelect;
	}


	/*************************************************************************************************
	 * Returns contents of the sizeOfSelection field.
	 */
	public int getSizeOfSelection()
	{
		if (pcrSelect_ == null) {
			return 0;
		} else {
			return pcrSelect_.getLength();
		}
	}

}
