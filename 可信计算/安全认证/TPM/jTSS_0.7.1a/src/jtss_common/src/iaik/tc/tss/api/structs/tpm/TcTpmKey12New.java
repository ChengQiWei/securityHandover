/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.api.structs.tpm;

import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder;

/**
 * This class extends TcTpmKey. The only differnece is that both, encData and encDataSize are set
 * to 0 (UINT32). This is a requirement for a new key (i.e. a key to be created inside the TPM). 
 */
public class TcTpmKey12New extends TcTpmKey12 implements TcITpmKeyNew {

	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder()
	 */
	public TcTpmKey12New()
	{
		super();
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcBlobData)
	 */
	public TcTpmKey12New(TcBlobData data)
	{
		super(data);
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcBlobData,
	 *      int)
	 */
	public TcTpmKey12New(TcBlobData data, int offset)
	{
		super(data, offset);
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder)
	 */
	public TcTpmKey12New(TcCompositeTypeDecoder composite)
	{
		super(composite);
	}

	
	/*************************************************************************************************
	 * This method encodes the TPM_KEY12 as a byte blob.
	 */
	public TcBlobData getEncoded()
	{
		TcBlobData retVal = TcBlobData.newUINT16( tag_);
		retVal.append(TcBlobData.newUINT16( fill_));
		retVal.append(TcBlobData.newUINT16( keyUsage_));
		retVal.append(TcBlobData.newUINT32( keyFlags_));
		retVal.append(TcBlobData.newBYTE( authDataUsage_));
		if (algorithmParms_ != null) {
			retVal.append(algorithmParms_.getEncoded());
		}
		retVal.append(TcBlobData.newUINT32(getPcrInfoSize()));
		if (pcrInfo_ != null) {
			retVal.append(pcrInfo_);
		}
		if (pubKey_ != null) {
			retVal.append(pubKey_.getEncoded());
		}

		// both, encDataSize and encData have to be 0 for a new key
		retVal.append(TcBlobData.newUINT32(0));
		retVal.append(TcBlobData.newUINT32(0));

		return retVal;
	}

}
