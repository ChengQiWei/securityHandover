/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.api.structs.tpm;

import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder;

/**
 * This class extends TcTpmKey. The only difference is that both, encData and encDataSize are set
 * to 0 (UINT32). This is a requirement for a new key (i.e. a key to be created inside the TPM). 
 */
public class TcTpmKeyNew extends TcTpmKey implements TcITpmKeyNew {

	/*************************************************************************************************
	 * Constructor - see superclass for details
	 */
	public TcTpmKeyNew()
	{
		super();
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 */
	public TcTpmKeyNew(TcBlobData blob)
	{
		super(blob);
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 */
	public TcTpmKeyNew(TcBlobData blob, int offset)
	{
		super(blob, offset);
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 */
	public TcTpmKeyNew(TcCompositeTypeDecoder composite)
	{
		super(composite);
	}

	
	/*************************************************************************************************
	 * This method encodes the TPM_KEY_PARMS as a byte blob.
	 */
	public TcBlobData getEncoded()
	{
		TcBlobData retVal = null;
		if (ver_ != null) {
			retVal = TcBlobData.newBlobData(ver_.getEncoded());
			retVal.append(TcBlobData.newUINT16( keyUsage_));
		} else {
			retVal = TcBlobData.newUINT16( keyUsage_);
		}
		retVal.append(TcBlobData.newUINT32( keyFlags_));
		retVal.append(TcBlobData.newBYTE( authDataUsage_));
		if (algorithmParms_ != null) {
			retVal.append(algorithmParms_.getEncoded());
		}
		retVal.append(TcBlobData.newUINT32( getPcrInfoSize()));
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
	
	protected void decode()
	{
		checkBoundaryPreconditions(35); // minimum size

		ver_ = new TcTpmStructVer(this);
		keyUsage_ = decodeTpmKeyUsage();
		keyFlags_ = decodeTpmKeyFlags();
		authDataUsage_ = decodeTpmAuthDataUsage();
		algorithmParms_ = new TcTpmKeyParms(this);
		long pcrInfoSize = decodeUINT32();
		pcrInfo_ = decodeBytes(pcrInfoSize);
		pubKey_ = null;
		long encSize = decodeUINT32();
		encData_ = decodeBytes(encSize);
	}


}
