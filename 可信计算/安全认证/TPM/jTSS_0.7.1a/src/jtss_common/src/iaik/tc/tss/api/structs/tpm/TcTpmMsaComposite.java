/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.api.structs.tpm;


import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder;
import iaik.tc.utils.misc.Utils;

public class TcTpmMsaComposite extends TcCompositeTypeDecoder {
	protected long msaList_;

	protected TcTpmDigest[] migAuthDigest_;


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder()
	 */
	public TcTpmMsaComposite()
	{
		super();
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcBlobData)
	 */
	public TcTpmMsaComposite(TcBlobData data)
	{
		super(data);
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcBlobData,
	 *      int)
	 */
	public TcTpmMsaComposite(TcBlobData data, int offset)
	{
		super(data, offset);
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder)
	 */
	public TcTpmMsaComposite(TcCompositeTypeDecoder composite)
	{
		super(composite);
	}


	/*************************************************************************************************
	 * This method decodes the TPM_MSA_COMPOSITE from the byte blob.
	 */
	protected void decode()
	{
		checkBoundaryPreconditions(4);

		msaList_ = decodeUINT32();
		if (msaList_ > 0) {
			migAuthDigest_ = new TcTpmDigest[(int) msaList_];
			for (int i = 0; i < msaList_; i++) {
				migAuthDigest_[i] = new TcTpmDigest(this);
			}
		}

	}


	/*************************************************************************************************
	 * This method encodes the TPM_MSA_COMPOSITE as a byte blob.
	 */
	/*************************************************************************************************
	 * This method encodes the TPM_MSA_COMPOSITE as a byte blob.
	 */
	public TcBlobData getEncoded()
	{
		TcBlobData retVal = TcBlobData.newUINT32( msaList_);
		for (int i = 0; i < msaList_; i++) {
			retVal.append(migAuthDigest_[i].getEncoded());
		}

		return retVal;
	}


	/*************************************************************************************************
	 * This method returns a String representation of the object.
	 */
	/*************************************************************************************************
	 * This method returns a String representation of the object.
	 */
	public String toString()
	{
		StringBuffer retVal = new StringBuffer();

		retVal.append("MSAlist: ");
		retVal.append(msaList_);
		retVal.append(Utils.getNL());
		if (migAuthDigest_ != null) {
			retVal.append("*migAuthDigest: ");
			for (int i = 0; i < msaList_; i++) {
				retVal.append(migAuthDigest_[i].toString());
			}
			retVal.append(Utils.getNL());
		}

		return retVal.toString();
	}


	/*************************************************************************************************
	 * Returns contents of the msaList field.
	 */
	public long getMsaList()
	{
		return msaList_;
	}


	/*************************************************************************************************
	 * Sets the msaList field.
	 */
	public void setMsaList(long msaList)
	{
		msaList_ = msaList;
	}


	/*************************************************************************************************
	 * Returns contents of the migAuthDigest field.
	 */
	public TcTpmDigest[] getMigAuthDigest()
	{
		return migAuthDigest_;
	}


	/*************************************************************************************************
	 * Sets the migAuthDigest field.
	 */
	public void setMigAuthDigest(TcTpmDigest[] migAuthDigest)
	{
		migAuthDigest_ = migAuthDigest;
	}

}
