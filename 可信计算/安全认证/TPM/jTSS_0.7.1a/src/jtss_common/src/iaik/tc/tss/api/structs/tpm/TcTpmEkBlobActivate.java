/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.api.structs.tpm;


import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder;
import iaik.tc.utils.misc.Utils;

public class TcTpmEkBlobActivate extends TcCompositeTypeDecoder {
	protected int tag_;

	protected TcTpmSymmetricKey sessionKey_;

	protected TcTpmDigest idDigest_;

	protected TcTpmPcrInfoShort pcrInfo_;


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder()
	 */
	public TcTpmEkBlobActivate()
	{
		super();
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcBlobData)
	 */
	public TcTpmEkBlobActivate(TcBlobData data)
	{
		super(data);
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcBlobData,
	 *      int)
	 */
	public TcTpmEkBlobActivate(TcBlobData data, int offset)
	{
		super(data, offset);
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder)
	 */
	public TcTpmEkBlobActivate(TcCompositeTypeDecoder composite)
	{
		super(composite);
	}


	/*************************************************************************************************
	 * This method decodes the TPM_EK_BLOB_ACTIVATE from the byte blob.
	 */
	protected void decode()
	{
		checkBoundaryPreconditions(2 + 8 + 20 + 23);

		tag_ = decodeUINT16();
		sessionKey_ = new TcTpmSymmetricKey(this);
		idDigest_ = new TcTpmDigest(this);
		pcrInfo_ = new TcTpmPcrInfoShort(this);

	}


	/*************************************************************************************************
	 * This method encodes the TPM_EK_BLOB_ACTIVATE as a byte blob.
	 */
	public TcBlobData getEncoded()
	{
		TcBlobData retVal = TcBlobData.newUINT16( tag_);
		if (sessionKey_ != null) {
			retVal.append(sessionKey_.getEncoded());
		}
		if (idDigest_ != null) {
			retVal.append(idDigest_.getEncoded());
		}
		if (pcrInfo_ != null) {
			retVal.append(pcrInfo_.getEncoded());
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
		if (sessionKey_ != null) {
			retVal.append("sessionKey: ");
			retVal.append(sessionKey_.toString());
			retVal.append(Utils.getNL());
		}
		if (idDigest_ != null) {
			retVal.append("idDigest: ");
			retVal.append(idDigest_.toString());
			retVal.append(Utils.getNL());
		}
		if (pcrInfo_ != null) {
			retVal.append("pcrInfo: ");
			retVal.append(pcrInfo_.toString());
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
	 * Returns contents of the sessionKey field.
	 */
	public TcTpmSymmetricKey getSessionKey()
	{
		return sessionKey_;
	}


	/*************************************************************************************************
	 * Sets the sessionKey field.
	 */
	public void setSessionKey(TcTpmSymmetricKey sessionKey)
	{
		sessionKey_ = sessionKey;
	}


	/*************************************************************************************************
	 * Returns contents of the idDigest field.
	 */
	public TcTpmDigest getIdDigest()
	{
		return idDigest_;
	}


	/*************************************************************************************************
	 * Sets the idDigest field.
	 */
	public void setIdDigest(TcTpmDigest idDigest)
	{
		idDigest_ = idDigest;
	}


	/*************************************************************************************************
	 * Returns contents of the pcrInfo field.
	 */
	public TcTpmPcrInfoShort getPcrInfo()
	{
		return pcrInfo_;
	}


	/*************************************************************************************************
	 * Sets the pcrInfo field.
	 */
	public void setPcrInfo(TcTpmPcrInfoShort pcrInfo)
	{
		pcrInfo_ = pcrInfo;
	}

}
