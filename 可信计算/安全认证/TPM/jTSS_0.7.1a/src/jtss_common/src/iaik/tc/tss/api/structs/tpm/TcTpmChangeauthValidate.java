/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.api.structs.tpm;


import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder;
import iaik.tc.utils.misc.Utils;

public class TcTpmChangeauthValidate extends TcCompositeTypeDecoder {
	protected TcTpmSecret newAuthSecret_;

	protected TcTpmNonce n1_;


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder()
	 */
	public TcTpmChangeauthValidate()
	{
		super();
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcBlobData)
	 */
	public TcTpmChangeauthValidate(TcBlobData data)
	{
		super(data);
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcBlobData,
	 *      int)
	 */
	public TcTpmChangeauthValidate(TcBlobData data, int offset)
	{
		super(data, offset);
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder)
	 */
	public TcTpmChangeauthValidate(TcCompositeTypeDecoder composite)
	{
		super(composite);
	}


	/*************************************************************************************************
	 * This method decodes the TPM_CHANGEAUTH_VALIDATE from the byte blob.
	 */
	protected void decode()
	{
		checkBoundaryPreconditions(20 + 20);

		newAuthSecret_ = new TcTpmSecret(this);
		n1_ = new TcTpmNonce(this);

	}


	/*************************************************************************************************
	 * This method encodes the TPM_CHANGEAUTH_VALIDATE as a byte blob.
	 */
	public TcBlobData getEncoded()
	{
		TcBlobData retVal = null;

		if (newAuthSecret_ != null) {
			retVal = TcBlobData.newBlobData(newAuthSecret_.getEncoded());
		}

		if (n1_ != null && retVal != null) {
			retVal.append(n1_.getEncoded());
		}
		if (n1_ != null && retVal == null) {
			retVal = TcBlobData.newBlobData(n1_.getEncoded());
		}

		return retVal;
	}


	/*************************************************************************************************
	 * This method returns a String representation of the object.
	 */
	public String toString()
	{
		StringBuffer retVal = new StringBuffer();

		if (newAuthSecret_ != null) {
			retVal.append("newAuthSecret: ");
			retVal.append(newAuthSecret_.toString());
			retVal.append(Utils.getNL());
		}
		if (n1_ != null) {
			retVal.append("n1: ");
			retVal.append(n1_.toString());
			retVal.append(Utils.getNL());
		}

		return retVal.toString();
	}


	/*************************************************************************************************
	 * Returns contents of the newAuthSecret field.
	 */
	public TcTpmSecret getNewAuthSecret()
	{
		return newAuthSecret_;
	}


	/*************************************************************************************************
	 * Sets the newAuthSecret field.
	 */
	public void setNewAuthSecret(TcTpmSecret newAuthSecret)
	{
		newAuthSecret_ = newAuthSecret;
	}


	/*************************************************************************************************
	 * Returns contents of the n1 field.
	 */
	public TcTpmNonce getN1()
	{
		return n1_;
	}


	/*************************************************************************************************
	 * Sets the n1 field.
	 */
	public void setN1(TcTpmNonce n1)
	{
		n1_ = n1;
	}

}
