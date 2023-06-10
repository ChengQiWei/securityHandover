/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.api.structs.tpm;


import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder;
import iaik.tc.utils.misc.Utils;

/**
 * This class provides a standard mechanism to define the parameters used to generate a key pair, and to
 * store the parts of a key shared between the public and private key parts.
 * 
 * @TPM_V1 50
 */
public class TcTpmKeyParms extends TcCompositeTypeDecoder {

	/**
	 * ID of the key algorithm in use.
	 */
	protected long algorithmID_;

	/**
	 * The encryption scheme that the key uses to encrypt information.
	 */
	protected int encScheme_;

	/**
	 * The signature scheme that the key uses to perform digital signatures.
	 */
	protected int sigScheme_;

	/**
	 * The parameter information dependent upon the key algorithm.
	 */
	protected TcBlobData parms_;


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 */
	public TcTpmKeyParms()
	{
		super();
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 */
	public TcTpmKeyParms(TcBlobData blob)
	{
		super(blob);
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 */
	public TcTpmKeyParms(TcBlobData blob, int offset)
	{
		super(blob, offset);
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 */
	public TcTpmKeyParms(TcCompositeTypeDecoder composite)
	{
		super(composite);
	}


	/*************************************************************************************************
	 * This method decodes the TPM_KEY_PARMS from the byte blob.
	 */
	protected void decode()
	{
		checkBoundaryPreconditions(12);

		algorithmID_ = decodeTpmAlgorithmId();
		encScheme_ = decodeTpmEncScheme();
		sigScheme_ = decodeTpmSigScheme();
		long parmSize = decodeUINT32();
		parms_ = decodeBytes(parmSize);
	}


	/*************************************************************************************************
	 * This method encodes the TPM_KEY_PARMS as a byte blob.
	 */
	public TcBlobData getEncoded()
	{
		TcBlobData retVal = TcBlobData.newUINT32( algorithmID_);
		retVal.append(TcBlobData.newUINT16( encScheme_));
		retVal.append(TcBlobData.newUINT16( sigScheme_));
		retVal.append(TcBlobData.newUINT32( getParmSize()));
		if (parms_ != null) {
			retVal.append(parms_);
		}

		return retVal;
	}


	/*************************************************************************************************
	 * This method returns a String representation of the object.
	 */
	public String toString()
	{
		StringBuffer retVal = new StringBuffer();

		retVal.append("algorithmID: ");
		retVal.append(algorithmID_);
		retVal.append(Utils.getNL());
		retVal.append("encScheme: ");
		retVal.append(encScheme_);
		retVal.append(Utils.getNL());
		retVal.append("sigScheme: ");
		retVal.append(sigScheme_);
		retVal.append(Utils.getNL());
		retVal.append("parmSize: ");
		retVal.append(getParmSize());
		retVal.append(Utils.getNL());
		if (parms_ != null) {
			retVal.append("parms: ");
			retVal.append(parms_.toHexString());
			retVal.append(Utils.getNL());
		}

		return retVal.toString();
	}


	/*************************************************************************************************
	 * Returns contents of the algorithmID field.
	 */
	public long getAlgorithmID()
	{
		return algorithmID_;
	}


	/*************************************************************************************************
	 * Sets the algorithmID field.
	 */
	public void setAlgorithmID(long algorithmID)
	{
		algorithmID_ = algorithmID;
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


	/*************************************************************************************************
	 * Returns contents of the parms field.
	 */
	public TcBlobData getParms()
	{
		return parms_;
	}


	/*************************************************************************************************
	 * Sets the parms field.
	 */
	public void setParms(TcBlobData parms)
	{
		parms_ = parms;
	}


	/*************************************************************************************************
	 * Returns contents of the parmSize field.
	 */
	public long getParmSize()
	{
		if (parms_ == null) {
			return 0;
		} else {
			return parms_.getLengthAsLong();
		}
	}


	/*************************************************************************************************
	 * Returns contents of the sigScheme field.
	 */
	public int getSigScheme()
	{
		return sigScheme_;
	}


	/*************************************************************************************************
	 * Sets the sigScheme field.
	 */
	public void setSigScheme(int sigScheme)
	{
		sigScheme_ = sigScheme;
	}
}
