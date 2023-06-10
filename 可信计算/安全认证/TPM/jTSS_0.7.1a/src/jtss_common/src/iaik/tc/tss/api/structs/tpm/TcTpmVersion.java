/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.api.structs.tpm;


import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder;

/**
 * The TPM_VERSION allows the TPM to communicate with outside entities as to the version of the
 * TPM. This structure is set by the TPM and included in structures that are maintained long term
 * outside of the TPM.
 * 
 * @TPM_V1 25
 */
public class TcTpmVersion extends TcCompositeTypeDecoder {

	/** This constant can be used for TPM 1.1 version comparisons */
	public static final TcTpmVersion TPM_V1_1 = new TcTpmVersion();

	/** This constant can be used for TPM 1.2 version comparisons */
	public static final TcTpmVersion TPM_V1_2 = new TcTpmVersion();

	static {
		TPM_V1_1.setMajor((short)1);
		TPM_V1_1.setMinor((short)1);

		TPM_V1_2.setMajor((short)1);
		TPM_V1_2.setMinor((short)2);
	}

	
	/**
	 * The major version indicator.
	 */
	protected short major_;

	/**
	 * The minor version indicator.
	 */
	protected short minor_;

	/**
	 * The major revision indicator.
	 */
	protected short revMajor_;

	/**
	 * The minor revision indicator.
	 */
	protected short revMinor_;


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 */
	public TcTpmVersion()
	{
		super();
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 */
	public TcTpmVersion(TcBlobData blob)
	{
		super(blob);
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 */
	public TcTpmVersion(TcBlobData blob, int offset)
	{
		super(blob, offset);
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 */
	public TcTpmVersion(TcCompositeTypeDecoder composite)
	{
		super(composite);
	}


	/*************************************************************************************************
	 * This method decodes the TPM_VERSION from the byte blob.
	 */
	protected void decode()
	{
		checkBoundaryPreconditions(4);

		major_ = decodeByte();
		minor_ = decodeByte();
		revMajor_ = decodeByte();
		revMinor_ = decodeByte();
	}


	/*************************************************************************************************
	 * This method encodes the TPM_VERSION as a byte blob.
	 */
	public TcBlobData getEncoded()
	{
		TcBlobData retVal = TcBlobData.newBYTE(major_);
		retVal.append(TcBlobData.newBYTE(minor_));
		retVal.append(TcBlobData.newBYTE(revMajor_));
		retVal.append(TcBlobData.newBYTE(revMinor_));
		return retVal;
	}


	/*************************************************************************************************
	 * This method returns a String representation of the object.
	 */
	public String toString()
	{
		StringBuffer retVal = new StringBuffer();

		retVal.append(getMajor());
		retVal.append(".");
		retVal.append(getMinor());
		retVal.append(" rev: ");
		retVal.append(getRevMajor());
		retVal.append(".");
		retVal.append(getRevMinor());

		return retVal.toString();
	}


	/*************************************************************************************************
	 * This method returns true if the two major and minor version numbers are equal, false otherwise.
	 * Note: revMinor and revMajor are ignored by this method.
	 */
	public boolean equalsMinMaj(Object obj)
	{
		if (!(obj instanceof TcTpmVersion)) {
			return false;
		}
		
		TcTpmVersion other = (TcTpmVersion)obj;

		if (other.getMajor() != getMajor()) {
			return false;
		}
		if (other.getMinor() != getMinor()) {
			return false;
		}
		
		return true;
	}
	

	/*************************************************************************************************
	 * This method returns true if the tow major and minor revisions numbers are equal, false 
	 * otherwise. Note: minor and major are ignored by this method (only revMinor and revMajor) are
	 * taken into account.
	 */
	public boolean equalsRevMinMaj(Object obj)
	{
		if (!(obj instanceof TcTpmVersion)) {
			return false;
		}
		
		TcTpmVersion other = (TcTpmVersion)obj;

		if (other.getRevMajor() != getRevMajor()) {
			return false;
		}
		if (other.getRevMinor() != getRevMinor()) {
			return false;
		}
		
		return true;
	}

	
	/*************************************************************************************************
	 * Returns contents of the major field.
	 */
	public short getMajor()
	{
		return major_;
	}


	/*************************************************************************************************
	 * Sets the major field.
	 */
	public void setMajor(short major)
	{
		major_ = major;
	}


	/*************************************************************************************************
	 * Returns contents of the minor field.
	 */
	public short getMinor()
	{
		return minor_;
	}


	/*************************************************************************************************
	 * Sets the minor field.
	 */
	public void setMinor(short minor)
	{
		minor_ = minor;
	}


	/*************************************************************************************************
	 * Returns contents of the revMajor field.
	 */
	public short getRevMajor()
	{
		return revMajor_;
	}


	/*************************************************************************************************
	 * Sets the revMajor field.
	 */
	public void setRevMajor(short revMajor)
	{
		revMajor_ = revMajor;
	}


	/*************************************************************************************************
	 * Returns contents of the revMinor field.
	 */
	public short getRevMinor()
	{
		return revMinor_;
	}


	/*************************************************************************************************
	 * Sets the revMinor field.
	 */
	public void setRevMinor(short revMinor)
	{
		revMinor_ = revMinor;
	}
}
