/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.api.structs.tsp;


/***************************************************************************************************
 * This structure allows the TSS Service Provider to communicate with outside entities as to the
 * version of the TPM, TSS Core Service or TSS ServiceProvider.
 * 
 * @TSS_V1 45
 * 
 * @TSS_1_2_EA 102
 */
public class TcTssVersion {

	/** This constant can be used for TPM 1.1 version comparisons */
	public static final TcTssVersion TPM_V1_1 = new TcTssVersion();

	/** This constant can be used for TPM 1.2 version comparisons */
	public static final TcTssVersion TPM_V1_2 = new TcTssVersion();

	static {
		TPM_V1_1.setMajor((short) 1);
		TPM_V1_1.setMinor((short) 1);

		TPM_V1_2.setMajor((short) 1);
		TPM_V1_2.setMinor((short) 2);
	}

	/**
	 * The major version indicator for the implementation of the TSS. For version 1 this must be 0x01.
	 */
	protected short major_; // BYTE

	/**
	 * The minor version indicator for the implementation of the TSS. For version 1.1b this must be
	 * 0x01, for version 1.2 this must be 0x02.
	 */
	protected short minor_; // BYTE

	/**
	 * The major vendor version indicator. The value is left to the TSS vendor to determine.
	 */
	protected short revMajor_; // BYTE

	/**
	 * The minor vendor version indicator. The value is left to the TSS vendor to determine.
	 */
	protected short revMinor_; // BYTE


	/*************************************************************************************************
	 * Default constructor.
	 */
	public TcTssVersion()
	{
	}


	/*************************************************************************************************
	 * Initialization method taking and setting all parameters at once.
	 */
	public TcTssVersion init(final short major, final short minor, final short revMajor,
			final short revMinor)
	{
		major_ = major;
		minor_ = minor;
		revMajor_ = revMajor;
		revMinor_ = revMinor;

		return this;
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
	public void setMajor(final short major)
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
	public void setMinor(final short minor)
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
	public void setRevMajor(final short revMajor)
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
	public void setRevMinor(final short revMinor)
	{
		revMinor_ = revMinor;
	}


	/*************************************************************************************************
	 * This method returns true if the two version numbers are equal, false otherwise.
	 */
	public boolean equals(Object obj)
	{
		return equalsMinMaj(obj) && equalsRevMinMaj(obj);
	}


	/*************************************************************************************************
	 * This method returns true if the two major and minor version numbers are equal, false otherwise.
	 * Note: revMinor and revMajor are ignored by this method.
	 */
	public boolean equalsMinMaj(Object obj)
	{
		if (!(obj instanceof TcTssVersion)) {
			return false;
		}

		TcTssVersion other = (TcTssVersion) obj;

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
		if (!(obj instanceof TcTssVersion)) {
			return false;
		}

		TcTssVersion other = (TcTssVersion) obj;

		if (other.getRevMajor() != getRevMajor()) {
			return false;
		}
		if (other.getRevMinor() != getRevMinor()) {
			return false;
		}

		return true;
	}


	/*************************************************************************************************
	 * Returns a String representation of the object.
	 */
	public String toString()
	{
		StringBuffer retVal = new StringBuffer();
		retVal.append("Version: ");
		retVal.append(getMajor());
		retVal.append(".");
		retVal.append(getMinor());
		retVal.append(".");
		retVal.append(getRevMajor());
		retVal.append(".");
		retVal.append(getRevMinor());
		return retVal.toString();
	}

}
