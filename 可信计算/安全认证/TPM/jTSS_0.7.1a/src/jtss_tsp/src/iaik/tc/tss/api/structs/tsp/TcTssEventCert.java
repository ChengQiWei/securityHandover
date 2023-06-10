/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.api.structs.tsp;


import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.utils.misc.Utils;

/**
 * This class implements the certificate the be used for events of type TSS_EV_CODE_CERT.
 * 
 * @TSS_1_2_EA 104
 */
public class TcTssEventCert {

	/**
	 * Version data.
	 */
	protected TcTssVersion versionInfo_ = null; // TSS_VERSION

	/**
	 * The hash value of the entire certificate.
	 */
	protected TcBlobData certificateHash_ = null; // BYTE*

	/**
	 * The actual digest of the entity.
	 */
	protected TcBlobData entityDigest_ = null; // BYTE*

	/**
	 * TRUE if the entity logging this event checked the measured value against the digest value in
	 * the certificate. FASLE if no checking was attempted.
	 */
	protected boolean digestChecked_ = false;

	/**
	 * Only valid when digestChecked_ is TRUE. TRUE if measured value matches digest value in
	 * certificate, FALSE otherwise.
	 */
	protected boolean digestVerified_ = false;

	/**
	 * The actual issuer certificate.
	 */
	protected TcBlobData issuer_ = null;


	/*************************************************************************************************
	 * Default constructor.
	 */
	public TcTssEventCert()
	{
	}


	/*************************************************************************************************
	 * This method returns the content of the certificateHash field.
	 */
	public TcBlobData getCertificateHash()
	{
		return certificateHash_;
	}


	/*************************************************************************************************
	 * This method sets the content of the certificateHash field.
	 */
	public void setCertificateHash(TcBlobData certificateHash)
	{
		certificateHash_ = certificateHash;
	}


	/*************************************************************************************************
	 * This method returns the content of the digestChecked field.
	 */
	public boolean isDigestChecked()
	{
		return digestChecked_;
	}


	/*************************************************************************************************
	 * This method sets the content of the digestChecked field.
	 */
	public void setDigestChecked(boolean digestChecked)
	{
		digestChecked_ = digestChecked;
	}


	/*************************************************************************************************
	 * This method returns the content of the digestVerified field.
	 */
	public boolean isDigestVerified()
	{
		return digestVerified_;
	}


	/*************************************************************************************************
	 * This method sets the content of the digestVerified field.
	 */
	public void setDigestVerified(boolean digestVerified)
	{
		digestVerified_ = digestVerified;
	}


	/*************************************************************************************************
	 * This method returns the content of the entityDigest field.
	 */
	public TcBlobData getEntityDigest()
	{
		return entityDigest_;
	}


	/*************************************************************************************************
	 * This method sets the content of the entityDigest field.
	 */
	public void setEntityDigest(TcBlobData entityDigest)
	{
		entityDigest_ = entityDigest;
	}


	/*************************************************************************************************
	 * This method returns the content of the issuer field.
	 */
	public TcBlobData getIssuer()
	{
		return issuer_;
	}


	/*************************************************************************************************
	 * This method sets the content of the issuer field.
	 */
	public void setIssuer(TcBlobData issuer)
	{
		issuer_ = issuer;
	}


	/*************************************************************************************************
	 * This method returns the content of the versionInfo field.
	 */
	public TcTssVersion getVersionInfo()
	{
		return versionInfo_;
	}


	/*************************************************************************************************
	 * This method sets the content of the versionInfo field.
	 */
	public void setVersionInfo(TcTssVersion versionInfo)
	{
		versionInfo_ = versionInfo;
	}


	/*************************************************************************************************
	 * This method returns the length of the certificateHash field.
	 * 
	 * @return The length of the certificateHash field.
	 */
	public long getCertificateHashLength()
	{
		if (certificateHash_ == null) {
			return 0;
		} else {
			return certificateHash_.getLengthAsLong();
		}
	}


	/*************************************************************************************************
	 * This method returns the length of the entityDigest field.
	 * 
	 * @return The length of the entityDigest field.
	 */
	public long getEntityDigestLength()
	{
		if (entityDigest_ == null) {
			return 0;
		} else {
			return entityDigest_.getLengthAsLong();
		}
	}


	/*************************************************************************************************
	 * This method returns the length of the issuer field.
	 * 
	 * @return The length of the issuer field.
	 */
	public long getIssuerLength()
	{
		if (issuer_ == null) {
			return 0;
		} else {
			return issuer_.getLengthAsLong();
		}
	}

	
	/*************************************************************************************************
	 * This method returns a String representation of the object.
	 */
	public String toString()
	{
		StringBuffer retVal = new StringBuffer();

		if (getVersionInfo() != null) {
			retVal.append(getVersionInfo().toString());
			retVal.append(Utils.getNL());
		}
		
		retVal.append("certificateHash: ");
		if (getCertificateHash() != null) {
			retVal.append(getCertificateHash().toHexString());
		} else {
			retVal.append("not set");
		}
		retVal.append(Utils.getNL());

		retVal.append("entityDigest: ");
		if (getEntityDigest() != null) {
			retVal.append(getEntityDigest().toHexString());
		} else {
			retVal.append("not set");
		}
		retVal.append(Utils.getNL());

		retVal.append("digestChecked: ");
		retVal.append(digestChecked_);
		retVal.append(Utils.getNL());

		retVal.append("digestVerified: ");
		retVal.append(digestVerified_);
		retVal.append(Utils.getNL());

		retVal.append("issuer: ");
		if (getIssuer() != null) {
			retVal.append(getIssuer().toHexString());
		} else {
			retVal.append("not set");
		}
		retVal.append(Utils.getNL());

		return retVal.toString();
	}

}
