/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.api.structs.tsp;


import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.utils.misc.Utils;

/***************************************************************************************************
 * This class provides information about a key registered in the TSS Persistent Storage.
 * 
 * @TSS_V1 49
 * 
 * @TSS_1_2_EA 107
 */
public class TcTssKmKeyinfo {

	/**
	 * Version data.
	 */
	protected TcTssVersion versionInfo_ = null; // TSS_VERSION

	/**
	 * The UUID the key is registered in the persistent storage of the TSS Key Manager.
	 */
	protected TcTssUuid keyUuid_ = null; // TSS_UUID

	/**
	 * The UUID the parent key which wraps the key addressed by keyUUID is registered in the
	 * persistent storage of the TSS Key Manger.
	 */
	protected TcTssUuid parentKeyUuid_ = null; // TSS_UUID

	/**
	 * Flag indicating whether key usage requires authorization or not. Currently the values 0x00 and
	 * 0x01 are defined. The value 0x00 means usage of the key without authorization is permitted. The
	 * value 0x01 means that on each usage of the key the authorization must be performed. All other
	 * values are reserved for future use.
	 */
	protected short authDataUsage_ = 0; // BYTE

	/**
	 * Flag indicating the key is loaded into the TPM. TRUE: Key is loaded into the TPM. FALSE: Key is
	 * not loaded into the TPM.
	 */
	protected boolean isLoaded_ = true; // TSS_BOOL (from tss_structs.h: TRUE: actually loaded in TPM)

	/**
	 * Vendor specific data.
	 */
	protected TcBlobData vendorData_ = null; // may be NULL


	/*************************************************************************************************
	 * Default constructor.
	 */
	public TcTssKmKeyinfo()
	{
	}


	/*************************************************************************************************
	 * Initialization method taking and setting all parameters at once.
	 */
	public TcTssKmKeyinfo init(TcTssVersion versionInfo, TcTssUuid keyUuid, TcTssUuid parentKeyUuid,
			short authDataUsage, boolean isLoaded, TcBlobData vendorData)
	{
		versionInfo_ = versionInfo;
		keyUuid_ = keyUuid;
		parentKeyUuid_ = parentKeyUuid;
		authDataUsage_ = authDataUsage;
		isLoaded_ = isLoaded;
		vendorData_ = vendorData;
		
		return this;
	}


	/*************************************************************************************************
	 * Returns contents of the authDataUsage field.
	 */
	public short getAuthDataUsage()
	{
		return authDataUsage_;
	}


	/*************************************************************************************************
	 * Sets the authDataUsage field.
	 */
	public void setAuthDataUsage(short authDataUsage)
	{
		authDataUsage_ = authDataUsage;
	}


	/*************************************************************************************************
	 * Returns contents of the isLoaded field.
	 */
	public boolean isLoaded()
	{
		return isLoaded_;
	}


	/*************************************************************************************************
	 * Sets the isLoaded field.
	 */
	public void setLoaded(boolean isLoaded)
	{
		isLoaded_ = isLoaded;
	}


	/*************************************************************************************************
	 * Returns contents of the keyUuid field.
	 */
	public TcTssUuid getKeyUuid()
	{
		return keyUuid_;
	}


	/*************************************************************************************************
	 * Sets the keyUuid field.
	 */
	public void setKeyUuid(TcTssUuid keyUuid)
	{
		keyUuid_ = keyUuid;
	}


	/*************************************************************************************************
	 * Returns contents of the parentKeyUuid field.
	 */
	public TcTssUuid getParentKeyUuid()
	{
		return parentKeyUuid_;
	}


	/*************************************************************************************************
	 * Sets the parentKeyUuid field.
	 */
	public void setParentKeyUuid(TcTssUuid parentKeyUuid)
	{
		parentKeyUuid_ = parentKeyUuid;
	}


	/*************************************************************************************************
	 * Returns contents of the rgbVendorData field.
	 */
	public TcBlobData getVendorData()
	{
		return vendorData_;
	}


	/*************************************************************************************************
	 * Sets the rgbVendorData field.
	 */
	public void setVendorData(TcBlobData rgbVendorData)
	{
		vendorData_ = rgbVendorData;
	}


	/*************************************************************************************************
	 * Returns the length of the vendorData.
	 */
	public long getVendorDataLength()
	{
		if (vendorData_ == null) {
			return 0;
		} else {
			return vendorData_.getLengthAsLong();
		}
	}


	/*************************************************************************************************
	 * Returns contents of the versionInfo field.
	 */
	public TcTssVersion getVersionInfo()
	{
		return versionInfo_;
	}


	/*************************************************************************************************
	 * Sets the versionInfo field.
	 */
	public void setVersionInfo(TcTssVersion versionInfo)
	{
		versionInfo_ = versionInfo;
	}


	/*************************************************************************************************
	 * Returns a string representation of the object.
	 */
	public String toString()
	{
		StringBuffer retVal = new StringBuffer();
		retVal.append("KeyInfo: ");
		retVal.append(Utils.getNL());
		retVal.append("  ");
		retVal.append(getVersionInfo());
		retVal.append(Utils.getNL());
		retVal.append("  key ");
		retVal.append(getKeyUuid());
		retVal.append(Utils.getNL());
		retVal.append("  parent key ");
		retVal.append(getParentKeyUuid());
		retVal.append(Utils.getNL());
		retVal.append("  is loaded: ");
		retVal.append(isLoaded());
		retVal.append(Utils.getNL());
		retVal.append("  auth data usage: ");
		retVal.append(getAuthDataUsage());
		retVal.append(Utils.getNL());
		if (getVendorDataLength() > 0) {
			retVal.append("  vendor data: ");
			retVal.append(getVendorData().toHexString());
		} else {
			retVal.append("  vendor data: none");
		}
		return retVal.toString();
	}

}
