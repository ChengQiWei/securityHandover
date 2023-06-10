/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */


package iaik.tc.tss.api.structs.tsp;


import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.utils.misc.Utils;

/**
 * This class is identical to TcTssKmKeyinfo except that it additionally includes the key's storage
 * type.
 * 
 * @TSS_1_2_EA 108
 */
public class TcTssKmKeyinfo2 extends TcTssKmKeyinfo {

	/**
	 * The storage type of the key.
	 */
	protected long persistentStorageType_ = 0;

	/**
	 * The storage type of the key's parent key.
	 */
	protected long persistentStorageTypeParent_ = 0;


	/*************************************************************************************************
	 * Default constructor.
	 */
	public TcTssKmKeyinfo2()
	{
	}


	/*************************************************************************************************
	 * Initialization method taking and setting all parameters at once.
	 */
	public TcTssKmKeyinfo init(TcTssVersion versionInfo, TcTssUuid keyUuid, TcTssUuid parentKeyUuid,
			short authDataUsage, boolean isLoaded, TcBlobData vendorData, long persistentStorageType,
			long persistentStorageTypeParent)
	{
		super.init(versionInfo, keyUuid, parentKeyUuid, authDataUsage, isLoaded, vendorData);
		persistentStorageType_ = persistentStorageType;
		persistentStorageTypeParent_ = persistentStorageTypeParent;
		
		return this;
	}


	/*************************************************************************************************
	 * This method returns the content of the persistenStorageTypeParent field.
	 */
	public long getPersistenStorageTypeParent()
	{
		return persistentStorageTypeParent_;
	}


	/*************************************************************************************************
	 * This method sets the content of the persistenStorageTypeParent field.
	 */
	public void setPersistenStorageTypeParent(long persistenStorageTypeParent)
	{
		persistentStorageTypeParent_ = persistenStorageTypeParent;
	}


	/*************************************************************************************************
	 * This method returns the content of the persistentStorageType field.
	 */
	public long getPersistentStorageType()
	{
		return persistentStorageType_;
	}


	/*************************************************************************************************
	 * This method sets the content of the persistentStorageType field.
	 */
	public void setPersistentStorageType(long persistentStorageType)
	{
		persistentStorageType_ = persistentStorageType;
	}


	/*************************************************************************************************
	 * Returns a string representation of the object.
	 */
	public String toString()
	{
		StringBuffer retVal = new StringBuffer(super.toString());
		retVal.append("persistent storage type: ");
		retVal.append(persistentStorageType_);
		retVal.append(Utils.getNL());
		retVal.append("persistent storage type parent: ");
		retVal.append(persistentStorageTypeParent_);
		retVal.append(Utils.getNL());

		return retVal.toString();
	}
}
