/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler, Ronald Toegl
 */

package iaik.tc.tss.impl.ps;


import iaik.tc.tss.api.constants.tcs.TcTcsErrors;
import iaik.tc.tss.api.constants.tpm.TcTpmConstants;
import iaik.tc.tss.api.exceptions.common.TcTssException;
import iaik.tc.tss.api.exceptions.tcs.TcTcsException;
import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.tss.api.structs.tpm.TcTpmStructVer;
import iaik.tc.tss.api.structs.tpm.TcTpmKey;
import iaik.tc.tss.api.structs.tpm.TcTpmKey12;
import iaik.tc.tss.api.structs.tsp.TcTssKmKeyinfo;
import iaik.tc.tss.api.structs.tsp.TcTssUuid;
import iaik.tc.utils.logging.Log;
import iaik.tc.utils.properties.Properties;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FilenameFilter;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.channels.FileLock;
import java.util.ArrayList;
import java.util.Random;

/**
 * 
 * 
 * Implements a basic file-system based persistent storage. As it only offers basic functionality, 
 * it does not the protect the key blobs.
 *  
 *   @author rtoegl, twinkler
 *
 *
 */
public abstract class TcTssPsFileSystem extends TcTssPersistentStorage {

	protected String storageBasePath_ = null;

	protected RandomAccessFile psTimestampFile_ = null;

	protected FileLock psLock_ = null;
	
	protected String keyBlobFileEnding_ = ".key";
	
	protected String keyParentFileEnding_ = ".parent";
	

	// ----------------------------------------------------------------------------------------------
	// Abstract methods
	// ----------------------------------------------------------------------------------------------

	
	abstract protected TcTssKmKeyinfo[] enumRegisteredKeysImpl(TcTssUuid keyUuid) throws TcTssException;
	
	// ----------------------------------------------------------------------------------------------
	// Constructor
	// ----------------------------------------------------------------------------------------------

	

	public TcTssPsFileSystem(Properties properties)
	{
		super(properties);
		
		try {
			storageBasePath_ = properties_.getProperty(this.getClass().getSimpleName(), "folder");
		} catch (IllegalArgumentException e) {
			Log.warn(this.getClass().getSimpleName() + " section or 'folder' key not found in ");
			throw e;
		}

		initPs();
	
		try {
			enforceConsistency();
		} catch (TcTcsException e)
		{
			Log.warn("Persistent storage consistency check failed.");
			//throw e;
		}
		
	}

	// ----------------------------------------------------------------------------------------------
	// Helper classes and methods
	// ----------------------------------------------------------------------------------------------


	

	//A helper class for filtering directory information
	protected class FileFilter implements FilenameFilter {
		
		String pattern_=null;
		
		public FileFilter(String pattern)
		{
			pattern_=pattern;
		}
		
		public boolean accept (File dir, String name) {
			return name.toLowerCase().endsWith(pattern_.toLowerCase());
		}
	}
	
	protected void initPs()
	{
		File storageDir = new File(storageBasePath_);
		if (!storageDir.exists()) {
			storageDir.mkdirs();
		}

		preOperations();
		postOperations();
		
	}


	protected File getKeyFile(TcTssUuid keyUuid)
	{
		return new File(storageBasePath_ + File.separator + keyUuid.toStringNoPrefix() + keyBlobFileEnding_);
	}

	
	protected File getParentKeyFile(TcTssUuid keyUuid)
	{
		return new File(storageBasePath_ + File.separator + keyUuid.toStringNoPrefix() + keyParentFileEnding_);
	}
	

	protected TcTssUuid getParentUuid(TcTssUuid keyUuid) throws TcTcsException {
		
		File keyParentFile = getParentKeyFile(keyUuid);
		
		String parentUuidString;

		try {
			FileInputStream fi = new FileInputStream(keyParentFile);
			byte[] inBytes = new byte[fi.available()];
			fi.read(inBytes);
			fi.close();
			
			parentUuidString = new String(inBytes);
			
		} catch (FileNotFoundException e) {
			throw new TcTcsException(TcTcsErrors.TCS_E_INTERNAL_ERROR, e.getMessage());
		} catch (IOException e) {
			throw new TcTcsException(TcTcsErrors.TCS_E_INTERNAL_ERROR, e.getMessage());
		}

		TcTssUuid parentUuid = new TcTssUuid();
		parentUuid.initString(parentUuidString);
		return parentUuid;
	}

	
	protected ArrayList<String> getHierarchyForRegisteredKey(TcTssUuid keyUuid)
	throws TcTcsException {

		ArrayList<String> keyUuids=new ArrayList<String>();

		TcTssUuid currentUuid=keyUuid;
		TcTssUuid currentParent=null;

		while (getKeyFile(currentUuid).exists()) // Loop will complete when a key is wrapped by a key that is not inside the repository
		{
			
			keyUuids.add(currentUuid.toStringNoPrefix());
			currentParent=getParentUuid(currentUuid);
			currentUuid = currentParent;
		}
		
		return keyUuids;
	}



	protected ArrayList<String> getAllRegisteredKeyUUIDs() throws TcTcsException {
		ArrayList<String> keyUuids=new ArrayList<String>();

	
		FileFilter keyFileFilter=new FileFilter(keyBlobFileEnding_);
		String[] fileNames;

		try {
			File directory = new File (storageBasePath_ + File.separator + ".");
			fileNames = directory.list(keyFileFilter);
		} catch (Exception e) //does apparently not throw IOException, still better be careful..
		{
			throw new TcTcsException(TcTcsErrors.TCS_E_INTERNAL_ERROR, e.getMessage());
		}

		for (int i = 0; i != fileNames.length; i++) 
		{
			String uuidString = fileNames[i].substring(0,fileNames[i].indexOf(keyBlobFileEnding_));
			keyUuids.add(uuidString);
		}

		return keyUuids;
	}
	
	protected boolean isRepositoryEmpty() throws TcTssException
	{
		
		ArrayList<String> registeredKeys= getAllRegisteredKeyUUIDs();

		return registeredKeys.size()==0;

	}
	
	/**
	 * Since we are just using the file system as database for this simple PS implementation, consistency has to be enforced.
	 * All key files in the repository and their parent information are inspected for existence and if
	 *  valid objects can be constructed from them.
	 *  Invalid data is renamed so that it is not lost, but will not interfere with further operations.
	 */

	protected synchronized void enforceConsistency() throws TcTcsException
	{
		ArrayList<String> keyUuids=new ArrayList<String>();

		//get all UUIDs in the repository and put them in a list.
		//Note: duplicates are likely, but just a performance matter
		
		FileFilter keyFileFilter=new FileFilter(keyBlobFileEnding_);
		FileFilter parentFileFilter=new FileFilter(keyParentFileEnding_);
		String[] fileNames;

		try {
			File directory = new File (storageBasePath_ + File.separator + ".");
			fileNames = directory.list(keyFileFilter);
		} catch (Exception e) //does apparently not throw IOException, still better be careful..
		{
			throw new TcTcsException(TcTcsErrors.TCS_E_INTERNAL_ERROR, e.getMessage());
		}

		for (int i = 0; i != fileNames.length; i++) 
		{
			String uuidString = fileNames[i].substring(0,fileNames[i].indexOf(keyBlobFileEnding_));
			keyUuids.add(uuidString);
		}

		try {
			File directory = new File (storageBasePath_ + File.separator + ".");
			fileNames = directory.list(parentFileFilter);
		} catch (Exception e) //does apparently not throw IOException, still better be careful..
		{
			throw new TcTcsException(TcTcsErrors.TCS_E_INTERNAL_ERROR, e.getMessage());
		}

		for (int i = 0; i != fileNames.length; i++) 
		{
			String uuidString = fileNames[i].substring(0,fileNames[i].indexOf(keyParentFileEnding_));
			keyUuids.add(uuidString);
		}

		
		//Iterate over all keys and check their consistency. If inconsistent, rename files.
		
		for (int i=0; i!=keyUuids.size(); i++)
		{
			Random rnd = new Random();
				
			TcTssUuid currentUuid=new TcTssUuid();
			currentUuid.initString(keyUuids.get(i));

			File currentKeyFile=getKeyFile(currentUuid);
			File currentParentFile=getParentKeyFile(currentUuid);

			if (!currentKeyFile.exists() & currentParentFile.exists())
			{
				File lostFile=new File(storageBasePath_ + File.separator + "LOST_PARENT_" +  rnd.nextLong() + "_" + keyUuids.get(i) + ".dat"); //rename file ==> remove from PS
				currentParentFile.renameTo(lostFile);
				continue;
								
			}

			if (currentKeyFile.exists() & !currentParentFile.exists())
			{
				File lostFile=new File(storageBasePath_ + File.separator + "LOST_KEY_" +  rnd.nextLong() + "_" + keyUuids.get(i) + ".dat"); //rename file ==> remove from PS
				currentKeyFile.renameTo(lostFile);
				continue;
			}

			if (!currentKeyFile.exists() & !currentParentFile.exists())
			{
				throw new TcTcsException(TcTcsErrors.TCS_E_INTERNAL_ERROR, "Could not check persisiten storage consistency. File System gives invalid directory information for" + storageBasePath_);
			}

			//Here, both files exist
			
			
						
			//Check, if the existing parent file can be read and if an UUID can be initialized from it.
			try {
				getParentUuid(currentUuid);
			} catch (Exception e)
			{
				File lostFile=new File(storageBasePath_ + File.separator+ "LOST_PARENT_" +  rnd.nextLong() + "_" + keyUuids.get(i) + ".dat"); //rename file ==> remove from PS
				File lostParentFile=new File(storageBasePath_ + File.separator + "LOST_KEY_" +  rnd.nextLong() + "_" + keyUuids.get(i) + ".dat"); //rename file ==> remove from PS
				currentKeyFile.renameTo(lostFile);
				currentParentFile.renameTo(lostParentFile);
								
				continue;
			}

			//Check the key file. Load it and initialize a key object from it.
			try {

				TcBlobData currentKeyBlob= getRegisteredKeyBlobImpl(currentUuid);

				// get a valid key structure
				
				TcBlobData tagKey12 = TcBlobData.
				newByteArray(new byte[] { 0x00, TcTpmConstants.TPM_TAG_KEY12 });
				TcBlobData tag = TcBlobData.newByteArray(currentKeyBlob.getRange(0, 2));

				if (tag.equals(tagKey12)) {
					
					new TcTpmKey12(currentKeyBlob);

				} else {
					TcBlobData ver = TcBlobData.newByteArray(currentKeyBlob.getRange(0, 4));
					if (new TcTpmStructVer(ver).equalsMinMaj(TcTpmStructVer.TPM_V1_1)) {
						
						new TcTpmKey(currentKeyBlob);
					
					} else {
						throw new TcTcsException(TcTcsErrors.TCS_E_BAD_PARAMETER,
								"The given blob seems to be neither a 1.1 nor a 1.2 TPM key blob.");
					}
				}


			}catch (Exception e)
			{
				File lostFile=new File(storageBasePath_ + File.separator + "LOST_PARENT_" +  rnd.nextLong() + "_" + keyUuids.get(i) + ".dat"); //rename file ==> remove from PS
				File lostParentFile=new File(storageBasePath_ + File.separator + "LOST_KEY_" +  rnd.nextLong() + "_" + keyUuids.get(i) + ".dat"); //rename file ==> remove from PS
				currentKeyFile.renameTo(lostFile);
				currentParentFile.renameTo(lostParentFile);
				
				continue;
			}

			//This key seems to be consistent and ok!
			
		}		
	}

	
	// ----------------------------------------------------------------------------------------------
	// methods managing the PS lock (based on file system lock)
	// ----------------------------------------------------------------------------------------------

	/**
	 * Acquires the file system lock.
	 */
	protected void preOperations()
	{
		try {
			psTimestampFile_ = new RandomAccessFile(storageBasePath_ + File.separator + "ps.modified",
					"rw");
			psLock_ = psTimestampFile_.getChannel().lock();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}


	protected void updateModificationTime() throws TcTssException
	{
		if (psTimestampFile_ == null) {
			throw new TcTcsException(TcTcsErrors.TCS_E_INTERNAL_ERROR,
					"Unable to update PS modification time. PS not locked.");
		}

		try {
			psTimestampFile_.writeLong(System.currentTimeMillis());
		} catch (FileNotFoundException e) {
			throw new TcTcsException(TcTcsErrors.TCS_E_INTERNAL_ERROR, e.getMessage());
		} catch (IOException e) {
			throw new TcTcsException(TcTcsErrors.TCS_E_INTERNAL_ERROR, e.getMessage());
		}
	}

	/**
	 * Releases the file system lock.
	 */
	protected void postOperations()
	{
		try {
			psLock_.release();
			psTimestampFile_.close();
			psTimestampFile_ = null;
		} catch (IOException e) {
			e.printStackTrace();
		}
	}



	// ----------------------------------------------------------------------------------------------
	// actual implementation methods
	// ----------------------------------------------------------------------------------------------


	/**
	 * 
	 * Stores the key by creating two files. One .key file, which stores the given blob,
	 * and one .parent file which stores the parentUuid.
	 */
	protected void registerKeyImpl(TcTssUuid parentUuid, TcTssUuid keyUuid, TcBlobData key)
	throws TcTssException
	{


		File keyFile = getKeyFile(keyUuid);
		File keyParentFile = getParentKeyFile(keyUuid);
		
		if (keyFile.exists() || keyParentFile.exists()) {
			throw new TcTcsException(TcTcsErrors.TCS_E_KEY_ALREADY_REGISTERED);
		}

		
		try {
			//Write Key blob to <uuid>.key file
			try {
				FileOutputStream fo = new FileOutputStream(keyFile);
				fo.write(key.asByteArray());
				fo.close();
				updateModificationTime();
			} catch (FileNotFoundException e) {
				throw new TcTcsException(TcTcsErrors.TCS_E_INTERNAL_ERROR, e.getMessage());
			} catch (IOException e) {
				throw new TcTcsException(TcTcsErrors.TCS_E_INTERNAL_ERROR, e.getMessage());
			}

			//Write parent uuid string to <uuid>.parent file
			try {
				FileOutputStream fo = new FileOutputStream(keyParentFile);
				fo.write(parentUuid.toStringNoPrefix().getBytes());
				fo.close();
				updateModificationTime();
			} catch (FileNotFoundException e) {
				throw new TcTcsException(TcTcsErrors.TCS_E_INTERNAL_ERROR, e.getMessage());
			} catch (IOException e) {
				throw new TcTcsException(TcTcsErrors.TCS_E_INTERNAL_ERROR, e.getMessage());
			}

		} catch (Exception e)
		{
			throw new TcTcsException(TcTcsErrors.TCS_E_KEY_NOT_REGISTERED, e.getMessage());
		}
	}

	
	/**
	 * Deletes the created files and therefore removes the key from storage.
	 * @throws TcTssException
	 */
	protected void unregisterKeyImpl(TcTssUuid keyUuid) throws TcTssException
	{
		File keyFile = getKeyFile(keyUuid);
		File keyParentFile = getParentKeyFile(keyUuid);
		
		if (!keyFile.exists() || !keyParentFile.exists()) {
			throw new TcTcsException(TcTcsErrors.TCS_E_KEY_NOT_REGISTERED);
		}

		try {
		
		keyFile.delete();
		keyParentFile.delete();
		updateModificationTime();
		
		} catch (Exception e)
		{
			throw new TcTcsException(TcTcsErrors.TCS_E_FAIL, e.getMessage());
		}
		
	}


	/**
	 * Returns the key blob, that was previously stored.
	 * @throws TcTssException
	 */
	protected TcBlobData getRegisteredKeyBlobImpl(TcTssUuid keyUuid) throws TcTssException
	{
		File keyFile = getKeyFile(keyUuid);
		if (!keyFile.exists()) {
			throw new TcTcsException(TcTcsErrors.TCS_E_KEY_NOT_REGISTERED,"Key is not registered:" + keyUuid.toString());
		}

		try {
			FileInputStream fi = new FileInputStream(keyFile);
			byte[] inBytes = new byte[fi.available()];
			fi.read(inBytes);
			fi.close();
			
			return TcBlobData.newByteArray(inBytes);
			
		} catch (FileNotFoundException e) {
			throw new TcTcsException(TcTcsErrors.TCS_E_INTERNAL_ERROR, e.getMessage());
		} catch (IOException e) {
			throw new TcTcsException(TcTcsErrors.TCS_E_INTERNAL_ERROR, e.getMessage());
		}
	}


	
}
