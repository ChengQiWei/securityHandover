/*
 * Copyright (C) 2008 IAIK, Graz University of Technology
 * authors: Thomas Holzmann
 */

package iaik.tc.tss.impl.ps;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.ArrayList;

import iaik.tc.tss.api.constants.tcs.TcTcsErrors;
import iaik.tc.tss.api.exceptions.common.TcTssException;
import iaik.tc.tss.api.exceptions.tcs.TcTcsException;
import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.tss.api.structs.tsp.TcTssKmKeyinfo;
import iaik.tc.tss.api.structs.tsp.TcTssUuid;
import iaik.tc.utils.properties.Properties;

public abstract class TcTssPsTrousers extends TcTssPersistentStorage {

	File storageFile_ = null;
	long numOfKeys_ = 0;

	// ///////////////////////////////////////////////////////////////
	// TODO At the moment this class can only handle reading from
	// TrouSerS persistent storage. I've started implementing write
	// access but it's not completed at the moment.
	//
	// ///////////////////////////////////////////////////////////////
	// The TrouSerS persistent storage file should look like this:
	//
	// TrouSerS 0.2.1+
	// Version 1: cached?
	// [BYTE PS version = '\1']
	// [UINT32 num_keys_on_disk ]
	// [TSS_UUID uuid0 ] yes
	// [TSS_UUID uuid_parent0 ] yes
	// [UINT16 pub_data_size0 ] yes
	// [UINT16 blob_size0 ] yes
	// [UINT32 vendor_data_size0] yes
	// [UINT16 cache_flags0 ] yes
	// [BYTE[] pub_data0 ]
	// [BYTE[] blob0 ]
	// [BYTE[] vendor_data0 ]
	// [...]
	//
	// NOTE: This is only valid for TrouSerS 0.2.1 or higher.
	//
	// NOTE: On Intel processors the persistent storage file has
	// little endian byte order. So we have to convert it
	// to big endian (JVM).
	//
	// Unfortunately we do not have unsigned types in Java, so we
	// will store the data types in bigger signed data types.
	// (i.e. UINT32 -> long, UINT16 -> int ...)
	// ///////////////////////////////////////////////////////////////

	public TcTssPsTrousers(Properties properties) {
		super(properties);
		String path = properties.getProperty(this.getClass().getSimpleName(),
				"file");
		try {
			storageFile_ = new File(path);
			storageFile_.createNewFile();
			FileInputStream fi = new FileInputStream(storageFile_);
			if (fi.skip(1) == -1) {
				// the file is empty -> create header
				fi.close();
				FileOutputStream fo = new FileOutputStream(storageFile_);
				byte[] version = new byte[1];
				version[0] = 1;
				fo.write(version);
				byte[] num = new byte[4];
				for (int i = 0; i < 4; i++)
					num[i] = 0;
				fo.write(version);
				fo.close();
				numOfKeys_ = 0;
			} else {
				byte[] num = new byte[4];
				fi.read(num);
				numOfKeys_ = getLongFromByteArray(num);
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	protected void preOperations() throws TcTssException {
		// we do not need preOperations ATM
	}

	protected void postOperations() throws TcTssException {
		// we do not need postOperations ATM
	}

	// ///////////////////////////////////////////////////////////////
	//
	// The implementation methods
	//
	// ///////////////////////////////////////////////////////////////

	protected void registerKeyImpl(TcTssUuid parentUuid, TcTssUuid keyUuid,
			TcBlobData key) throws TcTssException {
		// TODO not working yet, continue implementation
		// We have decided not to implement this feature at the moment, but I
		// don't want to delete the current code...

		// try {
		// //we can simply append our data
		// FileOutputStream fo = new FileOutputStream (storageFile_, true);
		// fo.write(getByteArrayFromUuid(keyUuid));
		// fo.write(getByteArrayFromUuid(parentUuid));
		// byte[] zeroInt16 = new byte[2];
		// zeroInt16[0] = 0x00;
		// zeroInt16[1] = 0x00;
		// fo.write(zeroInt16);
		// int length = key.getLength();
		// byte[] keyLength = new byte[2];
		// keyLength[0] = (byte)((length & 0xFF000000) >> 24);
		// keyLength[1] = (byte)((length & 0x00FF0000) >> 16);
		// fo.write(keyLength);
		// byte[] zeroInt32 = new byte[4];
		// for (int i = 0; i<4; i++)
		// zeroInt32[i] = 0x00;
		// fo.write(zeroInt32);
		// fo.write(zeroInt16);
		// length = key.getLength();
		// byte[] keyBigEndian = key.asByteArray();
		// byte[] keyLittleEndian = new byte[length];
		// for (int i = 0; i < length; i++)
		// keyLittleEndian[i] = keyBigEndian[length-1-i];
		//			
		// fo.close();
		// increaseKeyNum();
		//			
		//			
		// }
		// catch (Exception e) {
		// e.printStackTrace();
		// }
	}

	protected void unregisterKeyImpl(TcTssUuid keyUuid) throws TcTssException {
		// TODO not working yet, continue implementation
		// We have decided not to implement this feature at the monent, but I
		// don't want to delete the current code...

		// try {
		// BufferedInputStream fi = new BufferedInputStream(new FileInputStream
		// (storageFile_));
		// File newKeyFile = File.createTempFile("keys", "tmp");
		// BufferedOutputStream fo = new BufferedOutputStream(new
		// FileOutputStream ( newKeyFile));
		// // write header into the new file
		// byte[] header = new byte[5];
		// fi.read(header);
		// fo.write(header);
		// for (int i = 0; i < numOfKeys_; i++) {
		// long keySize = getSizeOfNextKey(fi);
		// byte[] key = new byte[(int)keySize];
		// if (isNextKeyUuid(fi, keyUuid)) {
		// fi.skip(keySize);
		// }
		// else {
		// fi.read(key);
		// fo.write(key);
		// }
		// }
		// // delete
		// if(!(storageFile_.delete() && newKeyFile.renameTo(storageFile_)))
		// throw new TcTcsException(TcTcsErrors.TCS_E_INTERNAL_ERROR,
		// "Replacing the old storage file with the newly created failed.");
		//				
		// decreaseKeyNum();
		//			
		// }
		// catch (IOException e) {
		// e.printStackTrace();
		// throw new TcTcsException(TcTcsErrors.TCS_E_INTERNAL_ERROR,
		// e.getMessage());
		// }

	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * iaik.tc.tss.impl.ps.TcTssPersistentStorage#getRegisteredKeyBlobImpl(iaik
	 * .tc.tss.api.structs.tsp.TcTssUuid)
	 */
	protected TcBlobData getRegisteredKeyBlobImpl(TcTssUuid keyUuid)
			throws TcTssException {
		TcBlobData blob = null;
		try {
			BufferedInputStream fi = new BufferedInputStream(
					new FileInputStream(storageFile_));
			fi.skip(5);

			for (int i = 0; i < numOfKeys_; i++) {
				if (isNextKeyUuid(fi, keyUuid)) {
					// read out key
					blob = getNextKeyBlob(fi, true);
				} else {
					// skip
					long size = getSizeOfNextKey(fi);
					fi.skip(size);
					continue;
				}
				// if we are here its the desired key, so return
				return blob;
			}

		} catch (Exception e) {
			e.printStackTrace();
		}
		throw new TcTcsException(TcTcsErrors.TCS_E_KEY_NOT_REGISTERED,
				"The key with the UUID: " + keyUuid.toStringNoPrefix()
						+ " could not be found.");
	}

	protected abstract TcTssKmKeyinfo[] enumRegisteredKeysImpl(TcTssUuid keyUuid)
			throws TcTssException;

	// ///////////////////////////////////////////////////////////////
	//
	// Helper Methods
	//
	// ///////////////////////////////////////////////////////////////

	/**
	 * Returns all UUIDs stored in the TrouSerS PS as ArrayList
	 * 
	 * @return all UUIDs
	 * @throws TcTssException
	 *             if IO error occurs
	 */
	protected ArrayList<String> getAllRegisteredKeyUuids()
			throws TcTssException {
		ArrayList<String> uuids = new ArrayList<String>();
		try {
			BufferedInputStream fi = new BufferedInputStream(
					new FileInputStream(storageFile_));
			fi.skip(5);
			for (int i = 0; i < numOfKeys_; i++) {
				fi.mark(50);
				byte[] byteUuid = new byte[16];
				if (fi.read(byteUuid) == -1)
					throw new IOException("No data avaliable.");
				TcTssUuid uuid = getUuidFromByteArray(byteUuid);
				uuids.add(uuid.toStringNoPrefix());
				fi.reset();
				long size = getSizeOfNextKey(fi);
				fi.skip(size);
			}
			fi.close();
		} catch (IOException e) {
			throw new TcTcsException(TcTcsErrors.TCS_E_INTERNAL_ERROR, e
					.getMessage());
		}
		return uuids;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * iaik.tc.tss.impl.ps.TcTssPersistentStorage#getHierarchyForRegisteredKey
	 * (iaik.tc.tss.api.structs.tsp.TcTssUuid)
	 */
	protected ArrayList<String> getHierarchyForRegisteredKey(TcTssUuid keyUuid)
			throws TcTssException {
		ArrayList<String> keyUuids = new ArrayList<String>();
		TcTssUuid currentUuid = keyUuid;
		TcTssUuid currentParent = null;

		ArrayList<String> allUuids = getAllRegisteredKeyUuids();
		while (allUuids.contains(currentUuid.toStringNoPrefix())) {
			keyUuids.add(currentUuid.toStringNoPrefix());
			currentParent = getParentUuid(currentUuid);
			currentUuid = currentParent;
		}
		return keyUuids;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * iaik.tc.tss.impl.ps.TcTssPersistentStorage#getParentUuid(iaik.tc.tss.
	 * api.structs.tsp.TcTssUuid)
	 */
	protected TcTssUuid getParentUuid(TcTssUuid childUuid)
			throws TcTssException {
		TcTssUuid parentUuid = null;
		// if its the SRK just create a dummy parent
		if (getUuidSRK().equals(childUuid)) {
			return new TcTssUuid().init(0L, 0, 0, (short) 0, (short) 0,
					new short[] { 0, 0, 0, 0, 0, 0 });
		}
		try {
			BufferedInputStream fi = new BufferedInputStream(
					new FileInputStream(storageFile_));
			// skip the header
			fi.skip(5);
			for (int i = 0; i < numOfKeys_; i++) {
				if (isNextKeyUuid(fi, childUuid)) {
					fi.skip(16);
					byte[] parent = new byte[16];
					fi.read(parent);
					parentUuid = getUuidFromByteArray(parent);
				} else {
					long size = getSizeOfNextKey(fi);
					fi.skip(size);
				}
			}
		} catch (IOException e) {
			e.printStackTrace();
			throw new TcTcsException(TcTcsErrors.TCS_E_INTERNAL_ERROR, e
					.getMessage());
		}
		return parentUuid;
	}

	/**
	 * Checks if the database is empty
	 * 
	 * @return true if it is empty
	 * @throws TcTssException
	 *             if a database error occurs
	 */
	protected boolean isRepositoryEmpty() throws TcTssException {
		ArrayList<String> registeredKeys = getAllRegisteredKeyUuids();
		return registeredKeys.size() == 0;
	}

	protected void enforceConsistency() throws TcTssException {
		// we do not need enforceConsistency() because we cannot
		// write to this persistent storage ATM
	}

	/**
	 * 
	 * Converts a byte[] in little endian with four bytes to a long.
	 * 
	 * @param bytes
	 *            the byte array to
	 * @return the long equivalent
	 */
	protected long getLongFromByteArray(byte[] bytes) {
		long number = 0;
		// little endian byte order
		for (int i = 0; i < 4; i++) {
			int shift = i * 8;
			number += (bytes[i] & 0x000000FFL) << shift;
		}
		return number;
	}

	/**
	 * Converts a byte[] representing the UUID struct from TrouSerS (little
	 * endian) to a TcTssUuid.
	 * 
	 * @param bytes
	 *            the array representing the UUID struct from TrouSerS
	 * @return the converted TcTssUuid
	 */
	protected TcTssUuid getUuidFromByteArray(byte[] bytes) {
		TcTssUuid uuid = new TcTssUuid();
		/*
		 * we get this struct from the trousers storage:
		 * 
		 * typedef struct tdTSS_UUID { UINT32 ulTimeLow; UINT16 usTimeMid;
		 * UINT16 usTimeHigh; BYTE bClockSeqHigh; BYTE bClockSeqLow; BYTE
		 * rgbNode[6]; } TSS_UUID;
		 * 
		 * => 16 bytes all together
		 */

		long timeLow = 0;
		int timeMid = 0;
		int timeHigh = 0;
		short clockSeqLow = 0;
		short clockSeqHigh = 0;
		short[] node = new short[6];

		// read out timeLow
		for (int i = 0; i < 4; i++) {
			int shift = i * 8;
			timeLow += ((bytes[i] & 0x000000FFL) << shift);
		}

		// read out timeMid and timeHigh
		for (int i = 0; i < 2; i++) {
			int shift = i * 8;
			timeMid += ((bytes[4 + i] & 0x000000FF) << shift);
			timeHigh += ((bytes[6 + i] & 0x000000FF) << shift);
		}

		// read out clockSeqLow and clockSeqHigh
		clockSeqHigh = (short) (bytes[8] & 0x000000FF);
		clockSeqLow = (short) (bytes[9] & 0x000000FF);

		// read out rgbNode
		for (int i = 0; i < 6; i++) {
			node[i] = (short) (bytes[10 + i] & 0x000000FF);
		}

		uuid.init(timeLow, timeMid, timeHigh, clockSeqLow, clockSeqHigh, node);

		return uuid;
	}

	/**
	 * Converts a TcTssUuid to a byte[] representing a TrouSerS UUID struct.
	 * 
	 * @param uuid
	 *            the UUID from which we want to get a byte[]
	 * @return a byte[] representing the UUID
	 */
	protected byte[] getByteArrayFromUuid(TcTssUuid uuid) {
		byte[] bytes = new byte[16];

		long timeLow = uuid.getTimeLow();
		int timeMid = uuid.getTimeMid();
		int timeHigh = uuid.getTimeHigh();
		short clockSeqHigh = uuid.getClockSeqHigh();
		short clockSeqLow = uuid.getClockSeqLow();
		short[] node = uuid.getNode();

		bytes[0] = (byte) (timeLow & 0x000000FFL);
		bytes[1] = (byte) ((timeLow & 0x0000FF00L) >> 8);
		bytes[2] = (byte) ((timeLow & 0x00FF0000L) >> 16);
		bytes[3] = (byte) ((timeLow & 0xFF000000L) >> 24);
		bytes[4] = (byte) (timeMid & 0x000000FF);
		bytes[5] = (byte) ((timeMid & 0x0000FF00) >> 8);
		bytes[6] = (byte) (timeHigh & 0x000000FF);
		bytes[7] = (byte) ((timeHigh & 0x0000FF00) >> 8);
		bytes[8] = (byte) (clockSeqHigh & 0x000000FF);
		bytes[9] = (byte) (clockSeqLow & 0x000000FF);
		for (int i = 0; i < 6; i++) {
			bytes[10 + i] = (byte) (node[i] & 0x000000FF);
		}

		return bytes;
	}

	/**
	 * Returns the byte[] as TcBlobData.
	 * 
	 * @param bytes
	 *            the byte[] to be converted
	 * @return TcBlobData representing the byte[]
	 */
	protected TcBlobData getBlobDataFromByteArray(byte[] bytes) {
		return TcBlobData.newByteArray(bytes);
	}

	/**
	 * Changes the number of key values in the TrouSerS PS file and the
	 * numOfKeys_ variable.
	 * 
	 * @param changeValue
	 *            the value with which the number of keys should be changed,
	 * @throws IOException
	 */
	protected void changeNumOfKeys(int changeValue) throws IOException {
		// TODO We don't need this at the moment because we don't use write
		// access
		// However, if you uncomment the code it should work.
		// FileOutputStream fo = new FileOutputStream (storageFile_);
		// numOfKeys_ += changeValue;
		// byte[] keyNum = new byte[4];
		// keyNum[0] = (byte)((numOfKeys_ & 0xFF00000000000000L) >> 56);
		// keyNum[1] = (byte)((numOfKeys_ & 0x00FF000000000000L) >> 48);
		// keyNum[2] = (byte)((numOfKeys_ & 0x0000FF0000000000L) >> 40);
		// keyNum[3] = (byte)((numOfKeys_ & 0x000000FF00000000L) >> 32);
		// byte[] version = new byte[1];
		// version[0] = 1;
		// fo.write(version);
		// fo.write(keyNum);
	}

	/**
	 * Increases the number of keys by one.
	 * 
	 * @see #changeNumOfKeys(int)
	 */
	protected void increaseKeyNum() {
		try {
			changeNumOfKeys(1);
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	/**
	 * Decreases the number of keys by one.
	 * 
	 * @see #changeNumOfKeys(int)
	 */
	protected void decreaseKeyNum() {
		try {
			changeNumOfKeys(-1);
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	/**
	 * Checks if the next key has the given UUID. The stream pointer will be
	 * reset to the position before this call.<br/> NOTE: the pointer has to be
	 * directly before the next key, otherwise the return value might be false,
	 * but that's not guaranteed.
	 * 
	 * @param fi
	 *            the BufferedInputStream where we have to read from
	 * @param keyUuid
	 *            the UUID we search for
	 * @return true if the next key has this UUID
	 */
	protected boolean isNextKeyUuid(BufferedInputStream fi, TcTssUuid keyUuid,
			boolean reset) {
		byte[] uuid = new byte[16];
		try {
			fi.mark(20);
			fi.read(uuid);
			if (reset)
				fi.reset();
		} catch (IOException e) {
			e.printStackTrace();
		}

		if (keyUuid.equals(getUuidFromByteArray(uuid)))
			return true;
		else
			return false;
	}

	protected boolean isNextKeyUuid(BufferedInputStream fi, TcTssUuid keyUuid) {
		return isNextKeyUuid(fi, keyUuid, true);
	}

	/**
	 * Returns the size of the next key in the input stream and resets the input
	 * stream to the current position. NOTE: the pointer has to be directly
	 * before the next key, otherwise a value will be returned but that is
	 * invalid.
	 * 
	 * @param fi
	 *            the input stream to read from
	 * @return the size of the next key
	 */
	protected long getSizeOfNextKey(BufferedInputStream fi) {
		long size = 0;
		byte[] int16 = new byte[2];
		byte[] int32 = new byte[4];
		try {
			fi.mark(200);
			// skip UUIDs
			fi.skip(32);
			size += 32;
			// read out pub data size
			fi.read(int16);
			size += ((int16[0] & 0xFFL));
			size += ((int16[1] & 0xFFL) << 8);
			size += 2;
			// read out blob size
			fi.read(int16);
			size += ((int16[0] & 0xFFL));
			size += ((int16[1] & 0xFFL) << 8);
			size += 2;
			// read out vendor data size
			fi.read(int32);
			for (int i = 0; i < 4; i++) {
				int shift = i * 8;
				size += ((int32[i] & 0xFFL) << shift);
			}
			size += 4;
			// cache flags
			size += 2;
			fi.reset();
		} catch (IOException e) {
			e.printStackTrace();
		}
		return size;
	}

	/**
	 * Returns the next key blob in this input stream. If reset is true, the
	 * stream pointer will be reset to the position at call time. NOTE: the
	 * pointer has to be directly before the next key, otherwise a value will be
	 * returned but that is invalid.
	 * 
	 * @param fi
	 *            the input stream to read from
	 * @param reset
	 *            if true, the pointer will be reset
	 * @return the blob data with the next key blob
	 */
	protected TcBlobData getNextKeyBlob(BufferedInputStream fi, boolean reset) {
		TcBlobData blobData = null;
		try {
			fi.mark(800);
			// skip UUIDs
			fi.skip(32);
			int pubDataSize = 0;
			int blobSize = 0;
			byte[] int16 = new byte[2];
			fi.read(int16);
			pubDataSize += (int16[0] & 0xFF);
			pubDataSize += ((int16[1] & 0xFF) << 8);
			fi.read(int16);
			blobSize += (int16[0] & 0xFF);
			blobSize += ((int16[1] & 0xFF) << 8);
			// skip vedor data size, cache flags and pub data
			fi.skip(4 + 2 + pubDataSize);
			byte[] blob = new byte[blobSize];
			fi.read(blob);
			blobData = TcBlobData.newByteArray(blob);
			if (reset)
				fi.reset();
		} catch (IOException e) {
			e.printStackTrace();
		}
		return blobData;

	}
}
