/*
 * Copyright (C) 2008 IAIK, Graz University of Technology
 * authors: Thomas Holzmann, Thomas Winkler, Ronald Toegl
 */

package iaik.tc.tss.impl.ps;

import java.util.ArrayList;

import iaik.tc.tss.api.constants.tcs.TcTcsErrors;
import iaik.tc.tss.api.constants.tpm.TcTpmConstants;
import iaik.tc.tss.api.exceptions.common.TcTssException;
import iaik.tc.tss.api.exceptions.tcs.TcTcsException;
import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.tss.api.structs.tpm.TcITpmKey;
import iaik.tc.tss.api.structs.tpm.TcTpmKey;
import iaik.tc.tss.api.structs.tpm.TcTpmKey12;
import iaik.tc.tss.api.structs.tpm.TcTpmPubkey;
import iaik.tc.tss.api.structs.tpm.TcTpmStructVer;
import iaik.tc.tss.api.structs.tsp.TcTssKmKeyinfo;
import iaik.tc.tss.api.structs.tsp.TcTssUuid;
import iaik.tc.tss.api.structs.tsp.TcTssVersion;
import iaik.tc.utils.misc.CheckPrecondition;
import iaik.tc.utils.properties.Properties;

public abstract class TcTssPersistentStorage implements TcITssPersistentStorage {

	protected Properties properties_ = null;

	public TcTssPersistentStorage(Properties properties) {
		CheckPrecondition.notNull(properties, "properties");
		properties_ = properties;
	}

	//--------------------------------------------------------------------------
	// --------------------
	// methods managing the pre- and post-operations (e.g. locking, getting
	// database connection...)
	//--------------------------------------------------------------------------
	// --------------------

	/**
	 * Makes all the things that have to be done before other operations can be
	 * executed. Depending on the implementation that can be e.g. locking a
	 * file, getting a database connection...
	 * 
	 * @throws TcTssException
	 *             if these operations could not be executed correctly.
	 */
	protected abstract void preOperations() throws TcTssException;

	/**
	 * Makes all the things that have to be done after all desired operations
	 * were executed. Depending on the implementation that can be e.g. unlocking
	 * a file, closing a database connection...
	 * 
	 * @throws TcTssException
	 *             if these operations could not be executed correctly.
	 */
	protected abstract void postOperations() throws TcTssException;

	//--------------------------------------------------------------------------
	// --------------------
	// wrapper methods ensuring that pre and post operations are executed
	// correctly
	//--------------------------------------------------------------------------
	// --------------------

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * iaik.tc.tss.impl.ps.TcITssPersistentStorage#registerKey(iaik.tc.tss.api
	 * .structs.tsp.TcTssUuid, iaik.tc.tss.api.structs.tsp.TcTssUuid,
	 * iaik.tc.tss.api.structs.common.TcBlobData)
	 */
	public synchronized void registerKey(TcTssUuid parentUuid,
			TcTssUuid keyUuid, TcBlobData key) throws TcTssException {
		preOperations();

		try {
			registerKeyImpl(parentUuid, keyUuid, key);
			postOperations();
		} catch (TcTssException e) {
			postOperations();
			enforceConsistency();
			throw e;
		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * iaik.tc.tss.impl.ps.TcITssPersistentStorage#unregisterKey(iaik.tc.tss
	 * .api.structs.tsp.TcTssUuid)
	 */
	public synchronized void unregisterKey(TcTssUuid keyUuid)
			throws TcTssException {
		preOperations();

		try {
			unregisterKeyImpl(keyUuid);
			postOperations();
		} catch (TcTssException e) {
			postOperations();
			enforceConsistency();
			throw e;
		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * iaik.tc.tss.impl.ps.TcITssPersistentStorage#getRegisteredKeyBlob(iaik
	 * .tc.tss.api.structs.tsp.TcTssUuid)
	 */
	public synchronized TcBlobData getRegisteredKeyBlob(TcTssUuid keyUuid)
			throws TcTssException {
		preOperations();

		try {
			TcBlobData retVal = getRegisteredKeyBlobImpl(keyUuid);
			postOperations();
			return retVal;
		} catch (TcTssException e) {
			postOperations();
			enforceConsistency();
			throw e;
		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * iaik.tc.tss.impl.ps.TcITssPersistentStorage#getRegisteredKeyByPublicInfo
	 * (long, iaik.tc.tss.api.structs.common.TcBlobData)
	 */
	public TcBlobData getRegisteredKeyByPublicInfo(long algId, TcBlobData pubKey)
			throws TcTssException {
		preOperations();

		try {
			TcBlobData retVal = getRegisteredKeyByPublicInfoImpl(algId, pubKey);
			postOperations();
			return retVal;
		} catch (TcTcsException e) {
			postOperations();
			enforceConsistency();
			throw e;
		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * iaik.tc.tss.impl.ps.TcITssPersistentStorage#enumRegisteredKeys(iaik.tc
	 * .tss.api.structs.tsp.TcTssUuid)
	 */
	public TcTssKmKeyinfo[] enumRegisteredKeys(TcTssUuid keyUuid)
			throws TcTssException {
		preOperations();

		try {
			TcTssKmKeyinfo[] retVal = enumRegisteredKeysImpl(keyUuid);
			postOperations();
			return retVal;
		} catch (TcTssException e) {
			postOperations();
			enforceConsistency();
			throw e;
		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * iaik.tc.tss.impl.ps.TcITssPersistentStorage#getRegisteredKey(iaik.tc.
	 * tss.api.structs.tsp.TcTssUuid)
	 */
	public TcTssKmKeyinfo getRegisteredKey(TcTssUuid keyUuid)
			throws TcTssException {
		preOperations();

		try {
			TcTssKmKeyinfo retVal = getRegisteredKeyImpl(keyUuid);
			postOperations();
			return retVal;
		} catch (TcTssException e) {
			postOperations();
			enforceConsistency();
			throw e;
		}
	}

	// ///////////////////////////////////////////////////////////////
	// 
	// The implementation methods.
	// 
	// ///////////////////////////////////////////////////////////////

	/**
	 * This is the implementation of registerKey() except "pre" and "post"
	 * operations (like getting file system lock, getting database
	 * connection...).
	 * 
	 * @see #registerKey(TcTssUuid, TcTssUuid, TcBlobData)
	 */
	protected abstract void registerKeyImpl(TcTssUuid parentUuid,
			TcTssUuid keyUuid, TcBlobData key) throws TcTssException;

	/**
	 * This is the implementation of unregisterKey() except "pre" and "post"
	 * operations (like getting file system lock, getting database
	 * connection...).
	 * 
	 * @see #unregisterKey(TcTssUuid)
	 */
	protected abstract void unregisterKeyImpl(TcTssUuid keyUuid)
			throws TcTssException;

	/**
	 * This is the implementation of getRegisteredKeyBlob() except "pre" and
	 * "post" operations (like getting file system lock, getting database
	 * connection...).
	 * 
	 * @see #getRegisteredKeyBlob(TcTssUuid)
	 */
	protected abstract TcBlobData getRegisteredKeyBlobImpl(TcTssUuid keyUuid)
			throws TcTssException;

	/**
	 * This is the implementation of getRegisteredKeyByPublicInfo() except "pre"
	 * and "post" operations (like getting file system lock, getting database
	 * connection...).
	 * 
	 * @see #getRegisteredKeyByPublicInfo(long, TcBlobData)
	 */
	protected TcBlobData getRegisteredKeyByPublicInfoImpl(long algId,
			TcBlobData pubKey) throws TcTssException {

		// get all keyinfos
		TcTssKmKeyinfo[] keyInfos = enumRegisteredKeysImpl(null);

		// search them for the right one
		for (int i = 0; i != keyInfos.length; i++) // Enumeration always
													// includes the
		// SRK if started with SRK.
		{
			TcTssUuid currentUuid = keyInfos[i].getKeyUuid();
			TcBlobData currentKeyBlob = getRegisteredKeyBlobImpl(currentUuid);

			// get a valid key structure
			TcITpmKey currentKey;
			TcBlobData tagKey12 = TcBlobData.newByteArray(new byte[] { 0x00,
					TcTpmConstants.TPM_TAG_KEY12 });
			TcBlobData tag = TcBlobData.newByteArray(currentKeyBlob.getRange(0,
					2));

			if (tag.equals(tagKey12)) {
				currentKey = new TcTpmKey12(currentKeyBlob);

			} else {
				TcBlobData ver = TcBlobData.newByteArray(currentKeyBlob
						.getRange(0, 4));
				if (new TcTpmStructVer(ver)
						.equalsMinMaj(TcTpmStructVer.TPM_V1_1)) {
					currentKey = new TcTpmKey(currentKeyBlob);
				} else {
					throw new TcTcsException(TcTcsErrors.TCS_E_BAD_PARAMETER,
							"The given blob seems to be neither a 1.1 nor a 1.2 TPM key blob.");
				}
			}

			long currentAlgorithmId = currentKey.getAlgorithmParms()
					.getAlgorithmID();

			if (currentAlgorithmId != algId) // if the current key is for use
												// with another algorithm, just
												// skip it.
				continue;

			TcBlobData currentPubKeyBlog = currentKey.getPubKey().getKey();
			TcBlobData givenPubKey = (new TcTpmPubkey(pubKey)).getPubKey().getKey();
			
						
			if (currentPubKeyBlog != null && givenPubKey != null && currentPubKeyBlog.equals(givenPubKey)) {
				return currentKeyBlob;
			}

		}

		// not found
		throw new TcTcsException(TcTcsErrors.TCS_E_KEY_NOT_REGISTERED,
				"Key not found by public key in persistent storage.");
	}

	/**
	 * This is the implementation of enumRegisteredKeys() except "pre" and
	 * "post" operations (like getting file system lock, getting database
	 * connection...).
	 * 
	 * @see #enumRegisteredKeys(TcTssUuid)
	 */
	protected abstract TcTssKmKeyinfo[] enumRegisteredKeysImpl(TcTssUuid keyUuid)
			throws TcTssException;

	/**
	 * This is the implementation of getRegisteredKey() except "pre" and "post"
	 * operations (like getting file system lock, getting database
	 * connection...).
	 * 
	 * @see #getRegisteredKey(TcTssUuid)
	 */
	protected TcTssKmKeyinfo getRegisteredKeyImpl(TcTssUuid keyUuid)
			throws TcTssException {

		// First get the complete key blob from disk
		TcBlobData keyBlob = getRegisteredKeyBlobImpl(keyUuid);

		// Determine the version to create proper key objects and version
		// informations
		TcTssKmKeyinfo keyInfo = new TcTssKmKeyinfo();
		TcTssVersion keyVersion = new TcTssVersion();

		TcITpmKey tmpKey;
		TcBlobData tagKey12 = TcBlobData.newByteArray(new byte[] { 0x00,
				TcTpmConstants.TPM_TAG_KEY12 });
		TcBlobData tag = TcBlobData.newByteArray(keyBlob.getRange(0, 2));

		if (tag.equals(tagKey12)) {
			keyVersion.init((short) 0x01, (short) 0x02, (short) 0x00,
					(short) 0x00); // Values according to TSS Spec. V1.2, March
									// 7, 2007, p. 757
			tmpKey = new TcTpmKey12(keyBlob);

		} else {
			TcBlobData ver = TcBlobData.newByteArray(keyBlob.getRange(0, 4));
			if (new TcTpmStructVer(ver).equalsMinMaj(TcTpmStructVer.TPM_V1_1)) {
				keyVersion.init((short) 0x01, (short) 0x01, (short) 0x00,
						(short) 0x00); // Values according to TSS Spec. V1.2,
										// March 7, 2007, p. 757
				tmpKey = new TcTpmKey(keyBlob);
			} else {
				throw new TcTcsException(TcTcsErrors.TCS_E_BAD_PARAMETER,
						"The given blob seems to be neither a 1.1 nor a 1.2 TPM key blob.");
			}
		}

		// Now get the UUID of the parent key from disk
		TcTssUuid parentUuid = getParentUuid(keyUuid);

		// Finally, create the keyInfo structure.

		keyInfo.init(keyVersion, keyUuid, parentUuid,
				tmpKey.getAuthDataUsage(), false, null); // A freshly registered
															// key is at this
															// level assumed not
															// to be loaded yet.
															// No vendor
															// specific data is
															// given.

		return keyInfo;
	}

	// ///////////////////////////////////////////////////////////////
	//
	// Helper methods
	//
	// TODO complete doku
	// ///////////////////////////////////////////////////////////////

	/**
	 * Returns the key hierarchy of a key as ArrayList i.e. the parent of this
	 * key, the parent of the parent and so on.
	 * 
	 * @param keyUuid
	 *            the UUID of the key
	 * @return the key hierarchy of that key as ArrayList
	 * @throws TcTssException
	 *             if an internal error occurs
	 */
	protected abstract ArrayList<String> getHierarchyForRegisteredKey(
			TcTssUuid keyUuid) throws TcTssException;

	/**
	 * Returns the parent of this key.
	 * 
	 * @param childUuid
	 *            the key from which we want to know the parent
	 * @return the parent key
	 * @throws TcTssException
	 */
	protected abstract TcTssUuid getParentUuid(TcTssUuid childUuid)
			throws TcTssException;

	protected abstract void enforceConsistency() throws TcTssException;

	/**
	 * Returns the UUID of the Storage Root Key (SRK)
	 * 
	 * @return the UUID of the SRK
	 */
	protected TcTssUuid getUuidSRK() {
		// Value as defined in TSS Spec.
		return new TcTssUuid().init(0L, 0, 0, (short) 0, (short) 0,
				new short[] { 0, 0, 0, 0, 0, 1 });
	}

}
