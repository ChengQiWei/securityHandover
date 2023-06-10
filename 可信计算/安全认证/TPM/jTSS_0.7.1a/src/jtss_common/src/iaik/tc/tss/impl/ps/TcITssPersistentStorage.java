/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler, Thomas Holzmann
 */

package iaik.tc.tss.impl.ps;


import iaik.tc.tss.api.exceptions.common.TcTssException;
import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.tss.api.structs.tsp.TcTssKmKeyinfo;
import iaik.tc.tss.api.structs.tsp.TcTssUuid;

public interface TcITssPersistentStorage {

	/**
	 * Registers the key in persistent storage.
	 * @param parentUuid the parent from the actual key
	 * @param keyUuid the UUID assigned to the key (has to be unique!)
	 * @param key the key value
	 * @throws TcTssException if registration failed
	 */
	public abstract void registerKey(TcTssUuid parentUuid, TcTssUuid keyUuid, TcBlobData key)
		throws TcTssException;

	/**
	 * Unregisters the key in persistent storage.
	 * @param keyUuid the UUID assigned to this key
	 * @throws TcTssException if unregister key failed
	 */
	public abstract void unregisterKey(TcTssUuid keyUuid) throws TcTssException;

	/**
	 * Gets the key blob from the key described by this UUID
	 * @param keyUuid the UUID assigned to the desired key
	 * @return a key blob containing the key with the given UUID
	 * @throws TcTssException if getting key blob failed
	 */
	public abstract TcBlobData getRegisteredKeyBlob(TcTssUuid keyUuid) throws TcTssException;

	/**
	 * TODO complete documentation
	 * 
	 * Returns a key blob described by the given public key and its algorithm
	 * @param algId the id describing the algorithm which belongs to the given key
	 * @param pubKey the given public key
	 * @return a blob containing the public info for the key
	 * @throws TcTssException
	 */
	public abstract TcBlobData getRegisteredKeyByPublicInfo(long algId, TcBlobData pubKey) throws TcTssException;

	/**
	 * Returns the whole key hierarchy of the given key i.e. all its 
	 * parents as TcTssKmKeyinfo[]. 
	 * @param keyUuid the UUID of the desired key
	 * @return the whole key hierarchy of the key. If the committed key
	 * value is null, all registered keys are returned.
	 * @throws TcTssException if the keys cannot be read out correctly
	 */
	public abstract TcTssKmKeyinfo[] enumRegisteredKeys(TcTssUuid keyUuid) throws TcTssException;

	/**
	 * Returns information on a registered key.
	 * @param keyUuid is the key to get information on
	 * @return ATTENTION: The isLoaded field of TcTssKmKeyinfo is always <code>false</code> upon return, because the
	 *  persistent storage has no way of knowing what the key manager is actually doing. No vendor specific data is
	 *  given. 
	 * @throws TcTssException
	 */
	public abstract TcTssKmKeyinfo getRegisteredKey(TcTssUuid keyUuid) throws TcTssException;

}