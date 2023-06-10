/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.api.tspi;


// TODO: update javadoc of this file!

import iaik.tc.tss.api.constants.tsp.TcTssConstants;
import iaik.tc.tss.api.exceptions.common.TcTssException;
import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.tss.api.structs.tsp.TcTssKmKeyinfo;
import iaik.tc.tss.api.structs.tsp.TcTssUuid;
import iaik.tc.tss.api.structs.tsp.TcTssVersion;

/**
 * The Context class represents a context of a connection to the TSS Core Service running on the
 * local or a remote TCG system. <br/> The focus of the Context object is:<br/>
 * <ul>
 * <li> to provide a connection to a TSS Core Service. There might be multiple connections to the
 * same or different core services.</li>
 * <li> to provide functions for resource management and freeing of memory
 * <li> to create working objects.</li>
 * <li> to establish a default policy for working objects as well as a policy object for the TPM
 * object representing the TPM owner.</li>
 * <li> to provide functionality to access the persistent storage database.</li>
 * </ul>
 */
public interface TcIContext extends TcIWorkingObject, TcIAttributes {

	/*************************************************************************************************
	 * This method tries to connect the context to a host running a TCS service.
	 *
	 * @TSS_V1 80
	 * @TSS_1_2_EA 192
	 *
	 * @param hostname The name of the cost to connect to. For example <code>"http://127.0.0.1:30004/axis/services/TSSCoreServiceBindingImpl"</code>
	 *
	 *
	 */
	public void connect(final String hostname) throws TcTssException;


	/*************************************************************************************************
	 * This method tries to connect the context to the default host (localhost).
	 *
	 * @TSS_V1 80
	 * @TSS_1_2_EA 192
	 *
	 *
	 */
	public void connect() throws TcTssException;


	/*************************************************************************************************
	 * This method returns the status of the context: True is returned if the context is connected,
	 * otherwise false.
	 *
	 * @return boolean indication connections status
	 */
	public boolean isConnected();


	/*************************************************************************************************
	 * This method is used to obtain a TPM object that allows interaction with the system's TPM.
	 *
	 * @TSS_V1 87
	 *
	 * @return TPM object representing the system's TPM
	 *
	 *
	 */
	public TcITpm getTpmObject() throws TcTssException;


	/*************************************************************************************************
	 * This method is used to obtain a Monotonic Counter object that allows interaction with the
   * TPM's counters.
	 *
	 * @TSS_V1 87
	 *
	 * @return Ctr object representing the system's montonic counters 
	 *
	 *
	 */
	public TcIMonotonicCtr getMonotonicCounters(long nvIndex) throws TcTssException;

	/*************************************************************************************************
	 * This method is used to obtain a NV RAM object that allows interaction with the TPM's NV RAM.
	 *
	 * @TSS_V1 87
	 *
	 * @return an object representing the system's NV-RAM
	 *
	 *
	 */
	public TcINvRam getNvRamObject(long nvIndex) throws TcTssException;

	/*************************************************************************************************
	 * This method returns a new key object. It is based on the createObject method of the TSS
	 * specification with the objectType set to {@link TcTssConstants#TSS_OBJECT_TYPE_RSAKEY}.
	 *
	 * @TSS_V1 83
	 *
	 * @TSS_1_2_EA 195
	 *
	 * @param initFlags is used to specify further options for the new object as defined by the TSS
	 *          specification. Key related initialization values are prefixed with TSS_KEY_ and are
	 *          defined in {@link TcTssConstants}. <br>
	 *          Valid initFlags are:
	 *          <ul>
	 *          <li>{@link TcTssConstants#TSS_KEY_SIZE_DEFAULT}</li>
	 *          <li>{@link TcTssConstants#TSS_KEY_SIZE_512}</li>
	 *          <li>{@link TcTssConstants#TSS_KEY_SIZE_1024}</li>
	 *          <li>{@link TcTssConstants#TSS_KEY_SIZE_2048}</li>
	 *          <li>{@link TcTssConstants#TSS_KEY_SIZE_4096}</li>
	 *          <li>{@link TcTssConstants#TSS_KEY_SIZE_8192}</li>
	 *          <li>{@link TcTssConstants#TSS_KEY_SIZE_16384}</li>
	 *          <li>{@link TcTssConstants#TSS_KEY_TYPE_AUTHCHANGE}</li>
	 *          <li>{@link TcTssConstants#TSS_KEY_TYPE_BIND}</li>
	 *          <li>{@link TcTssConstants#TSS_KEY_TYPE_DEFAULT}</li>
	 *          <li>{@link TcTssConstants#TSS_KEY_TYPE_IDENTITY}</li>
	 *          <li>{@link TcTssConstants#TSS_KEY_TYPE_LEGACY} (signing and binding)</li>
	 *          <li>{@link TcTssConstants#TSS_KEY_TYPE_SIGNING}</li>
	 *          <li>{@link TcTssConstants#TSS_KEY_TYPE_STORAGE}</li>
	 *          <li>{@link TcTssConstants#TSS_KEY_NON_VOLATILE}</li>
	 *          <li>{@link TcTssConstants#TSS_KEY_VOLATILE}</li>
	 *          <li>{@link TcTssConstants#TSS_KEY_NOT_MIGRATABLE} (default)</li>
	 *          <li>{@link TcTssConstants#TSS_KEY_MIGRATABLE}</li>
	 *          <li>{@link TcTssConstants#TSS_KEY_CERTIFIED_MIGRATABLE}</li>
	 *          <li>{@link TcTssConstants#TSS_KEY_NOT_CERTIFIED_MIGRATABLE}</li>
	 *          <li>{@link TcTssConstants#TSS_KEY_NO_AUTHORIZATION} (default)</li>
	 *          <li>{@link TcTssConstants#TSS_KEY_AUTHORIZATION}</li>
	 *          <li>{@link TcTssConstants#TSS_KEY_AUTHORIZATION_PRIV_USE_ONLY}</li>
	 *          <li>{@link TcTssConstants#TSS_KEY_STRUCT_DEFAULT} (default)</li>
	 *          <li>{@link TcTssConstants#TSS_KEY_STRUCT_KEY}</li>
	 *          <li>{@link TcTssConstants#TSS_KEY_STRUCT_KEY12}</li>
	 *          <li>{@link TcTssConstants#TSS_KEY_TSP_SRK}</li>
	 *          </ul>
	 *
	 * @return The new key object.
	 *
	 *
	 */
	public TcIRsaKey createRsaKeyObject(final long initFlags) throws TcTssException;


	/*************************************************************************************************
	 * This method returns a new policy object. It is based on the createObject method of the TSS with
	 * TSS_OBJECT_TYPE_POLICY as parameter.
	 *
	 * @TSS_V1 83
	 *
	 * @param initFlags is used to specify further options for the new object as defined by the TSS
	 *          specification. Policy related initialization values are prefixed with TSS_POLICY_ and
	 *          are defined in {@link TcTssConstants}. <br>
	 *          Valid initFlags are:
	 *          <ul>
	 *          <li>{@link TcTssConstants#TSS_POLICY_MIGRATION}</li>
	 *          <li>{@link TcTssConstants#TSS_POLICY_USAGE}</li>
	 *          </ul>
	 * @return the new policy object.
	 *
	 *
	 */
	public TcIPolicy createPolicyObject(final long initFlags) throws TcTssException;


	/*************************************************************************************************
	 * This method returns a new encdata object. It is based on the createObject method of the TSS
	 * with TSS_OBJECT_TYPE_ENCDATA as parameter.
	 *
	 * @TSS_V1 83
	 *
	 * @param initFlags is used to specify further options for the new object as defined by the TSS
	 *          specification. EncData related initialization values are prefixed with TSS_ENCDATA_
	 *          and are defined in {@link TcTssConstants}. <br>
	 *          Valid initFlags are:
	 *          <ul>
	 *          <li>{@link TcTssConstants#TSS_ENCDATA_BIND}</li>
	 *          <li>{@link TcTssConstants#TSS_ENCDATA_SEAL}</li>
	 *          <li>{@link TcTssConstants#TSS_ENCDATA_LEGACY}</li>
	 *          </ul>
	 * @return the new encdata object.
	 *
	 *
	 */
	public TcIEncData createEncDataObject(final long initFlags) throws TcTssException;


	/*************************************************************************************************
	 * This method returns a new PCR object. It is based on the createObject method of the TSS with
	 * TSS_OBJECT_TYPE_PCRS as parameter.
	 *
	 * @TSS_V1 83
	 *
	 * @param initFlags is used to specify further options for the new object as defined by the TSS
	 *          specification. Note: For TSS version 1.1 there is no PCR related init flag defined.
	 *          Consequently, 0 should be used as initFlags parameter.
	 * @return the new pcr object
	 *
	 *
	 */
	public TcIPcrComposite createPcrCompositeObject(final long initFlags) throws TcTssException;


	/*************************************************************************************************
	 * This method returns a new hash object. It is based on the createObject method of the TSS with
	 * TSS_OBJECT_TYPE_HASH as parameter.
	 *
	 * @TSS_V1 83
	 *
	 * @param initFlags is used to specify further options for the new object as defined by the TSS
	 *          specification. Hash related initialization values are prefixed with TSS_HASH_ and are
	 *          defined in {@link TcTssConstants}. <br>
	 *          Valid initFlags are:
	 *          <ul>
	 *          <li>{@link TcTssConstants#TSS_HASH_DEFAULT}</li>
	 *          <li>{@link TcTssConstants#TSS_HASH_OTHER}</li>
	 *          <li>{@link TcTssConstants#TSS_HASH_SHA1}</li>
	 *          </ul>
	 * @return the new hash object.
	 *
	 *
	 */
	public TcIHash createHashObject(final long initFlags) throws TcTssException;


	/*************************************************************************************************
	 * This method returns a new migdata object. It is based on the createObject method of the TSS
	 * with TSS_OBJECT_TYPE_MIGDATA as parameter.
	 *
	 * @TSS_1_2_EA 194
	 *
	 * @param initFlags is used to specify further options for the new object as defined by the TSS
	 *          specification. Note: For TSS version 1.2 there is no migdata related init flag defined.
	 *          Consequently, 0 should be used as initFlags parameter.
	 * @return the new migdata object.
	 *
	 *
	 */
	public TcIMigData createMigDataObject(final long initFlags) throws TcTssException;


	/*************************************************************************************************
	 * This method creates a key object based on the information contained in the key manager using
	 * the UUID and loads the key into the TPM. The persistent storage provides all information to
	 * load the parent keys required to load the key associated with the given UUID. This method tries
	 * to load the requested key from the system storage. 
	 * 
	 * @deprecated Use the getRegisteredKeysByUuid method with TSS_PS_TYPE_SYSTEM as parameter instead. 
	 * @TSS_V1 89
	 *
	 * @param uuid UUID of the key to be loaded.
	 * @return key object representing the loaded key
	 *
	 *
	 */
	public TcIRsaKey loadKeyByUuidFromSystem(final TcTssUuid uuid) throws TcTssException;


	/*************************************************************************************************
	 * This method creates a key object based on the information contained in the key manager using
	 * the UUID and loads the key into the TPM. The persistent storage provides all information to
	 * load the parent keys required to load the key associated with the given UUID. This method tries
	 * to load the requested key from the user storage. 
	 *
	 * @TSS_V1 89
	 *
	 * @deprecated Use the getRegisteredKeysByUuid method with TSS_PS_TYPE_USER as parameter instead.
	 * @param uuid UUID of the key to be loaded.
	 * @return key object representing the loaded key
	 *
	 *
	 */
	public TcIRsaKey loadKeyByUuidFromUser(final TcTssUuid uuid) throws TcTssException;


	/*************************************************************************************************
	 * This method creates a key object based on the information got by the key blob and loads the key
	 * into the TPM which unwraps the key blob utilizing the key addressed by unwrappingKey. The key
	 * addressed by unwrappingKey must have been loaded previously into the TPM.
	 *
	 * @TSS_V1 88
	 *
	 * @TSS_1_2_EA 207
	 *
	 * @param unwrappingKey Key to unwrap the blob.
	 * @param blob Wrapped key blob to load.
	 * @return The created key object.
	 *
	 *
	 */
	public TcIRsaKey loadKeyByBlob(final TcIRsaKey unwrappingKey, final TcBlobData blob)
		throws TcTssException;


	/*************************************************************************************************
	 * This method destroys the object associated with the object handle. All allocated resources
	 * (e.g. objects) associated within the object are also released.
	 *
	 * @TSS_V1 75
	 *
	 *
	 */
	public void closeContext() throws TcTssException;


	/*************************************************************************************************
	 * This method gets an array of key info objects. This information reflects the registered key
	 * hierarchy. The keys stored in the persistent storage are totally independent from either the
	 * context of the function call or the context, which was provided while processing the key
	 * registration.
	 *
	 * @TSS_V1 94
	 *
	 * @param uuid The UUID the key was registered in the persistent storage. If no key UUID is
	 *          provided (null), the returned key info array contains data reflecting the whole key
	 *          hierarchy starting with the root key. If a certain key UUID is provided, the returned
	 *          array only contains data reflecting the path of the key hierarchy regarding that key.
	 *          The first array entry is the key addressed by the given UUID followed by its parent
	 *          key up to the root key.
	 * @param storage Flag indicating the persistent storage the key is registered in
	 *          (TcTssConstatnts.TSS_PS_TYPE_*).
	 * @return Array containing the actual key hierarchy data
	 *
	 *
	 */
	public TcTssKmKeyinfo[] getRegisteredKeysByUuid(final TcTssUuid uuid, final long storage)
		throws TcTssException;


	/*************************************************************************************************
	 * This method is a wrapper for the getRegisteredKeysByUuid method. The storage type is set to
	 * TSS_PS_TYPE_SYSTEM.
	 *
	 * @TSS_V1 94
	 *
	 * @param uuid (see getRegisteredKeysByUuid)
	 * @return (see getRegisteredKeysByUuid)
	 *
	 *
	 */
	public TcTssKmKeyinfo[] getRegisteredKeysByUuidSystem(final TcTssUuid uuid) throws TcTssException;


	/*************************************************************************************************
	 * This method is a wrapper for the getRegisteredKeysByUuid method. The storage type is set to
	 * TSS_PS_TYPE_USER.
	 *
	 * @TSS_V1 94
	 *
	 * @param uuid (see getRegisteredKeysByUuid)
	 * @return (see getRegisteredKeysByUuid)
	 *
	 *
	 */
	public TcTssKmKeyinfo[] getRegisteredKeysByUuidUser(final TcTssUuid uuid) throws TcTssException;


	/*************************************************************************************************
	 * This method provides the default policy object of the context.
	 *
	 * @TSS_V1 82
	 *
	 * @TSS_1_2_EA 194
	 *
	 * @return The default policy object bound to the context.
	 *
	 *
	 */
	public TcIPolicy getDefaultPolicy() throws TcTssException;


	/*************************************************************************************************
	 * This method frees memory allocated by TSS Service Provider on a context base.
	 *
	 * @TSS_V1 81
	 *
	 * @TSS_1_2_EA 193
	 *
	 * @param cPtr The memory block to be freed.
	 */
	public void freeMemory(final long cPtr) throws TcTssException;


	/*************************************************************************************************
	 * This method is used to close a given object.
	 *
	 * @TSS_V1 84
	 *
	 * @param obj The object to be closed.
	 *
	 *
	 */
	public void closeObject(final TcIWorkingObject obj) throws TcTssException;


	/*************************************************************************************************
	 * This method provides the capabilities of the TSS Core Service or TSS Service Provider. This
	 * method returns the capability data as a binary blob.
	 *
	 * @TSS_V1 85
	 *
	 * @param capArea Flag indicating the attribute to query. <br>
	 *
	 * Valid capAreas are:
	 * <ul>
	 * <li>{@link TcTssConstants#TSS_TCSCAP_ALG}</li>
	 * <li>{@link TcTssConstants#TSS_TCSCAP_VERSION}</li>
	 * <li>{@link TcTssConstants#TSS_TCSCAP_CACHING}</li>
	 * <li>{@link TcTssConstants#TSS_TCSCAP_PERSSTORAGE}</li>
	 * <li>{@link TcTssConstants#TSS_TCSCAP_MANUFACTURER}</li>
	 * <li>{@link TcTssConstants#TSS_TSPCAP_ALG}</li>
	 * <li>{@link TcTssConstants#TSS_TSPCAP_VERSION}</li>
	 * <li>{@link TcTssConstants#TSS_TSPCAP_PERSSTORAGE}</li>
	 * <li>{@link TcTssConstants#TSS_TSPCAP_RANDOMLIMIT}</li>
	 * </ul>
	 * @param subCap Data indicating the attribute to query. <br>
	 *
	 * Valid subCaps are:
	 * <ul>
	 * <li>TcTssConstants.TSS_ALG_XXX</li>
	 * <li>{@link TcTssConstants#TSS_TCSCAP_PROP_KEYCACHE}</li>
	 * <li>{@link TcTssConstants#TSS_TCSCAP_PROP_AUTHCACHE}</li>
	 * <li>{@link TcTssConstants#TSS_TCSCAP_PROP_MANUFACTURER_ID}</li>
	 * <li>{@link TcTssConstants#TSS_TCSCAP_PROP_MANUFACTURER_STR}</li>
	 * </ul>
	 * @return capability blob
	 *
	 *
	 */
	public TcBlobData getCapability(final long capArea, final TcBlobData subCap)
		throws TcTssException;


	/*************************************************************************************************
	 * This method provides the capabilities of the TSS Core Service or TSS Service Provider. This
	 * method is to be used to read boolean flags.
	 *
	 * @TSS_V1 85
	 *
	 * @param capArea Flag indicating the attribute to query. <br>
	 *
	 * Valid capAreas are:
	 * <ul>
	 * <li>{@link TcTssConstants#TSS_TCSCAP_ALG}</li>
	 * <li>{@link TcTssConstants#TSS_TCSCAP_PERSSTORAGE}</li>
	 * <li>{@link TcTssConstants#TSS_TCSCAP_CACHING}</li>
	 * <li>{@link TcTssConstants#TSS_TSPCAP_ALG}</li>
	 * <li>{@link TcTssConstants#TSS_TSPCAP_PERSSTORAGE}</li>
	 * </ul>
	 * @param subCap Data indicating the attribute to query. <br>
	 *
	 * Valid subCaps are:
	 * <ul>
	 * <li>TcTssConstants.TSS_ALG_XXX</li>
	 * <li>{@link TcTssConstants#TSS_TCSCAP_PROP_KEYCACHE}</li>
	 * <li>{@link TcTssConstants#TSS_TCSCAP_PROP_AUTHCACHE}</li>
	 * </ul>
	 * @return boolean value
	 *
	 *
	 */
	public boolean getCapabilityBoolean(final long capArea, final TcBlobData subCap)
		throws TcTssException;


	/*************************************************************************************************
	 * This method provides the capabilities of the TSS Core Service or TSS Service Provider. This
	 * method is to be used to read version flags.
	 *
	 * @TSS_V1 85
	 *
	 * @param capArea Flag indicating the attribute to query. <br>
	 *
	 * Valid capAreas are:
	 * <ul>
	 * <li>{@link TcTssConstants#TSS_TCSCAP_VERSION}</li>
	 * <li>{@link TcTssConstants#TSS_TSPCAP_VERSION}</li>
	 * </ul>
	 * @param subCap Data indicating the attribute to query
	 * @return version object
	 */
	public TcTssVersion getCapabilityVersion(final long capArea, final TcBlobData subCap)
		throws TcTssException;


	/*************************************************************************************************
	 * This method registers a key in the TSS Persistent Storage database.
	 *
	 * @TSS_V1 90
	 *
	 * @param key Handle of the key object addressing the key to be registered.
	 * @param stypeKey Flag indicating the persistent storage
	 * @param uuidKey UUID by which the key is registered in the persistent storage
	 * @param stypeParentKey Flag indicating the persistent storage
	 * @param uuidParent UUID by which the parent key was registered in the persistent storage
	 */
	public void registerKey(final TcIRsaKey key, final long stypeKey, final TcTssUuid uuidKey,
			final long stypeParentKey, final TcTssUuid uuidParent) throws TcTssException;


	/*************************************************************************************************
	 * This method unregisters a key from the persistent storage database.
	 *
	 * @TSS_V1 91
	 *
	 * @param stypeKey Flag indicating the persistent storage
	 * @param uuidKey UUID of the key to be removed from the persistent storage
	 * @return key object containing the info from the archive
	 */
	public TcIRsaKey unregisterKey(final long stypeKey, final TcTssUuid uuidKey)
		throws TcTssException;


	/*************************************************************************************************
	 * This method searches the persistent storage for a registered key using the provided UUID and
	 * creates a key object initialized according to the found data. On successful completion of the
	 * method a handle to the created new key object is returned.
	 *
	 * @TSS_V1 92
	 *
	 * @param stypeKey Flag indicating the persistent storage
	 * @param uuidKey UUID of the key by which the key was registered in the persistent storage
	 * @return key object representing the key
	 */
	public TcIRsaKey getKeyByUuid(final long stypeKey, final TcTssUuid uuidKey) throws TcTssException;


	/*************************************************************************************************
	 * This method searches the persistent storage for a registered key using the provided public key
	 * information and creates a key object initialized according to the found data. On successful
	 * completion of the method a handle to the created new key object is returned.
	 *
	 * NOTE: The returned key structure does not carry a UUID.
	 *
	 * @TSS_V1 93
	 *
	 * @param stypeKey Flag indicating the persistent storage.
	 * @param algId Parameter indicates the algorithm of the requested key.
	 * @param publicInfo Public key info provided to identify the key to be looked for.
	 * @return Object representing the key.
	 */
	public TcIRsaKey getKeyByPublicInfo(final long stypeKey, final long algId,
			final TcBlobData publicInfo) throws TcTssException;

}