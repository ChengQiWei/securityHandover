/**
 * Copyright (C) 2007-2008 IAIK, Graz University of Technology
 * authors: Ronald Toegl, Thomas Holzmann
 */

package iaik.tc.tss.test.tsp.java.persistentstorage;

import iaik.tc.tss.api.constants.tsp.TcTssConstants;
import iaik.tc.tss.api.exceptions.common.TcTssException;
import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.tss.api.structs.tsp.TcTssUuid;
import iaik.tc.tss.api.structs.tsp.TcUuidFactory;
import iaik.tc.tss.api.tspi.TcIPolicy;
import iaik.tc.tss.api.tspi.TcIRsaKey;
import iaik.tc.tss.api.tspi.TcITpm;
import iaik.tc.tss.api.structs.tsp.TcTssKmKeyinfo;
import iaik.tc.tss.test.tsp.java.TestCommon;
import iaik.tc.tss.test.tsp.java.TestDefines;
import iaik.tc.utils.logging.Log;

/**
 * @author rtoegl
 *
 */
public class TestPersistentStorage extends TestCommon {

	/**
	 * Registers a key in the system persistent storage (i.e. a file should be
	 * generated), reads it back and finally unregisters it.
	 */
	public void testGetKeyByPublicInfoFromSystemPersistentStorage() {

		try {
			// Generate Key & assign policy

			TcBlobData keySecret = TcBlobData.newString("opentc");

			TcIRsaKey key = context_
					.createRsaKeyObject(TcTssConstants.TSS_KEY_SIZE_2048
							| TcTssConstants.TSS_KEY_TYPE_STORAGE
							| TcTssConstants.TSS_KEY_VOLATILE
							| TcTssConstants.TSS_KEY_NOT_MIGRATABLE
							| TcTssConstants.TSS_KEY_AUTHORIZATION
							| TcTssConstants.TSS_KEY_STRUCT_KEY);

			TcIPolicy keyUsgPolicy = context_
					.createPolicyObject(TcTssConstants.TSS_POLICY_USAGE);
			TcIPolicy keyMigPolicy = context_
					.createPolicyObject(TcTssConstants.TSS_POLICY_MIGRATION);
			keyUsgPolicy.setSecret(TcTssConstants.TSS_SECRET_MODE_PLAIN,
					keySecret);
			keyMigPolicy.setSecret(TcTssConstants.TSS_SECRET_MODE_PLAIN,
					keySecret);
			keyUsgPolicy.assignToObject(key);
			keyMigPolicy.assignToObject(key);

			key.createKey(srk_, null);

			// Generate Key 2 & assign policy. it is wrapped by key 1

			TcBlobData keySecret2 = TcBlobData.newString("opentc");

			TcIRsaKey key2 = context_
					.createRsaKeyObject(TcTssConstants.TSS_KEY_SIZE_2048
							| TcTssConstants.TSS_KEY_TYPE_STORAGE
							| TcTssConstants.TSS_KEY_VOLATILE
							| TcTssConstants.TSS_KEY_NOT_MIGRATABLE
							| TcTssConstants.TSS_KEY_AUTHORIZATION
							| TcTssConstants.TSS_KEY_STRUCT_KEY);

			TcIPolicy keyUsgPolicy2 = context_
					.createPolicyObject(TcTssConstants.TSS_POLICY_USAGE);
			TcIPolicy keyMigPolicy2 = context_
					.createPolicyObject(TcTssConstants.TSS_POLICY_MIGRATION);
			keyUsgPolicy2.setSecret(TcTssConstants.TSS_SECRET_MODE_PLAIN,
					keySecret2);
			keyMigPolicy2.setSecret(TcTssConstants.TSS_SECRET_MODE_PLAIN,
					keySecret2);
			keyUsgPolicy2.assignToObject(key2);
			keyMigPolicy2.assignToObject(key2);

			// Store it in the System persistent storage

			TcTssUuid keyUUID = TcUuidFactory.getInstance()
					.generateRandomUuid();
			TcTssUuid keyUUID2 = TcUuidFactory.getInstance()
					.generateRandomUuid();

			assertFalse(keyUUID.equals(keyUUID2));

			context_.registerKey(key2, TcTssConstants.TSS_PS_TYPE_USER,
					keyUUID2, TcTssConstants.TSS_PS_TYPE_SYSTEM, TcUuidFactory
							.getInstance().getUuidSRK());
			Log.info("key2 registered in persistent user storage with "
					+ keyUUID2.toString());

			context_.registerKey(key, TcTssConstants.TSS_PS_TYPE_SYSTEM,
					keyUUID, TcTssConstants.TSS_PS_TYPE_SYSTEM, TcUuidFactory
							.getInstance().getUuidSRK());
			Log.info("key registered in persistent system storage with "
					+ keyUUID.toString());

			// retrieve the key again and compare if they have the same UUID

			long algorithm = key.getAttribUint32(
					TcTssConstants.TSS_TSPATTRIB_KEY_INFO,
					TcTssConstants.TSS_TSPATTRIB_KEYINFO_ALGORITHM);

			TcBlobData publicKey = key.getPubKey();

			TcIRsaKey returnedSecondKey = context_.getKeyByPublicInfo(
					TcTssConstants.TSS_PS_TYPE_SYSTEM, algorithm, publicKey);

			assertTrue(key.getAttribKeyInfoVersion().equals(
					returnedSecondKey.getAttribKeyInfoVersion()));
			assertTrue(key.getPubKey().equals(returnedSecondKey.getPubKey()));

			// remove key from PS

			context_.unregisterKey(TcTssConstants.TSS_PS_TYPE_SYSTEM, keyUUID);

		} catch (TcTssException e) {
			if (PRINT_TRACE) {
				Log.err(e);
			}
			assertTrue(
					"Could not retrieve key by public key from system persistent storage",
					false);
		}

	}

	// Test case for a complete key hierarchy. It follows the hierarchy in the
	// standard.
	public void NOtestKeyHierarchyInitializationAndKeyLoading() {

		try {

			// **********************
			// *** Generate UUIDs ***
			// **********************

			TcTssUuid keyPKUuid = TcUuidFactory.getInstance()
					.generateRandomUuid();
			TcTssUuid keySKUuid = TcUuidFactory.getInstance().getUuidSK();

			TcTssUuid keyU1SK1Uuid = TcUuidFactory.getInstance().getUuidU1SK1();
			TcTssUuid keyU1K1Uuid = TcUuidFactory.getInstance()
					.generateRandomUuid();

			// *********************
			// *** Generate Keys ***
			// *********************

			// Generate Key 1 & assign policy

			TcBlobData keySecret = TcBlobData.newString("key1");

			TcIRsaKey keyPK = context_
					.createRsaKeyObject(TcTssConstants.TSS_KEY_SIZE_2048
							| TcTssConstants.TSS_KEY_TYPE_STORAGE
							| TcTssConstants.TSS_KEY_VOLATILE
							| TcTssConstants.TSS_KEY_NOT_MIGRATABLE
							| TcTssConstants.TSS_KEY_AUTHORIZATION);

			TcIPolicy keyUsgPolicy = context_
					.createPolicyObject(TcTssConstants.TSS_POLICY_USAGE);
			TcIPolicy keyMigPolicy = context_
					.createPolicyObject(TcTssConstants.TSS_POLICY_MIGRATION);
			keyUsgPolicy.setSecret(TcTssConstants.TSS_SECRET_MODE_PLAIN,
					keySecret);
			keyMigPolicy.setSecret(TcTssConstants.TSS_SECRET_MODE_PLAIN,
					keySecret);
			keyUsgPolicy.assignToObject(keyPK);
			keyMigPolicy.assignToObject(keyPK);

			// Generate Key 2 & assign policy. it is wrapped by key 1

			TcBlobData keySecret2 = TcBlobData.newString("key2");

			TcIRsaKey keySK = context_
					.createRsaKeyObject(TcTssConstants.TSS_KEY_SIZE_2048
							| TcTssConstants.TSS_KEY_TYPE_STORAGE
							| TcTssConstants.TSS_KEY_VOLATILE
							| TcTssConstants.TSS_KEY_NOT_MIGRATABLE
							| TcTssConstants.TSS_KEY_AUTHORIZATION);

			TcIPolicy keyUsgPolicy2 = context_
					.createPolicyObject(TcTssConstants.TSS_POLICY_USAGE);
			TcIPolicy keyMigPolicy2 = context_
					.createPolicyObject(TcTssConstants.TSS_POLICY_MIGRATION);
			keyUsgPolicy2.setSecret(TcTssConstants.TSS_SECRET_MODE_PLAIN,
					keySecret2);
			keyMigPolicy2.setSecret(TcTssConstants.TSS_SECRET_MODE_PLAIN,
					keySecret2);
			keyUsgPolicy2.assignToObject(keySK);
			keyMigPolicy2.assignToObject(keySK);

			// User Key 1 & assign policy. it is wrapped by system key 2

			TcBlobData userKeySecret1 = TcBlobData.newString("key3");

			TcIRsaKey keyU1SK1 = context_
					.createRsaKeyObject(TcTssConstants.TSS_KEY_SIZE_2048
							| TcTssConstants.TSS_KEY_TYPE_STORAGE
							| TcTssConstants.TSS_KEY_VOLATILE
							| TcTssConstants.TSS_KEY_NOT_MIGRATABLE
							| TcTssConstants.TSS_KEY_AUTHORIZATION);

			TcIPolicy userKeyUsgPolicy1 = context_
					.createPolicyObject(TcTssConstants.TSS_POLICY_USAGE);
			TcIPolicy userKeyMigPolicy1 = context_
					.createPolicyObject(TcTssConstants.TSS_POLICY_MIGRATION);
			userKeyUsgPolicy1.setSecret(TcTssConstants.TSS_SECRET_MODE_PLAIN,
					userKeySecret1);
			userKeyMigPolicy1.setSecret(TcTssConstants.TSS_SECRET_MODE_PLAIN,
					userKeySecret1);
			userKeyUsgPolicy1.assignToObject(keyU1SK1);
			userKeyMigPolicy1.assignToObject(keyU1SK1);

			// User Key 2 & assign policy. it is wrapped by user key 1

			TcBlobData userKeySecret2 = TcBlobData.newString("key4");

			TcIRsaKey keyU1K1 = context_
					.createRsaKeyObject(TcTssConstants.TSS_KEY_SIZE_2048
							| TcTssConstants.TSS_KEY_TYPE_STORAGE
							| TcTssConstants.TSS_KEY_VOLATILE
							| TcTssConstants.TSS_KEY_NOT_MIGRATABLE
							| TcTssConstants.TSS_KEY_AUTHORIZATION);

			TcIPolicy userKeyUsgPolicy2 = context_
					.createPolicyObject(TcTssConstants.TSS_POLICY_USAGE);
			TcIPolicy userKeyMigPolicy2 = context_
					.createPolicyObject(TcTssConstants.TSS_POLICY_MIGRATION);
			userKeyUsgPolicy2.setSecret(TcTssConstants.TSS_SECRET_MODE_PLAIN,
					userKeySecret2);
			userKeyMigPolicy2.setSecret(TcTssConstants.TSS_SECRET_MODE_PLAIN,
					userKeySecret2);
			userKeyUsgPolicy2.assignToObject(keyU1K1);
			userKeyMigPolicy2.assignToObject(keyU1K1);

			// ***********************
			// *** Load Keys in TPM***
			// ***********************

			keyPK.createKey(srk_, null);
			keyPK.loadKey(srk_);

			keySK.createKey(keyPK, null);
			keySK.loadKey(keyPK);

			keyU1SK1.createKey(keySK, null);
			keyU1SK1.loadKey(keySK);

			keyU1K1.createKey(keyU1SK1, null);
			keyU1K1.loadKey(keyU1SK1);

			// ****************************
			// *** Store the Keys in PS ***
			// ****************************

			context_.registerKey(keyPK, TcTssConstants.TSS_PS_TYPE_SYSTEM,
					keyPKUuid, TcTssConstants.TSS_PS_TYPE_SYSTEM, TcUuidFactory
							.getInstance().getUuidSRK());
			Log.info("key1 registered in persistent system storage with "
					+ keyPKUuid.toString());

			context_.registerKey(keySK, TcTssConstants.TSS_PS_TYPE_SYSTEM,
					keySKUuid, TcTssConstants.TSS_PS_TYPE_SYSTEM, keyPKUuid);
			Log.info("key2 registered in persistent system storage with "
					+ keySKUuid.toString());

			context_.registerKey(keyU1SK1, TcTssConstants.TSS_PS_TYPE_USER,
					keyU1SK1Uuid, TcTssConstants.TSS_PS_TYPE_SYSTEM, keySKUuid);
			Log.info("user key1 registered in persistent user storage with "
					+ keyU1SK1Uuid.toString());

			context_.registerKey(keyU1K1, TcTssConstants.TSS_PS_TYPE_USER,
					keyU1K1Uuid, TcTssConstants.TSS_PS_TYPE_USER, keyU1SK1Uuid);
			Log.info("user key2 registered in persistent user storage with "
					+ keyU1K1Uuid.toString());

			// ****************************
			// *** Unload keys from TPM ***
			// ****************************

			keyPK.unloadKey();
			keySK.unloadKey();
			keyU1SK1.unloadKey();
			keyU1K1.unloadKey();

			// *******************************
			// *** Check created Hierarchy ***
			// *******************************

			// At first for the system keys

			TcTssKmKeyinfo[] keyInfos = context_.getRegisteredKeysByUuid(null,
					TcTssConstants.TSS_PS_TYPE_SYSTEM);

			boolean key1Found = false;
			boolean key2Found = false;
			boolean srkFound = false;

			for (int i = 0; i != keyInfos.length; i++) {

				if (keyInfos[i].getKeyUuid().equals(keyPKUuid))
					key1Found = true;
				if (keyInfos[i].getKeyUuid().equals(keySKUuid))
					key2Found = true;
				if (keyInfos[i].getKeyUuid().equals(
						TcUuidFactory.getInstance().getUuidSRK()))
					srkFound = true;

			}

			assertTrue(key1Found && key2Found);
			// assertTrue(
			// "The SRK is not included in the system persistent storage. Make sure the PS is properly configured and either extract and store the SRK or retake ownership."
			// ,srkFound);

			if (!srkFound) {
				Log
						.info("The SRK is not included in the system persistent storage. It is now being extracted and stored...");
				ownerGetSRKPubKeyAndStore();
			}

			// then for the user keys

			TcTssKmKeyinfo[] userKeyInfos = context_.getRegisteredKeysByUuid(
					null, TcTssConstants.TSS_PS_TYPE_USER);

			boolean userKey1Found = false;
			boolean userKey2Found = false;

			for (int i = 0; i != userKeyInfos.length; i++) {

				if (userKeyInfos[i].getKeyUuid().equals(keyU1SK1Uuid))
					userKey1Found = true;
				if (userKeyInfos[i].getKeyUuid().equals(keyU1K1Uuid))
					userKey2Found = true;

			}

			assertTrue(userKey1Found && userKey2Found);

			// Now check the correct order

			TcTssKmKeyinfo[] hierarchy = context_.getRegisteredKeysByUuid(
					keyU1K1Uuid, TcTssConstants.TSS_PS_TYPE_USER);

			assertTrue(
					"The generated Key hierarchy does not have the correct length.",
					hierarchy.length == 5);

			assertTrue(hierarchy[0].getKeyUuid().equals(keyU1K1Uuid));
			assertTrue(hierarchy[1].getKeyUuid().equals(keyU1SK1Uuid));
			assertTrue(hierarchy[2].getKeyUuid().equals(keySKUuid));
			assertTrue(hierarchy[3].getKeyUuid().equals(keyPKUuid));
			assertTrue(hierarchy[4].getKeyUuid().equals(
					TcUuidFactory.getInstance().getUuidSRK()));

			// *************************
			// *** Load Keys from PS ***
			// *************************

			/*
			 * Here all keys need authorization, therefore the the application
			 * must be fully aware of the hierarchy. Each key along the
			 * hierarchy must be retrieved from the PS storage. Then the proper
			 * authorization secret must be set. Finally the key object can be
			 * loaded and used to unwrap the next key.
			 */

			// Key PK
			TcIRsaKey keyPKRetrieved = context_.getKeyByUuid(
					TcTssConstants.TSS_PS_TYPE_SYSTEM, keyPKUuid);

			TcBlobData keyPKLoadedSecret = TcBlobData.newString("key1");
			TcIPolicy keyPKLoadedPolicy = context_
					.createPolicyObject(TcTssConstants.TSS_POLICY_USAGE);
			keyPKLoadedPolicy.setSecret(TcTssConstants.TSS_SECRET_MODE_PLAIN,
					keyPKLoadedSecret);
			keyPKLoadedPolicy.assignToObject(keyPKRetrieved);

			keyPKRetrieved.loadKey(srk_);

			// Key SK

			TcIRsaKey keySKRetrieved = context_.getKeyByUuid(
					TcTssConstants.TSS_PS_TYPE_SYSTEM, keySKUuid);

			TcBlobData keySKLoadedSecret = TcBlobData.newString("key2");
			TcIPolicy keySKLoadedPolicy = context_
					.createPolicyObject(TcTssConstants.TSS_POLICY_USAGE);
			keySKLoadedPolicy.setSecret(TcTssConstants.TSS_SECRET_MODE_PLAIN,
					keySKLoadedSecret);
			keySKLoadedPolicy.assignToObject(keySKRetrieved);

			keySKRetrieved.loadKey(keyPKRetrieved);

			// Key U1SK1

			TcIRsaKey keyU1SK1Retrieved = context_.getKeyByUuid(
					TcTssConstants.TSS_PS_TYPE_USER, keyU1SK1Uuid);

			TcBlobData keyU1SK1LoadedSecret = TcBlobData.newString("key3");
			TcIPolicy keyU1SK1LoadedPolicy = context_
					.createPolicyObject(TcTssConstants.TSS_POLICY_USAGE);
			keyU1SK1LoadedPolicy.setSecret(
					TcTssConstants.TSS_SECRET_MODE_PLAIN, keyU1SK1LoadedSecret);
			keyU1SK1LoadedPolicy.assignToObject(keyU1SK1Retrieved);

			keyU1SK1Retrieved.loadKey(keySKRetrieved);

			// Key U1K1

			TcIRsaKey keyU1K1Retrieved = context_.getKeyByUuid(
					TcTssConstants.TSS_PS_TYPE_USER, keyU1K1Uuid);

			TcBlobData keyU1K1LoadedSecret = TcBlobData.newString("key4");
			TcIPolicy keyU1K1LoadedPolicy = context_
					.createPolicyObject(TcTssConstants.TSS_POLICY_USAGE);
			keyU1K1LoadedPolicy.setSecret(TcTssConstants.TSS_SECRET_MODE_PLAIN,
					keyU1K1LoadedSecret);
			keyU1K1LoadedPolicy.assignToObject(keyU1K1Retrieved);

			keyU1K1Retrieved.loadKey(keyU1SK1Retrieved);

			// make sure the correct keys are retrieved

			assertTrue(keyU1K1Retrieved.getPubKey().toHexString().equals(
					keyU1K1.getPubKey().toHexString()));
			assertTrue(keyU1SK1Retrieved.getPubKey().toHexString().equals(
					keyU1SK1.getPubKey().toHexString()));
			assertTrue(keySKRetrieved.getPubKey().toHexString().equals(
					keySK.getPubKey().toHexString()));
			assertTrue(keyPKRetrieved.getPubKey().toHexString().equals(
					keyPK.getPubKey().toHexString()));

			// ***************************
			// *** Remove Keys from PS ***
			// ***************************

			context_
					.unregisterKey(TcTssConstants.TSS_PS_TYPE_SYSTEM, keyPKUuid);
			context_
					.unregisterKey(TcTssConstants.TSS_PS_TYPE_SYSTEM, keySKUuid);

			context_.unregisterKey(TcTssConstants.TSS_PS_TYPE_USER,
					keyU1SK1Uuid);
			context_
					.unregisterKey(TcTssConstants.TSS_PS_TYPE_USER, keyU1K1Uuid);

		} catch (TcTssException e) {
			if (PRINT_TRACE) {
				Log.err(e);
			}
			assertTrue(
					"Unable to test user and system persistent key hierarchy.",
					false);
		}
	}

	/*************************************************************************************************
	 * Extracts the public portion of the SRK and stores it in the system
	 * persistent storage.
	 */
	public void ownerGetSRKPubKeyAndStore() {
		try {

			TcITpm tpm = context_.getTpmObject();
			TestDefines.tpmPolicy.assignToObject(tpm);

			TcIRsaKey srkPublic = context_.getTpmObject().OwnerGetSRKPubKey();

			TcTssUuid keyUUID1 = TcUuidFactory.getInstance().getUuidSRK();

			context_.registerKey(srkPublic, TcTssConstants.TSS_PS_TYPE_SYSTEM,
					keyUUID1, TcTssConstants.TSS_PS_TYPE_SYSTEM, TcUuidFactory
							.getInstance().getUuidSRK());
			Log.info("SRK registered in persistent system storage with "
					+ keyUUID1.toString());

		} catch (TcTssException e) {
			if (PRINT_TRACE) {
				Log.err(e);
				assertTrue(
						"Could not extract or store SRK key public part. (This requires a 1.2 TPM).",
						false);
			}
		}
	}

	/**
	 * Registers 2 keys in the system persistent storage (i.e. a file should be
	 * generated), retrieves the overall hierarchy and checks if they are
	 * returned and finally unregisters them.
	 */
	public void testGetRegisterKeysInSystemPersistentStorageSimpleTest() {

		try {
			// Generate Key 1 & assign policy

			TcBlobData keySecret = TcBlobData.newString("opentc");

			TcIRsaKey key1 = context_
					.createRsaKeyObject(TcTssConstants.TSS_KEY_SIZE_2048
							| TcTssConstants.TSS_KEY_TYPE_STORAGE
							| TcTssConstants.TSS_KEY_VOLATILE
							| TcTssConstants.TSS_KEY_NOT_MIGRATABLE
							| TcTssConstants.TSS_KEY_AUTHORIZATION);

			TcIPolicy keyUsgPolicy = context_
					.createPolicyObject(TcTssConstants.TSS_POLICY_USAGE);
			TcIPolicy keyMigPolicy = context_
					.createPolicyObject(TcTssConstants.TSS_POLICY_MIGRATION);
			keyUsgPolicy.setSecret(TcTssConstants.TSS_SECRET_MODE_PLAIN,
					keySecret);
			keyMigPolicy.setSecret(TcTssConstants.TSS_SECRET_MODE_PLAIN,
					keySecret);
			keyUsgPolicy.assignToObject(key1);
			keyMigPolicy.assignToObject(key1);

			key1.createKey(srk_, null);

			// Generate Key 2 & assign policy

			TcBlobData keySecret2 = TcBlobData.newString("opentc2");

			TcIRsaKey key2 = context_
					.createRsaKeyObject(TcTssConstants.TSS_KEY_SIZE_2048
							| TcTssConstants.TSS_KEY_TYPE_STORAGE
							| TcTssConstants.TSS_KEY_VOLATILE
							| TcTssConstants.TSS_KEY_NOT_MIGRATABLE
							| TcTssConstants.TSS_KEY_AUTHORIZATION);

			TcIPolicy keyUsgPolicy2 = context_
					.createPolicyObject(TcTssConstants.TSS_POLICY_USAGE);
			TcIPolicy keyMigPolicy2 = context_
					.createPolicyObject(TcTssConstants.TSS_POLICY_MIGRATION);
			keyUsgPolicy2.setSecret(TcTssConstants.TSS_SECRET_MODE_PLAIN,
					keySecret2);
			keyMigPolicy2.setSecret(TcTssConstants.TSS_SECRET_MODE_PLAIN,
					keySecret2);
			keyUsgPolicy2.assignToObject(key2);
			keyMigPolicy2.assignToObject(key2);

			key2.createKey(srk_, null);

			// Store both in the System persistent storage

			TcTssUuid keyUUID1 = TcUuidFactory.getInstance()
					.generateRandomUuid();
			TcTssUuid keyUUID2 = TcUuidFactory.getInstance()
					.generateRandomUuid();

			assertFalse(keyUUID1.equals(keyUUID2));

			context_.registerKey(key1, TcTssConstants.TSS_PS_TYPE_SYSTEM,
					keyUUID1, TcTssConstants.TSS_PS_TYPE_SYSTEM, TcUuidFactory
							.getInstance().getUuidSRK());
			Log.info("key1 registered in persistent system storage with "
					+ keyUUID1.toString());

			context_.registerKey(key2, TcTssConstants.TSS_PS_TYPE_SYSTEM,
					keyUUID2, TcTssConstants.TSS_PS_TYPE_SYSTEM, TcUuidFactory
							.getInstance().getUuidSRK());
			Log.info("key2 registered in persistent system storage with "
					+ keyUUID2.toString());

			// retrieve the key again and compare if they contain the same
			// public key

			TcTssKmKeyinfo[] keyInfos = context_.getRegisteredKeysByUuid(null,
					TcTssConstants.TSS_PS_TYPE_SYSTEM);

			boolean key1Found = false;
			boolean key2Found = false;

			for (int i = 0; i != keyInfos.length; i++) {

				if (keyInfos[i].getKeyUuid().equals(keyUUID1))
					key1Found = true;
				if (keyInfos[i].getKeyUuid().equals(keyUUID2))
					key2Found = true;

			}

			assertTrue(key1Found && key2Found);

			// remove keys from PS

			context_.unregisterKey(TcTssConstants.TSS_PS_TYPE_SYSTEM, keyUUID1);
			context_.unregisterKey(TcTssConstants.TSS_PS_TYPE_SYSTEM, keyUUID2);

		} catch (TcTssException e) {
			if (PRINT_TRACE) {
				Log.err(e);
			}
			assertTrue(
					"unable to retrieve key info enumeration of keys registered in system persistent storage",
					false);
		}

	}

	/**
	 * Registers 2 keys in the user persistent storage (i.e. a file should be
	 * generated), retrieves the overall hierarchy and checks if they are
	 * returned and finally unregisters them.
	 */
	public void testGetRegisterKeysInUserPersistentStorageSimpleTest() {

		try {

			// Generate Key 1 & assign policy

			TcBlobData keySecret = TcBlobData.newString("opentc");

			TcIRsaKey key1 = context_
					.createRsaKeyObject(TcTssConstants.TSS_KEY_SIZE_2048
							| TcTssConstants.TSS_KEY_TYPE_STORAGE
							| TcTssConstants.TSS_KEY_VOLATILE
							| TcTssConstants.TSS_KEY_NOT_MIGRATABLE
							| TcTssConstants.TSS_KEY_AUTHORIZATION);

			TcIPolicy keyUsgPolicy = context_
					.createPolicyObject(TcTssConstants.TSS_POLICY_USAGE);
			TcIPolicy keyMigPolicy = context_
					.createPolicyObject(TcTssConstants.TSS_POLICY_MIGRATION);
			keyUsgPolicy.setSecret(TcTssConstants.TSS_SECRET_MODE_PLAIN,
					keySecret);
			keyMigPolicy.setSecret(TcTssConstants.TSS_SECRET_MODE_PLAIN,
					keySecret);
			keyUsgPolicy.assignToObject(key1);
			keyMigPolicy.assignToObject(key1);

			key1.createKey(srk_, null);

			// Generate Key 2 & assign policy

			TcBlobData keySecret2 = TcBlobData.newString("opentc");

			TcIRsaKey key2 = context_
					.createRsaKeyObject(TcTssConstants.TSS_KEY_SIZE_2048
							| TcTssConstants.TSS_KEY_TYPE_STORAGE
							| TcTssConstants.TSS_KEY_VOLATILE
							| TcTssConstants.TSS_KEY_NOT_MIGRATABLE
							| TcTssConstants.TSS_KEY_AUTHORIZATION);

			TcIPolicy keyUsgPolicy2 = context_
					.createPolicyObject(TcTssConstants.TSS_POLICY_USAGE);
			TcIPolicy keyMigPolicy2 = context_
					.createPolicyObject(TcTssConstants.TSS_POLICY_MIGRATION);
			keyUsgPolicy2.setSecret(TcTssConstants.TSS_SECRET_MODE_PLAIN,
					keySecret2);
			keyMigPolicy2.setSecret(TcTssConstants.TSS_SECRET_MODE_PLAIN,
					keySecret2);
			keyUsgPolicy2.assignToObject(key2);
			keyMigPolicy2.assignToObject(key2);

			key2.createKey(srk_, null);

			// Store both in the user persistent storage

			TcTssUuid keyUUID1 = TcUuidFactory.getInstance()
					.generateRandomUuid();
			TcTssUuid keyUUID2 = TcUuidFactory.getInstance()
					.generateRandomUuid();

			assertFalse(keyUUID1.equals(keyUUID2));

			context_.registerKey(key1, TcTssConstants.TSS_PS_TYPE_USER,
					keyUUID1, TcTssConstants.TSS_PS_TYPE_SYSTEM, TcUuidFactory
							.getInstance().getUuidSRK());
			Log.info("key1 registered in persistent user storage with "
					+ keyUUID1.toString());

			context_.registerKey(key2, TcTssConstants.TSS_PS_TYPE_USER,
					keyUUID2, TcTssConstants.TSS_PS_TYPE_SYSTEM, TcUuidFactory
							.getInstance().getUuidSRK());
			Log.info("key2 registered in persistent user storage with "
					+ keyUUID2.toString());

			// retrieve the key again and compare if they contain the same
			// public key

			TcTssKmKeyinfo[] keyInfos = context_.getRegisteredKeysByUuid(null,
					TcTssConstants.TSS_PS_TYPE_USER);

			boolean key1Found = false;
			boolean key2Found = false;

			for (int i = 0; i != keyInfos.length; i++) {

				if (keyInfos[i].getKeyUuid().equals(keyUUID1))
					key1Found = true;
				if (keyInfos[i].getKeyUuid().equals(keyUUID2))
					key2Found = true;

			}

			assertTrue(key1Found && key2Found);

			// remove keys from PS

			context_.unregisterKey(TcTssConstants.TSS_PS_TYPE_USER, keyUUID1);
			context_.unregisterKey(TcTssConstants.TSS_PS_TYPE_USER, keyUUID2);

		} catch (TcTssException e) {
			if (PRINT_TRACE) {
				Log.err(e);
			}
			assertTrue(
					"unable to retrieve key info enumeration of keys registered in user persistent storage",
					false);
		}

	}

	/*************************************************************************************************
	 * Tries to extract the public portion of the SRK and stores it in the
	 * system persistent storage Note does not use the specific SRK UUID, so
	 * that the test case does not interfere with overall system ownership
	 * state.
	 */
	public void testOwnerGetSRKPubKeyAndStore() {
		try {

			TcITpm tpm = context_.getTpmObject();
			TestDefines.tpmPolicy.assignToObject(tpm);

			TcIRsaKey srkPublic = context_.getTpmObject().OwnerGetSRKPubKey();

			TcTssUuid keyUUID1 = TcUuidFactory.getInstance()
					.generateRandomUuid();

			// Use this instead to restore the SRK in the PS:
			// TcTssUuid keyUUID1 = TcUuidFactory.getInstance().getUuidSRK();

			context_.registerKey(srkPublic, TcTssConstants.TSS_PS_TYPE_SYSTEM,
					keyUUID1, TcTssConstants.TSS_PS_TYPE_SYSTEM, TcUuidFactory
							.getInstance().getUuidSRK());
			Log.info("SRK registered in persistent system storage with "
					+ keyUUID1.toString());

			// If you want to restore the SRK, you must NOT execute this line:
			context_.unregisterKey(TcTssConstants.TSS_PS_TYPE_SYSTEM, keyUUID1);

		} catch (TcTssException e) {
			if (PRINT_TRACE) {
				Log.err(e);
			}
		}
	}

	/**
	 * Registers a key in the system persistent storage (i.e. a file should be
	 * generated), reads it back and finally unregisters it.
	 */
	public void testRegisterKeyInSystemPersistentStorage() {

		try {

			// Generate Key & assign policy

			TcBlobData keySecret = TcBlobData.newString("opentc");

			TcIRsaKey key = context_
					.createRsaKeyObject(TcTssConstants.TSS_KEY_SIZE_2048
							| TcTssConstants.TSS_KEY_TYPE_STORAGE
							| TcTssConstants.TSS_KEY_VOLATILE
							| TcTssConstants.TSS_KEY_NOT_MIGRATABLE
							| TcTssConstants.TSS_KEY_AUTHORIZATION);

			TcIPolicy keyUsgPolicy = context_
					.createPolicyObject(TcTssConstants.TSS_POLICY_USAGE);
			TcIPolicy keyMigPolicy = context_
					.createPolicyObject(TcTssConstants.TSS_POLICY_MIGRATION);
			keyUsgPolicy.setSecret(TcTssConstants.TSS_SECRET_MODE_PLAIN,
					keySecret);
			keyMigPolicy.setSecret(TcTssConstants.TSS_SECRET_MODE_PLAIN,
					keySecret);
			keyUsgPolicy.assignToObject(key);
			keyMigPolicy.assignToObject(key);

			key.createKey(srk_, null);

			// Store it in the System persistent storage

			TcTssUuid keyUUID = TcUuidFactory.getInstance()
					.generateRandomUuid();

			context_.registerKey(key, TcTssConstants.TSS_PS_TYPE_SYSTEM,
					keyUUID, TcTssConstants.TSS_PS_TYPE_SYSTEM, TcUuidFactory
							.getInstance().getUuidSRK());
			Log.info("key registered in persistent system storage with "
					+ keyUUID.toString());

			// retrieve the key again and compare if they contain the same
			// public key

			TcIRsaKey secondKey = context_.getKeyByUuid(
					TcTssConstants.TSS_PS_TYPE_SYSTEM, keyUUID);

			assertTrue(secondKey.getPubKey().toHexString().equals(
					key.getPubKey().toHexString()));

			// remove key from PS

			context_.unregisterKey(TcTssConstants.TSS_PS_TYPE_SYSTEM, keyUUID);

		} catch (TcTssException e) {
			if (PRINT_TRACE) {
				Log.err(e);
			}
			assertTrue(
					"unable to register and unregister key in system persistent storage",
					false);
		}

	}

	/**
	 * Registers a key in the user persistent storage (i.e. a file should be
	 * generated), reads it back and finally unregisters it.
	 */
	public void testRegisterKeyInUserPersistentStorage() {

		try {

			// Generate Key & assign policy

			TcBlobData keySecret = TcBlobData.newString("opentc");

			TcIRsaKey key = context_
					.createRsaKeyObject(TcTssConstants.TSS_KEY_SIZE_2048
							| TcTssConstants.TSS_KEY_TYPE_STORAGE
							| TcTssConstants.TSS_KEY_VOLATILE
							| TcTssConstants.TSS_KEY_NOT_MIGRATABLE
							| TcTssConstants.TSS_KEY_AUTHORIZATION);

			TcIPolicy keyUsgPolicy = context_
					.createPolicyObject(TcTssConstants.TSS_POLICY_USAGE);
			TcIPolicy keyMigPolicy = context_
					.createPolicyObject(TcTssConstants.TSS_POLICY_MIGRATION);
			keyUsgPolicy.setSecret(TcTssConstants.TSS_SECRET_MODE_PLAIN,
					keySecret);
			keyMigPolicy.setSecret(TcTssConstants.TSS_SECRET_MODE_PLAIN,
					keySecret);
			keyUsgPolicy.assignToObject(key);
			keyMigPolicy.assignToObject(key);

			key.createKey(srk_, null);

			// Store it in the user persistent storage

			TcTssUuid keyUUID = TcUuidFactory.getInstance()
					.generateRandomUuid();

			context_.registerKey(key, TcTssConstants.TSS_PS_TYPE_USER, keyUUID,
					TcTssConstants.TSS_PS_TYPE_SYSTEM, TcUuidFactory
							.getInstance().getUuidSRK());
			Log.info("key registered in persistent user storage with "
					+ keyUUID.toString());

			// retrieve the key again and compare if they contain the same
			// public key

			TcIRsaKey secondKey = context_.getKeyByUuid(
					TcTssConstants.TSS_PS_TYPE_USER, keyUUID);

			assertTrue(secondKey.getPubKey().toHexString().equals(
					key.getPubKey().toHexString()));

			// remove key from PS

			context_.unregisterKey(TcTssConstants.TSS_PS_TYPE_USER, keyUUID);

		} catch (TcTssException e) {
			if (PRINT_TRACE) {
				Log.err(e);
			}
			assertTrue(
					"unable to register and unregister key in user persistent storage",
					false);
		}

	}

	public void testSimpleKeyHierarchyTest() {

		try {

			// Generate Key 1 & assign policy

			TcBlobData keySecret = TcBlobData.newString("opentc");

			TcIRsaKey key1 = context_
					.createRsaKeyObject(TcTssConstants.TSS_KEY_SIZE_2048
							| TcTssConstants.TSS_KEY_TYPE_STORAGE
							| TcTssConstants.TSS_KEY_VOLATILE
							| TcTssConstants.TSS_KEY_NOT_MIGRATABLE
							| TcTssConstants.TSS_KEY_AUTHORIZATION);

			TcIPolicy keyUsgPolicy = context_
					.createPolicyObject(TcTssConstants.TSS_POLICY_USAGE);
			TcIPolicy keyMigPolicy = context_
					.createPolicyObject(TcTssConstants.TSS_POLICY_MIGRATION);
			keyUsgPolicy.setSecret(TcTssConstants.TSS_SECRET_MODE_PLAIN,
					keySecret);
			keyMigPolicy.setSecret(TcTssConstants.TSS_SECRET_MODE_PLAIN,
					keySecret);
			keyUsgPolicy.assignToObject(key1);
			keyMigPolicy.assignToObject(key1);

			key1.createKey(srk_, null);

			// Generate Key 2 & assign policy. it is wrapped by key 1

			TcBlobData keySecret2 = TcBlobData.newString("opentc");

			TcIRsaKey key2 = context_
					.createRsaKeyObject(TcTssConstants.TSS_KEY_SIZE_2048
							| TcTssConstants.TSS_KEY_TYPE_STORAGE
							| TcTssConstants.TSS_KEY_VOLATILE
							| TcTssConstants.TSS_KEY_NOT_MIGRATABLE
							| TcTssConstants.TSS_KEY_AUTHORIZATION);

			TcIPolicy keyUsgPolicy2 = context_
					.createPolicyObject(TcTssConstants.TSS_POLICY_USAGE);
			TcIPolicy keyMigPolicy2 = context_
					.createPolicyObject(TcTssConstants.TSS_POLICY_MIGRATION);
			keyUsgPolicy2.setSecret(TcTssConstants.TSS_SECRET_MODE_PLAIN,
					keySecret2);
			keyMigPolicy2.setSecret(TcTssConstants.TSS_SECRET_MODE_PLAIN,
					keySecret2);
			keyUsgPolicy2.assignToObject(key2);
			keyMigPolicy2.assignToObject(key2);

			// Create UUIDs

			TcTssUuid keyUUID1 = TcUuidFactory.getInstance()
					.generateRandomUuid();
			TcTssUuid keyUUID2 = TcUuidFactory.getInstance()
					.generateRandomUuid();

			assertFalse(keyUUID1.equals(keyUUID2));

			// Store & load key 1

			context_.registerKey(key1, TcTssConstants.TSS_PS_TYPE_SYSTEM,
					keyUUID1, TcTssConstants.TSS_PS_TYPE_SYSTEM, TcUuidFactory
							.getInstance().getUuidSRK());
			Log.info("key1 registered in persistent system storage with "
					+ keyUUID1.toString());

			key1.loadKey(srk_);

			// context_.loadKeyByUuidFromSystem(keyUUID1);

			// Create & Store key 2
			key2.createKey(key1, null);

			context_.registerKey(key2, TcTssConstants.TSS_PS_TYPE_SYSTEM,
					keyUUID2, TcTssConstants.TSS_PS_TYPE_SYSTEM, keyUUID1);
			Log.info("key2 registered in persistent system storage with "
					+ keyUUID2.toString());

			// We should now have this hierarchy: SRK -> Key1 -> Key2

			// retrieve the key infos again and compare if they contain the same
			// public key

			TcTssKmKeyinfo[] keyInfos = context_.getRegisteredKeysByUuid(null,
					TcTssConstants.TSS_PS_TYPE_SYSTEM);

			boolean key1Found = false;
			boolean key2Found = false;

			for (int i = 0; i != keyInfos.length; i++) {

				if (keyInfos[i].getKeyUuid().equals(keyUUID1))
					key1Found = true;
				if (keyInfos[i].getKeyUuid().equals(keyUUID2))
					key2Found = true;

			}

			assertTrue(key1Found && key2Found);

			// Now check the correct order

			TcTssKmKeyinfo[] hierarchy = context_.getRegisteredKeysByUuid(
					keyUUID2, TcTssConstants.TSS_PS_TYPE_SYSTEM);

			assertTrue(hierarchy[0].getKeyUuid().equals(keyUUID2));
			assertTrue(hierarchy[1].getKeyUuid().equals(keyUUID1));
			//assertTrue(hierarchy[2].getKeyUuid().equals(
			//		TcUuidFactory.getInstance().getUuidSRK()));

			// Try to load key directly from persistent storage

			// FAILS: Loading of all key of the hierarchy fails..
			// TcIRsaKey key2retrieved =
			// context_.loadKeyByUuidFromSystem(keyUUID2);

			// remove keys from PS

			context_.unregisterKey(TcTssConstants.TSS_PS_TYPE_SYSTEM, keyUUID1);
			context_.unregisterKey(TcTssConstants.TSS_PS_TYPE_SYSTEM, keyUUID2);

		} catch (TcTssException e) {
			if (PRINT_TRACE) {
				Log.err(e);
			}
			assertTrue(
					"unable to retrieve key info enumeration of keys registered in system persistent storage",
					false);
		}

	}

	public void testWriteAndGetKey() {

		TcBlobData srkSecret = TcBlobData
				.newByteArray(TcTssConstants.TSS_WELL_KNOWN_SECRET);
		long srkSecretMode = TcTssConstants.TSS_SECRET_MODE_SHA1;

		// key type

		long keyType = TcTssConstants.TSS_KEY_TYPE_LEGACY;

		// key password

		TcBlobData keySecret = TcBlobData.newString("opentc");

		TcTssUuid keyUuid = null;

		try {

			TcIPolicy srkPolicy = context_
					.createPolicyObject(TcTssConstants.TSS_POLICY_USAGE);
			srkPolicy.setSecret(srkSecretMode, srkSecret);
			srkPolicy.assignToObject(srk_);

			TcIRsaKey key = context_.createRsaKeyObject( //
					TcTssConstants.TSS_KEY_SIZE_2048
							| keyType
							| //
							TcTssConstants.TSS_KEY_VOLATILE
							| TcTssConstants.TSS_KEY_NOT_MIGRATABLE
							| TcTssConstants.TSS_KEY_AUTHORIZATION);

			if (keyType == TcTssConstants.TSS_KEY_TYPE_LEGACY) {
				key.setAttribUint32(TcTssConstants.TSS_TSPATTRIB_KEY_INFO,
						TcTssConstants.TSS_TSPATTRIB_KEYINFO_SIGSCHEME,
						TcTssConstants.TSS_SS_RSASSAPKCS1V15_DER);
				key.setAttribUint32(TcTssConstants.TSS_TSPATTRIB_KEY_INFO,
						TcTssConstants.TSS_TSPATTRIB_KEYINFO_ENCSCHEME,
						TcTssConstants.TSS_ES_RSAESPKCSV15);
			}

			TcIPolicy keyUsgPolicy = context_
					.createPolicyObject(TcTssConstants.TSS_POLICY_USAGE);
			TcIPolicy keyMigPolicy = context_
					.createPolicyObject(TcTssConstants.TSS_POLICY_MIGRATION);
			keyUsgPolicy.setSecret(TcTssConstants.TSS_SECRET_MODE_PLAIN,
					keySecret);
			keyMigPolicy.setSecret(TcTssConstants.TSS_SECRET_MODE_PLAIN,
					keySecret);
			keyUsgPolicy.assignToObject(key);
			keyMigPolicy.assignToObject(key);
			key.createKey(srk_, null);

			// TODO (later version): Do UUID generation according to IEEE 802
			// Spec
			keyUuid = new TcTssUuid().init(1, 2, 3, (short) 4, (short) 5,
					context_.getTpmObject().getRandom(6).asShortArray());

			TcTssKmKeyinfo[] previousKeys = context_
					.getRegisteredKeysByUuidSystem(null);

			int previousLength = previousKeys != null ? previousKeys.length: 0;
			
			// register the key in the persistent storage of the TSS
			try {
				context_.registerKey(key, TcTssConstants.TSS_PS_TYPE_SYSTEM,
						keyUuid, TcTssConstants.TSS_PS_TYPE_SYSTEM,
						TcUuidFactory.getInstance().getUuidSRK());
				Log.info("key registered in persistent system storage with "
						+ keyUuid.toString());
			} catch (TcTssException e) {
				throw e;
			}

			Log.info("parent key is SRK, key length is 2048 bits");
			Log.info("CreateKey succeeded");

			TcTssKmKeyinfo[] returnedKeys = context_
					.getRegisteredKeysByUuidSystem(null);
			if (previousLength + 1 != returnedKeys.length)
				throw new Exception("The key seems not to be stored correctly.");
			// if (returnedKey.length > 1)
			// throw new Exception(
			// "There seems to be a duplicate key in persistent storage...");
			// else if (returnedKey.length < 1)
			// throw new Exception(
			// "The key seems not to be stored correctly in persistent storage..."
			// );

			// if (!returnedKeys[0].getKeyUuid().equals(keyUuid))
			// throw new Exception("The compared keys do not match.");

		} catch (Exception e) {
			Log.err(e);
			assertTrue(e.getMessage(), false);
		} finally {
			try {
				context_.unregisterKey(TcTssConstants.TSS_PS_TYPE_SYSTEM,
						keyUuid);
			} catch (Exception e) {
				e.printStackTrace();
			}
		}

	}

}
