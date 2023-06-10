/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Christian Pointner
 */

package iaik.tc.tss.test.tsp.java.migration;

import iaik.tc.tss.api.constants.tsp.TcTssConstants;
import iaik.tc.tss.api.exceptions.common.TcTssException;
import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.tss.api.structs.tpm.TcTpmMigrationkeyAuth;
import iaik.tc.tss.api.tspi.TcIRsaKey;
import iaik.tc.tss.api.tspi.TcITpm;
import iaik.tc.tss.test.tsp.java.TestCommon;
import iaik.tc.tss.test.tsp.java.TestDefines;
import iaik.tc.utils.logging.Log;

public class TestMigration extends TestCommon {

	public void testAuthorizeMigrationTicket()
	{
		try {
			
			TcITpm tpm = context_.getTpmObject();
			TestDefines.tpmPolicy.assignToObject(tpm);

			TcIRsaKey migrationKey = context_.createRsaKeyObject(TcTssConstants.TSS_KEY_SIZE_2048
					| TcTssConstants.TSS_KEY_TYPE_BIND| TcTssConstants.TSS_KEY_MIGRATABLE | TcTssConstants.TSS_KEY_AUTHORIZATION);
			TestDefines.keyUsgPolicy.assignToObject(migrationKey);
			TestDefines.keyMigPolicy.assignToObject(migrationKey);
			migrationKey.createKey(srk_, null);
			
			TcTpmMigrationkeyAuth migrate = tpm.authorizeMigrationTicket(migrationKey, TcTssConstants.TSS_MS_MIGRATE);
			
			TcTpmMigrationkeyAuth rewrap = tpm.authorizeMigrationTicket(migrationKey, TcTssConstants.TSS_MS_REWRAP);
			
		} catch (TcTssException e) {
			if (PRINT_TRACE)
				Log.err(e);
			assertTrue("authorizing migration ticket failed", false);
		}	
	}
		
	public void testCreateMigrationBlob()
	{
		try {

			TcITpm tpm = context_.getTpmObject();
			TestDefines.tpmPolicy.assignToObject(tpm);
			
			TcIRsaKey migrationKey = context_.createRsaKeyObject(TcTssConstants.TSS_KEY_SIZE_2048
					| TcTssConstants.TSS_KEY_TYPE_BIND | TcTssConstants.TSS_KEY_MIGRATABLE | TcTssConstants.TSS_KEY_AUTHORIZATION);
			TestDefines.keyUsgPolicy.assignToObject(migrationKey);
			TestDefines.keyMigPolicy.assignToObject(migrationKey);
			migrationKey.createKey(srk_, null);
			
			TcTpmMigrationkeyAuth keyAuth = tpm.authorizeMigrationTicket(migrationKey, TcTssConstants.TSS_MS_MIGRATE);
			TcBlobData out1[] = migrationKey.createMigrationBlob(srk_, keyAuth);	

			if(out1[0] == null)
				assertTrue("random should not be null", false);	

			keyAuth = tpm.authorizeMigrationTicket(migrationKey, TcTssConstants.TSS_MS_REWRAP);
			TcBlobData out2[] = migrationKey.createMigrationBlob(srk_, keyAuth);

			if(out2[0] != null)
				assertTrue("random should be null", false);	
			
		} catch (TcTssException e) {
			if (PRINT_TRACE)
				Log.err(e);
			assertTrue("creating migration blob failed", false);
		}	
	}

	public void testConvertMigrationBlob()
	{
		try {

			TcITpm tpm = context_.getTpmObject();
			TestDefines.tpmPolicy.assignToObject(tpm);

			// create the key of the migration authority
			TcIRsaKey maKey = context_.createRsaKeyObject(TcTssConstants.TSS_KEY_SIZE_2048
					| TcTssConstants.TSS_KEY_TYPE_STORAGE | TcTssConstants.TSS_KEY_AUTHORIZATION);
			TestDefines.keyUsgPolicy.assignToObject(maKey);
			TestDefines.keyMigPolicy.assignToObject(maKey);
			maKey.createKey(srk_, null);

			// create the key to migrate from
			TcIRsaKey srcKey = context_.createRsaKeyObject(TcTssConstants.TSS_KEY_SIZE_2048
					| TcTssConstants.TSS_KEY_TYPE_BIND | TcTssConstants.TSS_KEY_MIGRATABLE | TcTssConstants.TSS_KEY_AUTHORIZATION);
			TestDefines.keyUsgPolicy.assignToObject(srcKey);
			TestDefines.keyMigPolicy.assignToObject(srcKey);
			srcKey.createKey(srk_, null);

			// authorize the migration authority to be used
			TcTpmMigrationkeyAuth keyAuth = tpm.authorizeMigrationTicket(maKey, TcTssConstants.TSS_MS_MIGRATE);
			
			// create the migration blob from the key to be migrated
			TcBlobData out[] = srcKey.createMigrationBlob(srk_, keyAuth);

			// create an key object for the migrated key
			TcIRsaKey destKey = context_.createRsaKeyObject(TcTssConstants.TSS_KEY_SIZE_2048
					| TcTssConstants.TSS_KEY_TYPE_BIND | TcTssConstants.TSS_KEY_MIGRATABLE | TcTssConstants.TSS_KEY_AUTHORIZATION);

			// convert the migration blob to create a normal wrapped key
			maKey.loadKey(srk_);
			destKey.convertMigrationBlob(maKey, out[0], out[1]);
		
		} catch (TcTssException e) {
			if (PRINT_TRACE)
				Log.err(e);
			assertTrue("converting migration blob failed", false);
		}	
	}



	public void testMigrateKey()
	{
		try {

			TcITpm tpm = context_.getTpmObject();
			TestDefines.tpmPolicy.assignToObject(tpm);

			// create the key of the migration authority
			TcIRsaKey maKey = context_.createRsaKeyObject(TcTssConstants.TSS_KEY_SIZE_2048
					| TcTssConstants.TSS_KEY_TYPE_MIGRATE | TcTssConstants.TSS_KEY_AUTHORIZATION);
			TestDefines.keyUsgPolicy.assignToObject(maKey);
			TestDefines.keyMigPolicy.assignToObject(maKey);
			maKey.createKey(srk_, null);

			// create the key (data) to migrate from
			TcIRsaKey srcKey = context_.createRsaKeyObject(TcTssConstants.TSS_KEY_SIZE_2048
					| TcTssConstants.TSS_KEY_TYPE_BIND | TcTssConstants.TSS_KEY_MIGRATABLE | TcTssConstants.TSS_KEY_AUTHORIZATION);
			TestDefines.keyUsgPolicy.assignToObject(srcKey);
			TestDefines.keyMigPolicy.assignToObject(srcKey);
			srcKey.createKey(srk_, null);

			// authorize the migration authority to be used and create migration blob
			TcTpmMigrationkeyAuth keyAuth = tpm.authorizeMigrationTicket(maKey, TcTssConstants.TSS_MS_MIGRATE);
			TcBlobData out[] = srcKey.createMigrationBlob(srk_, keyAuth);
			TcBlobData random = out[0]; // send this to the destination
			TcBlobData migData = out[1]; // send this to Migration Authority

			// create the public key to be used (comes form destination)
			TcIRsaKey pubKey = context_.createRsaKeyObject(TcTssConstants.TSS_KEY_SIZE_2048
					| TcTssConstants.TSS_KEY_TYPE_STORAGE | TcTssConstants.TSS_KEY_NO_AUTHORIZATION);
			TestDefines.keyUsgPolicy.assignToObject(pubKey);
			TestDefines.keyMigPolicy.assignToObject(pubKey);
			pubKey.createKey(srk_, null);

			// create the migration data key object
			TcIRsaKey migDataKey = context_.createRsaKeyObject(TcTssConstants.TSS_KEY_TYPE_LEGACY);
			migDataKey.setAttribData(TcTssConstants.TSS_TSPATTRIB_KEY_BLOB,
					TcTssConstants.TSS_TSPATTRIB_KEYBLOB_BLOB, migData);

			// migrate the data (key)
			maKey.loadKey(srk_);
			pubKey.loadKey(srk_);
			maKey.migrateKey(pubKey, migDataKey);

			TcBlobData migratedData = migDataKey.getAttribData(TcTssConstants.TSS_TSPATTRIB_KEY_BLOB,
					TcTssConstants.TSS_TSPATTRIB_KEYBLOB_BLOB);

			// create an key object for the migrated key
			TcIRsaKey destKey = context_.createRsaKeyObject(TcTssConstants.TSS_KEY_SIZE_2048
					| TcTssConstants.TSS_KEY_TYPE_BIND | TcTssConstants.TSS_KEY_MIGRATABLE | TcTssConstants.TSS_KEY_NO_AUTHORIZATION);

			// convert the migration blob to create a normal wrapped key
			destKey.convertMigrationBlob(pubKey, random, migratedData);
		} catch (TcTssException e) {
			if (PRINT_TRACE)
				Log.err(e);
			assertTrue("migrating key failed", false);
		}
	}


}
