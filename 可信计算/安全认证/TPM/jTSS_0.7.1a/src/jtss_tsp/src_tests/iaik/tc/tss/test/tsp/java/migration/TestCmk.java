/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Christian Pointner
 */

package iaik.tc.tss.test.tsp.java.migration;

import iaik.tc.tss.api.constants.tsp.TcTssConstants;
import iaik.tc.tss.api.exceptions.common.TcTssException;
import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.tss.api.structs.tpm.TcTpmDigest;
import iaik.tc.tss.api.structs.tpm.TcTpmMigrationkeyAuth;
import iaik.tc.tss.api.structs.tsp.TcTssValidation;
import iaik.tc.tss.api.tspi.TcIHash;
import iaik.tc.tss.api.tspi.TcIMigData;
import iaik.tc.tss.api.tspi.TcIRsaKey;
import iaik.tc.tss.api.tspi.TcITpm;
import iaik.tc.tss.test.tsp.java.TestCommon;
import iaik.tc.tss.test.tsp.java.TestDefines;
import iaik.tc.utils.logging.Log;

public class TestCmk extends TestCommon {

	public void testCMKSetRestrictions()
	{
		try {

			TcITpm tpm = context_.getTpmObject();
			TestDefines.tpmPolicy.assignToObject(tpm);
			
			long restrictions = TcTssConstants.TSS_CMK_DELEGATE_STORAGE | TcTssConstants.TSS_CMK_DELEGATE_BIND;
			tpm.CMKSetRestrictions(restrictions);
			
		} catch (TcTssException e) {
			if (PRINT_TRACE)
				Log.err(e);
			assertTrue("CMK set restrictions failed", false);
		}	
	}

	public void testCMKApproveMA()
	{
		try {

			TcITpm tpm = context_.getTpmObject();
			TestDefines.tpmPolicy.assignToObject(tpm);

			// crate migData object and add authority key to the msa list
			TcIMigData migData = context_.createMigDataObject(0);
			TcIRsaKey maKey[] = { null , null, null };
			for(int i=0; i < 3; i++) {
				// create the key of the migration authority
				maKey[i] = context_.createRsaKeyObject(TcTssConstants.TSS_KEY_STRUCT_KEY12 |
						TcTssConstants.TSS_KEY_SIZE_2048 | TcTssConstants.TSS_KEY_TYPE_MIGRATE |
						TcTssConstants.TSS_KEY_AUTHORIZATION);
				TestDefines.keyUsgPolicy.assignToObject(maKey[i]);
				TestDefines.keyMigPolicy.assignToObject(maKey[i]);
				maKey[i].createKey(srk_, null);
				
				TcBlobData pubKeyBlob = maKey[i].getAttribData(TcTssConstants.TSS_TSPATTRIB_KEY_BLOB,
						TcTssConstants.TSS_TSPATTRIB_KEYBLOB_PUBLIC_KEY);
				
				migData.setAttribData(TcTssConstants.TSS_MIGATTRIB_MIGRATIONBLOB, 
						TcTssConstants.TSS_MIGATTRIB_MIG_MSALIST_PUBKEY_BLOB, pubKeyBlob);
			}
			
			tpm.CMKApproveMA(migData);
			
			TcTpmDigest msaHmac = new TcTpmDigest(
					migData.getAttribData(TcTssConstants.TSS_MIGATTRIB_AUTHORITY_DATA, 
							TcTssConstants.TSS_MIGATTRIB_AUTHORITY_APPROVAL_HMAC));
			
		} catch (TcTssException e) {
			if (PRINT_TRACE)
				Log.err(e);
			assertTrue("CMK approve migration authority failed", false);
		}	
	}

	public void testCMKCreateTicket()
	{
		try {

			TcITpm tpm = context_.getTpmObject();
			TestDefines.tpmPolicy.assignToObject(tpm);
			
			// create the parent key of the source
			TcIRsaKey srcKey = context_.createRsaKeyObject(TcTssConstants.TSS_KEY_STRUCT_KEY12 |
					TcTssConstants.TSS_KEY_SIZE_2048 | TcTssConstants.TSS_KEY_TYPE_STORAGE |
					TcTssConstants.TSS_KEY_AUTHORIZATION);
			TestDefines.keyUsgPolicy.assignToObject(srcKey);
			TestDefines.keyMigPolicy.assignToObject(srcKey);
			srcKey.createKey(srk_, null);
			srcKey.loadKey(srk_);
			
			// create the parent key of the destination
			TcIRsaKey destKey = context_.createRsaKeyObject(TcTssConstants.TSS_KEY_STRUCT_KEY12 |
					TcTssConstants.TSS_KEY_SIZE_2048 | TcTssConstants.TSS_KEY_TYPE_STORAGE |
					TcTssConstants.TSS_KEY_AUTHORIZATION);
			TestDefines.keyUsgPolicy.assignToObject(destKey);
			TestDefines.keyMigPolicy.assignToObject(destKey);
			destKey.createKey(srk_, null);
			destKey.loadKey(srk_);
			
			// create a key for the authority and approve its use
			//NOTE: legacy/signing key needed for MSA since
			//      key migration through this authority
			//      requires the MSA's signature
			TcIMigData migData = context_.createMigDataObject(0);
			TcIRsaKey maKey = context_.createRsaKeyObject(TcTssConstants.TSS_KEY_STRUCT_KEY12 |
						TcTssConstants.TSS_KEY_SIZE_2048 | TcTssConstants.TSS_KEY_TYPE_SIGNING |
						TcTssConstants.TSS_KEY_AUTHORIZATION);
			TestDefines.keyUsgPolicy.assignToObject(maKey);
			TestDefines.keyMigPolicy.assignToObject(maKey);
			maKey.createKey(srk_, null);
				
			TcBlobData pubKeyBlob = maKey.getAttribData(TcTssConstants.TSS_TSPATTRIB_KEY_BLOB,
					TcTssConstants.TSS_TSPATTRIB_KEYBLOB_PUBLIC_KEY);
			migData.setAttribData(TcTssConstants.TSS_MIGATTRIB_MIGRATIONBLOB, 
					TcTssConstants.TSS_MIGATTRIB_MIG_MSALIST_PUBKEY_BLOB, pubKeyBlob);
			tpm.CMKApproveMA(migData);
			
			// create a CMK
			TcIRsaKey cmKey = context_.createRsaKeyObject(TcTssConstants.TSS_KEY_STRUCT_KEY12 |
					TcTssConstants.TSS_KEY_SIZE_2048 | TcTssConstants.TSS_KEY_TYPE_SIGNING |
					TcTssConstants.TSS_KEY_MIGRATABLE | TcTssConstants.TSS_KEY_CERTIFIED_MIGRATABLE |
					TcTssConstants.TSS_KEY_AUTHORIZATION);
			TestDefines.keyUsgPolicy.assignToObject(cmKey);
			TestDefines.keyMigPolicy.assignToObject(cmKey);
			
			// assign MA/MSA information
			TcBlobData msaDigest = migData.getAttribData(TcTssConstants.TSS_MIGATTRIB_AUTHORITY_DATA, 
					TcTssConstants.TSS_MIGATTRIB_AUTHORITY_DIGEST);
			cmKey.setAttribData(TcTssConstants.TSS_TSPATTRIB_KEY_CMKINFO, 
					TcTssConstants.TSS_TSPATTRIB_KEYINFO_CMK_MA_DIGEST, msaDigest);
			
			TcBlobData msaHmac = migData.getAttribData(TcTssConstants.TSS_MIGATTRIB_AUTHORITY_DATA, 
					TcTssConstants.TSS_MIGATTRIB_AUTHORITY_APPROVAL_HMAC);
			cmKey.setAttribData(TcTssConstants.TSS_TSPATTRIB_KEY_CMKINFO, 
					TcTssConstants.TSS_TSPATTRIB_KEYINFO_CMK_MA_APPROVAL, msaHmac);
			
			cmKey.createKey(srcKey, null);
			
			// authorize the migration to the destination key and store it
			TcTpmMigrationkeyAuth keyAuth = tpm.authorizeMigrationTicket(destKey, TcTssConstants.TSS_MS_RESTRICT_APPROVE_DOUBLE);
			migData.setAttribData(TcTssConstants.TSS_MIGATTRIB_MIGRATIONTICKET, 0, keyAuth.getEncoded());

			// sign the migration ticket
			TcBlobData cmPubKeyBlob = cmKey.getAttribData(TcTssConstants.TSS_TSPATTRIB_KEY_BLOB,
					TcTssConstants.TSS_TSPATTRIB_KEYBLOB_PUBLIC_KEY);
			migData.setAttribData(TcTssConstants.TSS_MIGATTRIB_MIGRATIONBLOB, 
					TcTssConstants.TSS_MIGATTRIB_MIG_SOURCE_PUBKEY_BLOB, cmPubKeyBlob);
			
			TcBlobData destPubKeyBlob = destKey.getAttribData(TcTssConstants.TSS_TSPATTRIB_KEY_BLOB,
					TcTssConstants.TSS_TSPATTRIB_KEYBLOB_PUBLIC_KEY);
			migData.setAttribData(TcTssConstants.TSS_MIGATTRIB_MIGRATIONBLOB, 
					TcTssConstants.TSS_MIGATTRIB_MIG_DESTINATION_PUBKEY_BLOB, destPubKeyBlob);
			
			TcBlobData maPubKeyBlob = maKey.getAttribData(TcTssConstants.TSS_TSPATTRIB_KEY_BLOB,
					TcTssConstants.TSS_TSPATTRIB_KEYBLOB_PUBLIC_KEY);
			migData.setAttribData(TcTssConstants.TSS_MIGATTRIB_MIGRATIONBLOB, 
					TcTssConstants.TSS_MIGATTRIB_MIG_AUTHORITY_PUBKEY_BLOB, maPubKeyBlob);

			TcIHash hash = context_.createHashObject(TcTssConstants.TSS_HASH_SHA1);
			hash.updateHashValue(maPubKeyBlob.sha1());
			hash.updateHashValue(destPubKeyBlob.sha1());
			hash.updateHashValue(cmPubKeyBlob.sha1());
			hash.getHashValue();
			maKey.loadKey(srk_);
			TcBlobData sig = hash.sign(maKey);
			
			// save ticket signature
			migData.setAttribData(TcTssConstants.TSS_MIGATTRIB_TICKET_DATA, 
					TcTssConstants.TSS_MIGATTRIB_TICKET_SIG_VALUE, sig);
			
			tpm.CMKCreateTicket(maKey, migData);
			
			TcTpmDigest sigTicket = new TcTpmDigest(
					migData.getAttribData(TcTssConstants.TSS_MIGATTRIB_TICKET_DATA, 
							TcTssConstants.TSS_MIGATTRIB_TICKET_SIG_TICKET));
		} catch (TcTssException e) {
			if (PRINT_TRACE)
				Log.err(e);
			assertTrue("CMK ticket creation failed", false);
		}	
	}

	public void testCMKCreateBlob()
	{
		try {

			TcITpm tpm = context_.getTpmObject();
			TestDefines.tpmPolicy.assignToObject(tpm);
			
			// create the parent key of the source
			TcIRsaKey srcKey = context_.createRsaKeyObject(TcTssConstants.TSS_KEY_STRUCT_KEY12 |
					TcTssConstants.TSS_KEY_SIZE_2048 | TcTssConstants.TSS_KEY_TYPE_STORAGE |
					TcTssConstants.TSS_KEY_AUTHORIZATION);
			TestDefines.keyUsgPolicy.assignToObject(srcKey);
			TestDefines.keyMigPolicy.assignToObject(srcKey);
			srcKey.createKey(srk_, null);
			srcKey.loadKey(srk_);
			
			// create the parent key of the destination
			TcIRsaKey destKey = context_.createRsaKeyObject(TcTssConstants.TSS_KEY_STRUCT_KEY12 |
					TcTssConstants.TSS_KEY_SIZE_2048 | TcTssConstants.TSS_KEY_TYPE_STORAGE |
					TcTssConstants.TSS_KEY_AUTHORIZATION);
			TestDefines.keyUsgPolicy.assignToObject(destKey);
			TestDefines.keyMigPolicy.assignToObject(destKey);
			destKey.createKey(srk_, null);
			destKey.loadKey(srk_);
			
			// create a key for the authority and approve its use
			//NOTE: legacy/signing key needed for MSA since
			//      key migration through this authority
			//      requires the MSA's signature
			TcIMigData migData = context_.createMigDataObject(0);
			TcIRsaKey maKey = context_.createRsaKeyObject(TcTssConstants.TSS_KEY_STRUCT_KEY12 |
						TcTssConstants.TSS_KEY_SIZE_2048 | TcTssConstants.TSS_KEY_TYPE_SIGNING |
						TcTssConstants.TSS_KEY_AUTHORIZATION);
			TestDefines.keyUsgPolicy.assignToObject(maKey);
			TestDefines.keyMigPolicy.assignToObject(maKey);
			maKey.createKey(srk_, null);
				
			TcBlobData pubKeyBlob = maKey.getAttribData(TcTssConstants.TSS_TSPATTRIB_KEY_BLOB,
					TcTssConstants.TSS_TSPATTRIB_KEYBLOB_PUBLIC_KEY);
			migData.setAttribData(TcTssConstants.TSS_MIGATTRIB_MIGRATIONBLOB, 
					TcTssConstants.TSS_MIGATTRIB_MIG_MSALIST_PUBKEY_BLOB, pubKeyBlob);
			tpm.CMKApproveMA(migData);
			
			// create a CMK
			TcIRsaKey cmKey = context_.createRsaKeyObject(TcTssConstants.TSS_KEY_STRUCT_KEY12 |
					TcTssConstants.TSS_KEY_SIZE_2048 | TcTssConstants.TSS_KEY_TYPE_SIGNING |
					TcTssConstants.TSS_KEY_MIGRATABLE | TcTssConstants.TSS_KEY_CERTIFIED_MIGRATABLE |
					TcTssConstants.TSS_KEY_AUTHORIZATION);
			TestDefines.keyUsgPolicy.assignToObject(cmKey);
			TestDefines.keyMigPolicy.assignToObject(cmKey);
			
			// assign MA/MSA information
			TcBlobData msaDigest = migData.getAttribData(TcTssConstants.TSS_MIGATTRIB_AUTHORITY_DATA, 
					TcTssConstants.TSS_MIGATTRIB_AUTHORITY_DIGEST);
			cmKey.setAttribData(TcTssConstants.TSS_TSPATTRIB_KEY_CMKINFO, 
					TcTssConstants.TSS_TSPATTRIB_KEYINFO_CMK_MA_DIGEST, msaDigest);
			
			TcBlobData msaHmac = migData.getAttribData(TcTssConstants.TSS_MIGATTRIB_AUTHORITY_DATA, 
					TcTssConstants.TSS_MIGATTRIB_AUTHORITY_APPROVAL_HMAC);
			cmKey.setAttribData(TcTssConstants.TSS_TSPATTRIB_KEY_CMKINFO, 
					TcTssConstants.TSS_TSPATTRIB_KEYINFO_CMK_MA_APPROVAL, msaHmac);
			
			cmKey.createKey(srcKey, null);
			
			// authorize the migration to the destination key and store it
			TcTpmMigrationkeyAuth keyAuth = tpm.authorizeMigrationTicket(destKey, TcTssConstants.TSS_MS_RESTRICT_APPROVE_DOUBLE);
			migData.setAttribData(TcTssConstants.TSS_MIGATTRIB_MIGRATIONTICKET, 0, keyAuth.getEncoded());

			// sign the migration ticket
			TcBlobData cmPubKeyBlob = cmKey.getAttribData(TcTssConstants.TSS_TSPATTRIB_KEY_BLOB,
					TcTssConstants.TSS_TSPATTRIB_KEYBLOB_PUBLIC_KEY);
			migData.setAttribData(TcTssConstants.TSS_MIGATTRIB_MIGRATIONBLOB, 
					TcTssConstants.TSS_MIGATTRIB_MIG_SOURCE_PUBKEY_BLOB, cmPubKeyBlob);
			
			TcBlobData destPubKeyBlob = destKey.getAttribData(TcTssConstants.TSS_TSPATTRIB_KEY_BLOB,
					TcTssConstants.TSS_TSPATTRIB_KEYBLOB_PUBLIC_KEY);
			migData.setAttribData(TcTssConstants.TSS_MIGATTRIB_MIGRATIONBLOB, 
					TcTssConstants.TSS_MIGATTRIB_MIG_DESTINATION_PUBKEY_BLOB, destPubKeyBlob);
			
			TcBlobData maPubKeyBlob = maKey.getAttribData(TcTssConstants.TSS_TSPATTRIB_KEY_BLOB,
					TcTssConstants.TSS_TSPATTRIB_KEYBLOB_PUBLIC_KEY);
			migData.setAttribData(TcTssConstants.TSS_MIGATTRIB_MIGRATIONBLOB, 
					TcTssConstants.TSS_MIGATTRIB_MIG_AUTHORITY_PUBKEY_BLOB, maPubKeyBlob);

			TcIHash hash = context_.createHashObject(TcTssConstants.TSS_HASH_SHA1);
			hash.updateHashValue(maPubKeyBlob.sha1());
			hash.updateHashValue(destPubKeyBlob.sha1());
			hash.updateHashValue(cmPubKeyBlob.sha1());
			hash.getHashValue();
			maKey.loadKey(srk_);
			TcBlobData sig = hash.sign(maKey);
			
			// save ticket signature and create the ticket
			migData.setAttribData(TcTssConstants.TSS_MIGATTRIB_TICKET_DATA, 
					TcTssConstants.TSS_MIGATTRIB_TICKET_SIG_VALUE, sig);
			tpm.CMKCreateTicket(maKey, migData);

			TcBlobData random = cmKey.CMKCreateBlob(srcKey, migData);
			TcBlobData xorBlob = migData.getAttribData(TcTssConstants.TSS_MIGATTRIB_MIGRATIONBLOB, 
					TcTssConstants.TSS_MIGATTRIB_MIGRATION_XOR_BLOB);
		} catch (TcTssException e) {
			if (PRINT_TRACE)
				Log.err(e);
			assertTrue("CMK migrationblob creation failed", false);
		}	
	}

	public void testCMKConvertMigration()
	{
		try {

			TcITpm tpm = context_.getTpmObject();
			TestDefines.tpmPolicy.assignToObject(tpm);

			// create the parent key of the source
			TcIRsaKey srcKey = context_.createRsaKeyObject(TcTssConstants.TSS_KEY_STRUCT_KEY12 |
					TcTssConstants.TSS_KEY_SIZE_2048 | TcTssConstants.TSS_KEY_TYPE_STORAGE |
					TcTssConstants.TSS_KEY_AUTHORIZATION);
			TestDefines.keyUsgPolicy.assignToObject(srcKey);
			TestDefines.keyMigPolicy.assignToObject(srcKey);
			srcKey.createKey(srk_, null);
			srcKey.loadKey(srk_);
			
			// create the parent key of the destination
			TcIRsaKey destKey = context_.createRsaKeyObject(TcTssConstants.TSS_KEY_STRUCT_KEY12 |
					TcTssConstants.TSS_KEY_SIZE_2048 | TcTssConstants.TSS_KEY_TYPE_STORAGE |
					TcTssConstants.TSS_KEY_AUTHORIZATION);
			TestDefines.keyUsgPolicy.assignToObject(destKey);
			TestDefines.keyMigPolicy.assignToObject(destKey);
			destKey.createKey(srk_, null);
			destKey.loadKey(srk_);
			
			// create a key for the authority and approve its use
			//NOTE: legacy/signing key needed for MSA since
			//      key migration through this authority
			//      requires the MSA's signature
			TcIMigData migData = context_.createMigDataObject(0);
			TcIRsaKey maKey = context_.createRsaKeyObject(TcTssConstants.TSS_KEY_STRUCT_KEY12 |
						TcTssConstants.TSS_KEY_SIZE_2048 | TcTssConstants.TSS_KEY_TYPE_SIGNING |
						TcTssConstants.TSS_KEY_AUTHORIZATION);
			TestDefines.keyUsgPolicy.assignToObject(maKey);
			TestDefines.keyMigPolicy.assignToObject(maKey);
			maKey.createKey(srk_, null);
				
			TcBlobData pubKeyBlob = maKey.getAttribData(TcTssConstants.TSS_TSPATTRIB_KEY_BLOB,
					TcTssConstants.TSS_TSPATTRIB_KEYBLOB_PUBLIC_KEY);
			migData.setAttribData(TcTssConstants.TSS_MIGATTRIB_MIGRATIONBLOB, 
					TcTssConstants.TSS_MIGATTRIB_MIG_MSALIST_PUBKEY_BLOB, pubKeyBlob);
			tpm.CMKApproveMA(migData);
			
			// create a CMK
			TcIRsaKey cmKey = context_.createRsaKeyObject(TcTssConstants.TSS_KEY_STRUCT_KEY12 |
					TcTssConstants.TSS_KEY_SIZE_2048 | TcTssConstants.TSS_KEY_TYPE_SIGNING |
					TcTssConstants.TSS_KEY_MIGRATABLE | TcTssConstants.TSS_KEY_CERTIFIED_MIGRATABLE |
					TcTssConstants.TSS_KEY_AUTHORIZATION);
			TestDefines.keyUsgPolicy.assignToObject(cmKey);
			TestDefines.keyMigPolicy.assignToObject(cmKey);
			
			// assign MA/MSA information
			TcBlobData msaDigest = migData.getAttribData(TcTssConstants.TSS_MIGATTRIB_AUTHORITY_DATA, 
					TcTssConstants.TSS_MIGATTRIB_AUTHORITY_DIGEST);
			cmKey.setAttribData(TcTssConstants.TSS_TSPATTRIB_KEY_CMKINFO, 
					TcTssConstants.TSS_TSPATTRIB_KEYINFO_CMK_MA_DIGEST, msaDigest);
			
			TcBlobData msaHmac = migData.getAttribData(TcTssConstants.TSS_MIGATTRIB_AUTHORITY_DATA, 
					TcTssConstants.TSS_MIGATTRIB_AUTHORITY_APPROVAL_HMAC);
			cmKey.setAttribData(TcTssConstants.TSS_TSPATTRIB_KEY_CMKINFO, 
					TcTssConstants.TSS_TSPATTRIB_KEYINFO_CMK_MA_APPROVAL, msaHmac);
			
			cmKey.createKey(srcKey, null);
			
			// authorize the migration to the destination key and store it
			TcTpmMigrationkeyAuth keyAuth = tpm.authorizeMigrationTicket(destKey, TcTssConstants.TSS_MS_RESTRICT_APPROVE_DOUBLE);
			migData.setAttribData(TcTssConstants.TSS_MIGATTRIB_MIGRATIONTICKET, 0, keyAuth.getEncoded());

			// sign the migration ticket
			TcBlobData cmPubKeyBlob = cmKey.getAttribData(TcTssConstants.TSS_TSPATTRIB_KEY_BLOB,
					TcTssConstants.TSS_TSPATTRIB_KEYBLOB_PUBLIC_KEY);
			migData.setAttribData(TcTssConstants.TSS_MIGATTRIB_MIGRATIONBLOB, 
					TcTssConstants.TSS_MIGATTRIB_MIG_SOURCE_PUBKEY_BLOB, cmPubKeyBlob);
			
			TcBlobData destPubKeyBlob = destKey.getAttribData(TcTssConstants.TSS_TSPATTRIB_KEY_BLOB,
					TcTssConstants.TSS_TSPATTRIB_KEYBLOB_PUBLIC_KEY);
			migData.setAttribData(TcTssConstants.TSS_MIGATTRIB_MIGRATIONBLOB, 
					TcTssConstants.TSS_MIGATTRIB_MIG_DESTINATION_PUBKEY_BLOB, destPubKeyBlob);
			
			TcBlobData maPubKeyBlob = maKey.getAttribData(TcTssConstants.TSS_TSPATTRIB_KEY_BLOB,
					TcTssConstants.TSS_TSPATTRIB_KEYBLOB_PUBLIC_KEY);
			migData.setAttribData(TcTssConstants.TSS_MIGATTRIB_MIGRATIONBLOB, 
					TcTssConstants.TSS_MIGATTRIB_MIG_AUTHORITY_PUBKEY_BLOB, maPubKeyBlob);

			TcIHash hashSrc = context_.createHashObject(TcTssConstants.TSS_HASH_SHA1);
			hashSrc.updateHashValue(maPubKeyBlob.sha1());
			hashSrc.updateHashValue(destPubKeyBlob.sha1());
			hashSrc.updateHashValue(cmPubKeyBlob.sha1());
			hashSrc.getHashValue();
			maKey.loadKey(srk_);
			TcBlobData sigSrc = hashSrc.sign(maKey);
			
			// save ticket signature and create the ticket
			migData.setAttribData(TcTssConstants.TSS_MIGATTRIB_TICKET_DATA, 
					TcTssConstants.TSS_MIGATTRIB_TICKET_SIG_VALUE, sigSrc);
			tpm.CMKCreateTicket(maKey, migData);

			TcBlobData random = cmKey.CMKCreateBlob(srcKey, migData);
			TcBlobData xorBlob = migData.getAttribData(TcTssConstants.TSS_MIGATTRIB_MIGRATIONBLOB, 
					TcTssConstants.TSS_MIGATTRIB_MIGRATION_XOR_BLOB);
			
			// 
			// Create a CMK ticket for the destination TPM 
			// We are using the same TPM so the next steps ar not necessary, but are
			// done for procedural info 
			
			TcIHash hashDest = context_.createHashObject(TcTssConstants.TSS_HASH_SHA1);
			TcBlobData authorityDigest = migData.getAttribData(TcTssConstants.TSS_MIGATTRIB_MIG_AUTH_DATA, 
					TcTssConstants.TSS_MIGATTRIB_MIG_AUTH_AUTHORITY_DIGEST);
			hashDest.updateHashValue(authorityDigest);
			TcBlobData destDigest = migData.getAttribData(TcTssConstants.TSS_MIGATTRIB_MIG_AUTH_DATA, 
					TcTssConstants.TSS_MIGATTRIB_MIG_AUTH_DESTINATION_DIGEST);
			hashDest.updateHashValue(destDigest);
			TcBlobData srcDigest = migData.getAttribData(TcTssConstants.TSS_MIGATTRIB_MIG_AUTH_DATA, 
					TcTssConstants.TSS_MIGATTRIB_MIG_AUTH_SOURCE_DIGEST);
			hashDest.updateHashValue(srcDigest);
			hashDest.getHashValue();
			// maKey.loadKey(srk_); // key is already loaded
			TcBlobData sigDest = hashSrc.sign(maKey);
			
			// save ticket signature and create the ticket
			migData.setAttribData(TcTssConstants.TSS_MIGATTRIB_TICKET_DATA, 
					TcTssConstants.TSS_MIGATTRIB_TICKET_SIG_VALUE, sigDest);
			tpm.CMKCreateTicket(maKey, migData);
			
			// create an key object for the migrated key
			TcIRsaKey migratedKey = context_.createRsaKeyObject(TcTssConstants.TSS_KEY_STRUCT_KEY12 |
					TcTssConstants.TSS_KEY_SIZE_2048 | TcTssConstants.TSS_KEY_TYPE_SIGNING |
					TcTssConstants.TSS_KEY_MIGRATABLE | TcTssConstants.TSS_KEY_CERTIFIED_MIGRATABLE);
			
			migratedKey.CMKConvertMigration(destKey, migData, random);
			
		} catch (TcTssException e) {
			if (PRINT_TRACE)
				Log.err(e);
			assertTrue("CMK converting migration blob failed", false);
		}	
	}

	public void testCertifyKey()
	{
		try {

			TcITpm tpm = context_.getTpmObject();
			TestDefines.tpmPolicy.assignToObject(tpm);
			
			// create the parent key of the source
			TcIRsaKey srcKey = context_.createRsaKeyObject(TcTssConstants.TSS_KEY_STRUCT_KEY12 |
					TcTssConstants.TSS_KEY_SIZE_2048 | TcTssConstants.TSS_KEY_TYPE_STORAGE |
					TcTssConstants.TSS_KEY_AUTHORIZATION);
			TestDefines.keyUsgPolicy.assignToObject(srcKey);
			TestDefines.keyMigPolicy.assignToObject(srcKey);
			srcKey.createKey(srk_, null);
			srcKey.loadKey(srk_);
			
			// create a key for the authority and approve its use
			TcIMigData migData = context_.createMigDataObject(0);
			TcIRsaKey maKey = context_.createRsaKeyObject(TcTssConstants.TSS_KEY_STRUCT_KEY12 |
						TcTssConstants.TSS_KEY_SIZE_2048 | TcTssConstants.TSS_KEY_TYPE_SIGNING |
						TcTssConstants.TSS_KEY_AUTHORIZATION);
			TestDefines.keyUsgPolicy.assignToObject(maKey);
			TestDefines.keyMigPolicy.assignToObject(maKey);
			maKey.createKey(srk_, null);
				
			TcBlobData pubKeyBlob = maKey.getAttribData(TcTssConstants.TSS_TSPATTRIB_KEY_BLOB,
					TcTssConstants.TSS_TSPATTRIB_KEYBLOB_PUBLIC_KEY);
			migData.setAttribData(TcTssConstants.TSS_MIGATTRIB_MIGRATIONBLOB, 
					TcTssConstants.TSS_MIGATTRIB_MIG_MSALIST_PUBKEY_BLOB, pubKeyBlob);
			tpm.CMKApproveMA(migData);
			
			// create a CMK
			TcIRsaKey cmKey = context_.createRsaKeyObject(TcTssConstants.TSS_KEY_STRUCT_KEY12 |
					TcTssConstants.TSS_KEY_SIZE_2048 | TcTssConstants.TSS_KEY_TYPE_SIGNING |
					TcTssConstants.TSS_KEY_MIGRATABLE | TcTssConstants.TSS_KEY_CERTIFIED_MIGRATABLE |
					TcTssConstants.TSS_KEY_AUTHORIZATION);
			TestDefines.keyUsgPolicy.assignToObject(cmKey);
			TestDefines.keyMigPolicy.assignToObject(cmKey);
			
			// assign MA/MSA information
			TcBlobData msaDigest = migData.getAttribData(TcTssConstants.TSS_MIGATTRIB_AUTHORITY_DATA, 
					TcTssConstants.TSS_MIGATTRIB_AUTHORITY_DIGEST);
			cmKey.setAttribData(TcTssConstants.TSS_TSPATTRIB_KEY_CMKINFO, 
					TcTssConstants.TSS_TSPATTRIB_KEYINFO_CMK_MA_DIGEST, msaDigest);
			
			TcBlobData msaHmac = migData.getAttribData(TcTssConstants.TSS_MIGATTRIB_AUTHORITY_DATA, 
					TcTssConstants.TSS_MIGATTRIB_AUTHORITY_APPROVAL_HMAC);
			cmKey.setAttribData(TcTssConstants.TSS_TSPATTRIB_KEY_CMKINFO, 
					TcTssConstants.TSS_TSPATTRIB_KEYINFO_CMK_MA_APPROVAL, msaHmac);
			
			cmKey.createKey(srcKey, null);
			cmKey.loadKey(srcKey);
			
			TcIRsaKey certifyKey = context_.createRsaKeyObject(TcTssConstants.TSS_KEY_STRUCT_KEY12 |
					TcTssConstants.TSS_KEY_SIZE_2048 | TcTssConstants.TSS_KEY_TYPE_SIGNING | 
					TcTssConstants.TSS_KEY_MIGRATABLE | TcTssConstants.TSS_KEY_AUTHORIZATION);
			TestDefines.keyUsgPolicy.assignToObject(certifyKey);
			TestDefines.keyMigPolicy.assignToObject(certifyKey);
			certifyKey.createKey(srk_, null);
			certifyKey.loadKey(srk_);
			
			TcTssValidation validation = cmKey.certifyKey(certifyKey, null);
			
		} catch (TcTssException e) {
			if (PRINT_TRACE)
				Log.err(e);
			assertTrue("CMK converting migration blob failed", false);
		}		
	}
}
