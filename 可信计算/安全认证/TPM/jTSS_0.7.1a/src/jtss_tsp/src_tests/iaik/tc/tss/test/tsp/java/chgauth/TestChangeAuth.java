/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.test.tsp.java.chgauth;

import iaik.tc.tss.api.constants.tpm.TcTpmErrors;
import iaik.tc.tss.api.constants.tsp.TcTssConstants;
import iaik.tc.tss.api.exceptions.common.TcTssException;
import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.tss.api.tspi.TcIEncData;
import iaik.tc.tss.api.tspi.TcIHash;
import iaik.tc.tss.api.tspi.TcIPolicy;
import iaik.tc.tss.api.tspi.TcIRsaKey;
import iaik.tc.tss.api.tspi.TcITpm;
import iaik.tc.tss.test.tsp.java.TestCommon;
import iaik.tc.tss.test.tsp.java.TestDefines;
import iaik.tc.utils.logging.Log;

public class TestChangeAuth extends TestCommon {
	
	public void testResetLock()
	{
		try {
			TcITpm tpm = context_.getTpmObject();
			TestDefines.tpmPolicy.assignToObject(tpm);
			tpm.setStatus(TcTssConstants.TSS_TPMSTATUS_RESETLOCK, true);
		} catch (TcTssException e) {
			
		}
	}
	
	public void testChangeKeyAuth()
	{
		try {
			TcIRsaKey key = context_.createRsaKeyObject(TcTssConstants.TSS_KEY_TYPE_SIGNING);
			TestDefines.keyUsgPolicy.assignToObject(key);
			TestDefines.keyMigPolicy.assignToObject(key);
			key.createKey(srk_, null);

			// use key (requires secret)
			key.loadKey(srk_);
			TcIHash hash = context_.createHashObject(TcTssConstants.TSS_HASH_SHA1);
			hash.updateHashValue(TcBlobData.newString("test"));
			hash.sign(key);

			// change policy
			TcIPolicy newPolicy = context_.createPolicyObject(TcTssConstants.TSS_POLICY_USAGE);
			newPolicy.setSecret(TestDefines.KEY_SECRET_MODE, TcBlobData.newString("new secret").sha1());
			key.changeAuth(srk_, newPolicy);
			key.unloadKey();

			// use key again to check if auth change worked
			key.loadKey(srk_);
			hash = context_.createHashObject(TcTssConstants.TSS_HASH_SHA1);
			hash.updateHashValue(TcBlobData.newString("test"));
			hash.sign(key);
			key.unloadKey();

			// set wrong usage secret (i.e. use old secret) and ensure that this does not work anymore
			TestDefines.keyUsgPolicy.assignToObject(key);

			// use key again to check if auth change worked
			key.loadKey(srk_);
			hash = context_.createHashObject(TcTssConstants.TSS_HASH_SHA1);
			hash.updateHashValue(TcBlobData.newString("test"));
			try {
				hash.sign(key);
				assertTrue("Hash.sign succeeded although it should not due to changed auth.", false);
			} catch (TcTssException e) {
				if (e.getErrCode() == TcTpmErrors.TPM_E_AUTHFAIL) {
					// expected behavior
				} else {
					key.unloadKey();
					throw e;
				}
			} finally {
				key.unloadKey();
			}

		} catch (TcTssException e) {
			if (PRINT_TRACE) {
				Log.err(e);
			}
			assertTrue("changing key auth failed", false);
		}

	}


	public void testChangeEncDataAuth()
	{
		try {
			TcIRsaKey key = context_.createRsaKeyObject(TcTssConstants.TSS_KEY_TYPE_STORAGE);
			TestDefines.keyUsgPolicy.assignToObject(key);
			TestDefines.keyMigPolicy.assignToObject(key);
			key.createKey(srk_, null);
			key.loadKey(srk_);

			// seal data (using secret)
			TcIEncData encData = context_.createEncDataObject(TcTssConstants.TSS_ENCDATA_SEAL);
			TcIPolicy origPolicy = context_.createPolicyObject(TcTssConstants.TSS_POLICY_USAGE);
			origPolicy.setSecret(TcTssConstants.TSS_SECRET_MODE_PLAIN, TcBlobData.newString("originalSecret"));
			origPolicy.assignToObject(encData);
			encData.seal(key, TcBlobData.newString("some data"), null);

			// change policy of sealed data
			TcIPolicy newPolicy = context_.createPolicyObject(TcTssConstants.TSS_POLICY_USAGE);
			newPolicy.setSecret(TestDefines.KEY_SECRET_MODE, TcBlobData.newString("new secret").sha1());
			encData.changeAuth(key, newPolicy);

			// do unseal using the new secret
			encData.unseal(key);

			// set wrong secret for encData (i.e. set the original secret)
			origPolicy.assignToObject(encData);

			// do unseal using the original secret (this should fail)
			try {
				encData.unseal(key);
				assertTrue("Unseal succeeded although it should not due to changed auth.", false);
			} catch (TcTssException e) {
				if (e.getErrCode() == TcTpmErrors.TPM_E_AUTHFAIL
						|| e.getErrCode() == TcTpmErrors.TPM_E_AUTH2FAIL) {
					// expected behavior
				} else {
					throw e;
				}
			}

		} catch (TcTssException e) {
			if (PRINT_TRACE) {
				Log.err(e);
			}
			assertTrue("changing encData auth failed", false);
		}
	}


	public void testChangeTpmAuth()
	{
		try {
			TcIPolicy newPolicy = context_.createPolicyObject(TcTssConstants.TSS_POLICY_USAGE);
			newPolicy.setSecret(TestDefines.OWNER_SECRET_MODE, TcBlobData.newString("some new secret"));
			
			TcITpm tpm = context_.getTpmObject();
			TestDefines.tpmPolicy.assignToObject(tpm);

			// change the ownership secret
			tpm.changeAuth(null, newPolicy);
			
			try {
				// try to read the EK using the old owner secret - should fail
				TestDefines.tpmPolicy.assignToObject(tpm);
				tpm.getPubEndorsementKeyOwner();
				assertTrue("GetPubEk succeeded although it should not due to changed auth.", false);
			} catch (TcTssException e) {
				if (e.getErrCode() == TcTpmErrors.TPM_E_AUTHFAIL) {
					// expected behavior
				} else {
					throw e;
				}
			}

			// reading the public EK with the new owner secret should work
			newPolicy.assignToObject(tpm);
			tpm.getPubEndorsementKeyOwner();

			// change the ownership secret back to the initial value
			tpm.changeAuth(null, TestDefines.tpmPolicy);

		} catch (TcTssException e) {
			if (PRINT_TRACE) {
				Log.err(e);
			}
			assertTrue("changing TPM owner secret failed", false);
		}
	}


	public void testChangeSrkAuth()
	{
	
		try {
			
			
			TcITpm tpm = context_.getTpmObject();
			TestDefines.tpmPolicy.assignToObject(tpm);

			TcIPolicy newPolicy = context_.createPolicyObject(TcTssConstants.TSS_POLICY_USAGE);
			newPolicy.setSecret(TestDefines.SRK_SECRET_MODE, TcBlobData.newString("some new secret")
					.sha1());

			// change SRK auth to new secret
			srk_.changeAuth(tpm, newPolicy);

			// seal data (using SRK)
			TcIEncData encData = context_.createEncDataObject(TcTssConstants.TSS_ENCDATA_SEAL);
			TcIPolicy encDataPol = context_.createPolicyObject(TcTssConstants.TSS_POLICY_USAGE);
			encDataPol.setSecret(TcTssConstants.TSS_SECRET_MODE_PLAIN, TcBlobData.newString("dataSecret"));
			encDataPol.assignToObject(encData);
			encData.seal(srk_, TcBlobData.newString("some data"), null);

			// try unseal using the old SRK auth
			try {
				TestDefines.srkPolicy.assignToObject(srk_);
				encData.unseal(srk_);
				assertTrue("Unseal succeeded although it should not due to changed auth.", false);
			} catch (TcTssException e) {
				if (e.getErrCode() == TcTpmErrors.TPM_E_AUTHFAIL || e.getErrCode() == TcTpmErrors.TPM_E_AUTH2FAIL) { //AUTH2FAIL is the (incorrect) behavior of the IBM SW TPM
					// expected behavior
				} else {
					throw e;
				}
			}

			// try unseal using the new SRK auth
			newPolicy.assignToObject(srk_);
			encData.unseal(srk_);

			// change SRK auth back to old secret
			srk_.changeAuth(tpm, TestDefines.srkPolicy);

		} catch (TcTssException e) {
			if (PRINT_TRACE) {
				Log.err(e);
			}
			assertTrue("changing SRK secret failed", false);
		}
	}

}
