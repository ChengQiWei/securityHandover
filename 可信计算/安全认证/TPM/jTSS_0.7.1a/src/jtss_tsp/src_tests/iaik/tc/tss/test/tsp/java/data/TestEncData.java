/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.test.tsp.java.data;


import iaik.tc.tss.api.constants.tpm.TcTpmErrors;
import iaik.tc.tss.api.constants.tsp.TcTssConstants;
import iaik.tc.tss.api.exceptions.common.TcTssException;
import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.tss.api.structs.tsp.TcTssVersion;
import iaik.tc.tss.api.tspi.TcIEncData;
import iaik.tc.tss.api.tspi.TcIPcrComposite;
import iaik.tc.tss.api.tspi.TcIPolicy;
import iaik.tc.tss.api.tspi.TcIRsaKey;
import iaik.tc.tss.test.tsp.java.TestCommon;
import iaik.tc.tss.test.tsp.java.TestDefines;
import iaik.tc.utils.logging.Log;

public class TestEncData extends TestCommon {

	/*************************************************************************************************
	 * Tries to bind and unbind data.
	 */
	public void testBindAndUnbind()
	{
		
	// Testing for bug in microTSS paper 	
	//	for (int i=0; i!=100;i++)
	//	{
		
		try {
			
			
			
			// create new key
			TcIRsaKey key = context_.createRsaKeyObject( //
					TcTssConstants.TSS_KEY_TYPE_BIND | TcTssConstants.TSS_KEY_SIZE_2048 | //
							TcTssConstants.TSS_KEY_VOLATILE | TcTssConstants.TSS_KEY_AUTHORIZATION | // 
							TcTssConstants.TSS_KEY_NOT_MIGRATABLE);
			TestDefines.keyUsgPolicy.assignToObject(key);
			TestDefines.keyMigPolicy.assignToObject(key);
			key.createKey(srk_, null);
			key.loadKey(srk_);

			// create encdata object
			TcIEncData encData = context_.createEncDataObject(TcTssConstants.TSS_ENCDATA_BIND);

			// bind
			TcBlobData rawData = TcBlobData.newString("Hello World from IAIK!");

			encData.bind(key, rawData);

			// get bound data
			TcBlobData boundData = encData.getAttribData(TcTssConstants.TSS_TSPATTRIB_ENCDATA_BLOB,
					TcTssConstants.TSS_TSPATTRIB_ENCDATABLOB_BLOB);
			// Log.debug(boundData.toHexString());

			// unbind
			TcBlobData unboundData = encData.unbind(key);
			// Log.debug(unboundData.toString());

	//		System.out.println("Test no." + i +" completed sucessfully.");
			
			assertEquals("original input data and unbound data do not match", rawData.toString(),
					unboundData.toString());

		} catch (TcTssException e) {
			if (PRINT_TRACE) {
				Log.err(e);
			}
			assertTrue("binding and un-binding failed", false);
		}
//		}
	}


	/*************************************************************************************************
	 * Tries to seal and unseal data.
	 */

//  TODO: readd this class when problems with SOAP are solved
	public void NOtestSealAndUnseal()
	{
		try {
			// use the following line to either use PCR_INFO or PCR_INFO_LONG (and hence get STORED_DATA
			// or STORED_DATA12 return blobs)
			if (getRealTpmVersion().equalsMinMaj(TcTssVersion.TPM_V1_2)
					&& !tpmManufactuerIs(TPM_MAN_ETHZ)) {
				context_.setAttribUint32(TcTssConstants.TSS_TSPATTRIB_CONTEXT_VERSION_MODE, 0,
						TcTssConstants.TSS_TSPATTRIB_CONTEXT_VERSION_V1_2);
			}

			// create new key
			TcIRsaKey key = context_.createRsaKeyObject( //
					TcTssConstants.TSS_KEY_TYPE_STORAGE | TcTssConstants.TSS_KEY_SIZE_2048 | //
							TcTssConstants.TSS_KEY_VOLATILE | TcTssConstants.TSS_KEY_AUTHORIZATION | //
							TcTssConstants.TSS_KEY_NOT_MIGRATABLE);
			TestDefines.keyUsgPolicy.assignToObject(key);
			TestDefines.keyMigPolicy.assignToObject(key);
			key.createKey(srk_, null);
			key.loadKey(srk_);

			// create encdata object
			TcIEncData encData = context_.createEncDataObject(TcTssConstants.TSS_ENCDATA_SEAL);

			// get policy and set secret
			TcIPolicy encDataPol = context_.createPolicyObject(TcTssConstants.TSS_POLICY_USAGE);
			encDataPol
					.setSecret(TcTssConstants.TSS_SECRET_MODE_PLAIN, TcBlobData.newString("dataSecret"));
			encDataPol.assignToObject(encData);

			// get pcr value
			TcBlobData pcrValue = context_.getTpmObject().pcrRead(8);

			// create pcr composite
			TcIPcrComposite pcrs = context_.createPcrCompositeObject(0);
			pcrs.setPcrValue(8, pcrValue);

			// seal
			TcBlobData rawData = TcBlobData.newString("Hello World from IAIK!");
			encData.seal(key, rawData, pcrs);

			// get sealed data (not required but for debuging/demo)
			TcBlobData sealedData = encData.getAttribData(TcTssConstants.TSS_TSPATTRIB_ENCDATA_BLOB,
					TcTssConstants.TSS_TSPATTRIB_ENCDATABLOB_BLOB);

			// unseal
			TcBlobData unsealedData = encData.unseal(key);
			// Log.debug(unsealedData.toString());

			assertEquals("original input data and unsealed data do not match", rawData.toString(),
					unsealedData.toString());

		} catch (TcTssException e) {
			if (PRINT_TRACE) {
				Log.err(e);
			}
			assertTrue("sealing and unsealing failed", false);
		}
	}


	/*************************************************************************************************
	 * Tries to seal and unseal data with a PCR bound key. The PCRs the key is associated with are
	 * changed before unseal. Therefore the Unseal must must fail.
	 */

//  TODO: readd this class when problems with SOAP are solved
	public void NOtestSealAndUnsealWithPcrBoundKey()
	{
		try {
			// use the following line to either use PCR_INFO or PCR_INFO_LONG (and hence get STORED_DATA
			// or STORED_DATA12 return blobs)
			if (getRealTpmVersion().equalsMinMaj(TcTssVersion.TPM_V1_2)
					&& !tpmManufactuerIs(TPM_MAN_ETHZ)) {
				context_.setAttribUint32(TcTssConstants.TSS_TSPATTRIB_CONTEXT_VERSION_MODE, 0,
						TcTssConstants.TSS_TSPATTRIB_CONTEXT_VERSION_V1_2);
			}

			TcIPcrComposite pcrComposite = context_.createPcrCompositeObject(0);
			pcrComposite.setPcrValue(10, context_.getTpmObject().pcrRead(10));

			// create new key
			TcIRsaKey key = context_.createRsaKeyObject( //
					TcTssConstants.TSS_KEY_TYPE_STORAGE | TcTssConstants.TSS_KEY_SIZE_2048 | //
							TcTssConstants.TSS_KEY_VOLATILE | TcTssConstants.TSS_KEY_AUTHORIZATION | //
							TcTssConstants.TSS_KEY_NOT_MIGRATABLE);
			TestDefines.keyUsgPolicy.assignToObject(key);
			TestDefines.keyMigPolicy.assignToObject(key);
			key.createKey(srk_, pcrComposite);
			key.loadKey(srk_);

			// create encdata object
			TcIEncData encData = context_.createEncDataObject(TcTssConstants.TSS_ENCDATA_SEAL);

			// get policy and set secret
			TcIPolicy encDataPol = context_.createPolicyObject(TcTssConstants.TSS_POLICY_USAGE);
			encDataPol
					.setSecret(TcTssConstants.TSS_SECRET_MODE_PLAIN, TcBlobData.newString("dataSecret"));
			encDataPol.assignToObject(encData);

			// get pcr value
			TcBlobData pcrValue = context_.getTpmObject().pcrRead(8);

			// create pcr composite
			TcIPcrComposite pcrs = context_.createPcrCompositeObject(0);
			pcrs.setPcrValue(8, pcrValue);

			// seal
			TcBlobData rawData = TcBlobData.newString("Hello World from IAIK!");
			encData.seal(key, rawData, pcrs);

			// get sealed data (not required but for debugging/demo)
			TcBlobData sealedData = encData.getAttribData(TcTssConstants.TSS_TSPATTRIB_ENCDATA_BLOB,
					TcTssConstants.TSS_TSPATTRIB_ENCDATABLOB_BLOB);

			// extend the PCR the sealing key is bound to
			context_.getTpmObject().pcrExtend(10, TcBlobData.newString("foobar").sha1(), null);

			// unseal
			try {
				TcBlobData unsealedData = encData.unseal(key);
			} catch (TcTssException e) {
				if (e.getErrCode() == TcTpmErrors.TPM_E_WRONGPCRVAL) {
					// expected behavior
					return;
				} else if (e.getErrCode() == TcTpmErrors.TPM_E_INVALID_PCR_INFO) {
					// expected behavior for Atmel Chips
					Log.info("TPM returned error code TPM_INVALID_PCR_INFO but should return TPM_E_WRONGPCRVAL (normal on Atmel TPMv1.2)");
					return;
				} else {
					throw e;
				}
			}

			if (tpmManufactuerIs(TPM_MAN_ETHZ)) {
				Log.info("ETHZ TPM Emulator detected. EMU Bug: PCRs are not checked for PCR bound keys!");
			} else {
				assertTrue("Unseal succeeded although the PCRs the sealing key is bound to changed.", false);
			}
			

		} catch (TcTssException e) {
			if (PRINT_TRACE) {
				Log.err(e);
			}
			assertTrue("sealing and unsealing failed", false);
		}
	}

}
