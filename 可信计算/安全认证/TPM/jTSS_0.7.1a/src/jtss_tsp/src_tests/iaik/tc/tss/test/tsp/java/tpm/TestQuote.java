/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.test.tsp.java.tpm;

import iaik.tc.tss.api.constants.tpm.TcTpmOrdinals;
import iaik.tc.tss.api.constants.tsp.TcTssConstants;
import iaik.tc.tss.api.exceptions.common.TcTssException;
import iaik.tc.tss.api.structs.tpm.TcTpmCapVersionInfo;
import iaik.tc.tss.api.structs.tsp.TcTssValidation;
import iaik.tc.tss.api.tspi.TcIPcrComposite;
import iaik.tc.tss.api.tspi.TcIRsaKey;
import iaik.tc.tss.api.tspi.TcITpm;
import iaik.tc.tss.test.tsp.java.TestCommon;
import iaik.tc.tss.test.tsp.java.TestDefines;
import iaik.tc.utils.logging.Log;

public class TestQuote extends TestCommon {

	public void testQuote()
	{
		try {
			TcIRsaKey key = context_.createRsaKeyObject(TcTssConstants.TSS_KEY_TYPE_SIGNING | TcTssConstants.TSS_KEY_AUTHORIZATION);
			TestDefines.keyUsgPolicy.assignToObject(key);
			TestDefines.keyMigPolicy.assignToObject(key);
			key.createKey(srk_, null);
			key.loadKey(srk_);

			TcIPcrComposite pcrComp = context_.createPcrCompositeObject(TcTssConstants.TSS_PCRS_STRUCT_INFO);
			pcrComp.selectPcrIndex(1);
			pcrComp.selectPcrIndex(10);

			TcITpm tpm = context_.getTpmObject();
			tpm.quote(key, pcrComp, null);

			//If the PCR values are needed for validation they must be fetched manually.
			pcrComp.setPcrValue(1, tpm.pcrRead(1));
			pcrComp.setPcrValue(10, tpm.pcrRead(10));

		} catch (TcTssException e) {
			if (PRINT_TRACE) {
				Log.err(e);
			}
			assertTrue("testQuote", false);
		}

	}



	/**
	 * This method tests TPM_Quote2 without requesting a version struct
	 *
	 */
	public void testQuote2withoutVersion()
	{
		try {
			if (!isOrdinalSupported(TcTpmOrdinals.TPM_ORD_Quote2)) {
				Log.info("This TPM does not support TPM_Quote2");
				return;
			}
			if (tpmManufactuerIs(TPM_MAN_ATML)) {
				Log.info("skipping this test on Atmel TPMv1.2 (they have a bug in the signature calculation)");
				return;
			}

			TcIRsaKey key = context_.createRsaKeyObject(TcTssConstants.TSS_KEY_TYPE_SIGNING | TcTssConstants.TSS_KEY_AUTHORIZATION);
			TestDefines.keyUsgPolicy.assignToObject(key);
			TestDefines.keyMigPolicy.assignToObject(key);
			key.createKey(srk_, null);
			key.loadKey(srk_);

			TcIPcrComposite pcrComp = context_.createPcrCompositeObject(TcTssConstants.TSS_PCRS_STRUCT_INFO_SHORT);
			pcrComp.selectPcrIndexEx(1, TcTssConstants.TSS_PCRS_DIRECTION_RELEASE);
			pcrComp.selectPcrIndexEx(10, TcTssConstants.TSS_PCRS_DIRECTION_RELEASE);

			TcITpm tpm = context_.getTpmObject();

			// Quote2 without adding version

			Object[] tpmOutData = tpm.quote2(key, false, pcrComp, null);

			TcTssValidation outValidation = (TcTssValidation)tpmOutData[0];
			TcTpmCapVersionInfo capVersion = (TcTpmCapVersionInfo)tpmOutData[1];

			if (capVersion != null) {
				assertTrue("Version in quote2 return data should be null.", false);
			}

		} catch (TcTssException e) {
			e.printStackTrace();
			assertTrue("testQuote2", false);
		}
	}

	/**
	 * This method tests TPM_Quote2 and requesting a version struct
	 *   this test don't works with TrouSerS by now because of a bug in Tspi_TPM_Quote2
	 */
	public void testQuote2withVersion()
	{
		try {
			if (!isOrdinalSupported(TcTpmOrdinals.TPM_ORD_Quote2)) {
				Log.info("This TPM does not support TPM_Quote2");
				return;
			}
			if (tcsManufactuerIs(TCS_MAN_IBM)) {
				Log.info("The IBM/TrouSerS TSS has a bug at Quote2 when requesting a version struct");
				return;
			}
			if (tpmManufactuerIs(TPM_MAN_ATML)) {
				Log.info("skipping this test on Atmel TPMv1.2 (they have a bug in the signature calculation)");
				return;
			}
			if (tpmManufactuerIs(TPM_MAN_IBM)) {
				Log.info("skipping this test on IBM SW TPM (they seem to have an implementation bug)");
				return;
			}

			TcIRsaKey key = context_.createRsaKeyObject(TcTssConstants.TSS_KEY_TYPE_SIGNING | TcTssConstants.TSS_KEY_AUTHORIZATION);
			TestDefines.keyUsgPolicy.assignToObject(key);
			TestDefines.keyMigPolicy.assignToObject(key);
			key.createKey(srk_, null);
			key.loadKey(srk_);

			TcIPcrComposite pcrComp = context_.createPcrCompositeObject(TcTssConstants.TSS_PCRS_STRUCT_INFO_SHORT);
			pcrComp.selectPcrIndexEx(1, TcTssConstants.TSS_PCRS_DIRECTION_RELEASE);
			pcrComp.selectPcrIndexEx(10, TcTssConstants.TSS_PCRS_DIRECTION_RELEASE);

			TcITpm tpm = context_.getTpmObject();

			Object[] tpmOutData = tpm.quote2(key, true, pcrComp, null);

			TcTssValidation outValidation = (TcTssValidation)tpmOutData[0];
			TcTpmCapVersionInfo capVersion = (TcTpmCapVersionInfo)tpmOutData[1];

//			Log.debug(outValidation.toString());
//			Log.debug(capVersion.toString());

			if (capVersion == null) {
				assertTrue("Version in quote2 return data should NOT be null.", false);
			}


		} catch (TcTssException e) {
			e.printStackTrace();
			assertTrue("testQuote2", false);
		}
	}
}
