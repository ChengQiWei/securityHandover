/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.test.tsp.java.tpm;


import iaik.tc.tss.api.constants.tpm.TcTpmConstants;
import iaik.tc.tss.api.constants.tpm.TcTpmErrors;
import iaik.tc.tss.api.constants.tpm.TcTpmOrdinals;
import iaik.tc.tss.api.constants.tsp.TcTssConstants;
import iaik.tc.tss.api.constants.tsp.TcTssErrors;
import iaik.tc.tss.api.exceptions.common.TcTssException;
import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.tss.api.structs.tpm.TcTpmCounterValue;
import iaik.tc.tss.api.structs.tsp.TcTssValidation;
import iaik.tc.tss.api.tspi.TcIPolicy;
import iaik.tc.tss.api.tspi.TcIRsaKey;
import iaik.tc.tss.api.tspi.TcITpm;
import iaik.tc.tss.impl.csp.TcCrypto;
import iaik.tc.tss.test.tsp.java.TestCommon;
import iaik.tc.tss.test.tsp.java.TestDefines;
import iaik.tc.utils.logging.Log;

public class TestTpm extends TestCommon {

	/**
	 * Triggers a TPM self-test.
	 */
	public void testSelfTest()
	{
		try {
			TcITpm tpm = context_.getTpmObject();
			tpm.selfTestFull();
		} catch (TcTssException e) {
			if (PRINT_TRACE)
				Log.err(e);
			assertTrue("triggering TPM self-test failed", false);
		}
	}


	public void testGetTestResult()
	{
		try {
			TcITpm tpm = context_.getTpmObject();
			TcBlobData res = tpm.getTestResult();
		} catch (TcTssException e) {
			if (PRINT_TRACE)
				Log.err(e);
			assertTrue("testGetTestResult failed", false);
		}

	}


	/**
	 * Reads public EK from TPM with owner authorization (assuming TPM ownership is already taken)
	 */
	public void testGetEndorsementKeyOwner()
	{
		try {
			TcITpm tpm = context_.getTpmObject();
			TestDefines.tpmPolicy.assignToObject(tpm);
			TcIRsaKey pubEk = tpm.getPubEndorsementKeyOwner();
		} catch (TcTssException e) {
			if (e.getErrCode() == TcTpmErrors.TPM_E_NOSRK) {
				Log.info("TPM Ownership not taken.");
			} else {
				if (PRINT_TRACE)
					Log.err(e);
				assertTrue("testGetEndorsementKeyOwner failed", false);
			}
		}
	}


	/**
	 * <ul>
	 * <li> Reads public EK from TPM without owner authorization. This is typically only possible if
	 * ownership has not yet been taken.
	 * <li> Checksum validation is done by the TSP (validation is set to null)
	 * </ul>
	 */
	public void testGetEndorsementKeyNoOwner()
	{
		try {
			TcITpm tpm = context_.getTpmObject();
			Object[] resData = tpm.getPubEndorsementKey(false, null);
		} catch (TcTssException e) {
			if (e.getErrCode() == TcTpmErrors.TPM_E_DISABLED_CMD) {
				Log.info("Reading public EK without owner authorization is disabled.");
				return;
			}
			if (PRINT_TRACE) {
				Log.err(e);
			}
			assertTrue("testGetEndorsementKeyNoOwner failed", false);
		}
	}


	/**
	 * <ul>
	 * <li> Reads public EK from TPM without owner authorization. This is typically only possible if
	 * ownership has not yet been taken.
	 * <li> Checksum validation is done by the test code.
	 * </ul>
	 */
	public void testGetEndorsementKeyNoOwnerSelfValidate()
	{
		try {
			TcTssValidation validataion = new TcTssValidation();
			TcBlobData externalData = TcCrypto.getRandom((int) TcTpmConstants.TPM_SHA1_160_HASH_LEN);
			validataion.setExternalData(externalData);
			TcITpm tpm = context_.getTpmObject();
			Object[] resData = tpm.getPubEndorsementKey(false, validataion);
			TcIRsaKey pubEk = (TcIRsaKey)resData[0];
			TcTssValidation outValidation = (TcTssValidation)resData[1];

			TcBlobData pubEkBlob = pubEk.getAttribData(TcTssConstants.TSS_TSPATTRIB_KEY_BLOB,
					TcTssConstants.TSS_TSPATTRIB_KEYBLOB_PUBLIC_KEY);
			TcBlobData expectedData = (TcBlobData) pubEkBlob.clone();
			expectedData.append(externalData);

			if (!outValidation.getValidationData().equals(expectedData.sha1())) {
				assertTrue("validation of pubEK checksum failed", false);
			}

		} catch (TcTssException e) {
			if (e.getErrCode() == TcTpmErrors.TPM_E_DISABLED_CMD) {
				Log.info("Reading public EK without owner authorization is disabled.");
				return;
			}
			if (PRINT_TRACE) {
				Log.err(e);
			}
			assertTrue("testGetEndorsementKeyNoOwnerSelfValidate failed", false);
		}
	}


	/**
	 * <ul>
	 * <li> get random data from TPM
	 * <li> stir TPM random data using external random data
	 * <li> once again get random data from TPM
	 * </ul>
	 */
	public void testGetRandomAndStirRandom()
	{
		try {
			TcITpm tpm = context_.getTpmObject();
			TcBlobData bd = tpm.getRandom(128);
			tpm.stirRandom(TcCrypto.getRandom(128));
			bd = tpm.getRandom(256);
		} catch (TcTssException e) {
			if (PRINT_TRACE) {
				Log.err(e);
			}
			assertTrue("stirRandom/getRandom failed", false);
		}
	}


	/*************************************************************************************************
	 * Tries write and read a Data Integrity Register (DIR)
	 */
	public void NOtestDirReadAndWrite()
	{
		try {
			if (!isOrdinalSupported(TcTpmOrdinals.TPM_ORD_DirRead)) {
				Log.info("TPM_ORD_DirRead is not supported by this TPM");
				return;
			}

			TcITpm tpm = context_.getTpmObject();
			TestDefines.tpmPolicy.assignToObject(tpm);

			TcBlobData bdRead = tpm.dirRead(1);
			// Log.debug(this, "len: " + bdRead.getLength());
			// Log.debug(this, "data: " + bdRead.toHexString());

			TcBlobData bdWrite = TcBlobData.newString("dir test value").sha1();
			tpm.dirWrite(1, bdWrite);

			bdRead = tpm.dirRead(1);
			// Log.debug(this, "len: " + bdRead.getLength());
			// Log.debug(this, "data: " + bdRead.toHexString());

			if (!(bdWrite.toHexString()).equals(bdRead.toHexString())) {
				assertTrue("actual DIR content does not match expected content (see warning).", false);
			}

		} catch (TcTssException e) {
			if (PRINT_TRACE) {
				Log.err(e);
			}
			assertTrue("reading or writing dir failed", false);
		}
	}



	/*************************************************************************************************
	 * Tries to unlock the TPM if it is in some lock state (e.g. defending against dictionary
	 * attacks).
	 */
	public void NOtestUnlock()
	{
		try {
			TcITpm tpm = context_.getTpmObject();
			TestDefines.tpmPolicy.assignToObject(tpm);
			tpm.setStatus(TcTssConstants.TSS_TPMSTATUS_RESETLOCK, true);
		} catch (TcTssException e) {
			if (PRINT_TRACE) {
				Log.err(e);
			}
		}
	}
	
	
	/*************************************************************************************************
	 * Tries to read the value of the current counter
	 */
	public void testReadCurrentCounter()
	{
		try {
			if (tpmManufactuerIs(TPM_MAN_ETHZ)) {
				// TPM Emulator up to 0.5.1 not implemented the PROP_ACTIVE_COUNTER capability
				Log.info("skipping this test on TPM Emulator because of not implemented capability TPM_CAP_PROP_ACTIVE_COUNTER");
				return;
			}
			
			TcITpm tpm = context_.getTpmObject();
			TestDefines.tpmPolicy.assignToObject(tpm);
			TcTpmCounterValue counterValue = tpm.readCurrentCounter();
		} catch (TcTssException e) {
			if (e.getErrCode() == TcTssErrors.TSS_E_NO_ACTIVE_COUNTER) {
				Log.info("There is no counter active");
				return;
			}
			if (PRINT_TRACE) {
				Log.err(e);
			}
			assertTrue("reading of current counter value failed", false);
		}
	}
	
	/*************************************************************************************************
	 * Tries to set the operator authorization
	 * Test would need physical presence therefore it is deactivated
	 */
	public void NOtestSetOperatorAuth()
	{
		try {			
			TcITpm tpm = context_.getTpmObject();
			TestDefines.tpmPolicy.assignToObject(tpm);
			
			TcIPolicy operatorPolicy = context_.createPolicyObject(TcTssConstants.TSS_POLICY_OPERATOR);
			operatorPolicy.setSecret(TcTssConstants.TSS_SECRET_MODE_PLAIN, TcBlobData.newString("operatorSecret"));
			
			tpm.setOperatorAuth(operatorPolicy);
			
			TcIPolicy outPolicy = tpm.getPolicyObject(TcTssConstants.TSS_POLICY_OPERATOR);
			
			if(outPolicy == null)
				assertTrue("Operator Policy should be not null after SetOperatorAuth", false);
			
		} catch (TcTssException e) {
			if (PRINT_TRACE) {
				Log.err(e);
			}
			assertTrue("reading of current counter value failed", false);
		}
	}
}
