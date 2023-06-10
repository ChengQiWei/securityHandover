/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.test.tsp.java.ownership;


import iaik.tc.tss.api.constants.tpm.TcTpmErrors;
import iaik.tc.tss.api.constants.tsp.TcTssConstants;
import iaik.tc.tss.api.exceptions.common.TcTssException;
import iaik.tc.tss.api.exceptions.tcs.TcTpmException;
import iaik.tc.tss.api.tspi.TcIRsaKey;
import iaik.tc.tss.api.tspi.TcITpm;
import iaik.tc.tss.test.tsp.java.TestCommon;
import iaik.tc.tss.test.tsp.java.TestDefines;
import iaik.tc.utils.logging.Log;
import junit.framework.Assert;

public class TestTakeOwnership extends TestCommon {

	public void testTakeOwnership()
	{
		try {
			TcITpm tpm = context_.getTpmObject();
			TestDefines.tpmPolicy.assignToObject(tpm);
			TcIRsaKey srk = context_.createRsaKeyObject(TcTssConstants.TSS_KEY_TSP_SRK | TcTssConstants.TSS_KEY_AUTHORIZATION);
			TestDefines.srkPolicy.assignToObject(srk);
			tpm.takeOwnership(srk, null);
		} catch (TcTpmException e) {
			if (e.getErrCode() == TcTpmErrors.TPM_E_OWNER_SET) {
				// this will happen in most cases 
				Log.info("TPM ownership already taken");
			} else if (e.getErrCode() == TcTpmErrors.TPM_E_DISABLED_CMD) {
				// this will happen in some cases
				Log.info("TPM ownership command is disabled");
			} else if (e.getErrCode() == TcTpmErrors.TPM_E_DISABLED) {
				// this will happen in some cases
				Log.info("TPM is disabled");
			} else {
				if (PRINT_TRACE) e.printStackTrace();
				Assert.assertTrue("takeOwnership failed", false);
			}
		} catch (TcTssException e) {
			if (PRINT_TRACE) e.printStackTrace();
			Assert.assertTrue("takeOwnership failed", false);
		}
	}

}
