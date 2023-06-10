/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.test.tsp.java.ownership;

import iaik.tc.tss.api.constants.tpm.TcTpmErrors;
import iaik.tc.tss.api.exceptions.common.TcTssException;
import iaik.tc.tss.api.exceptions.tcs.TcTpmException;
import iaik.tc.tss.api.tspi.TcITpm;
import iaik.tc.tss.test.tsp.java.TestCommon;
import iaik.tc.tss.test.tsp.java.TestDefines;
import iaik.tc.utils.logging.Log;

public class TestClearOwner extends TestCommon {

	public void testClearOwner()
	{
		try {
			TcITpm tpm = context_.getTpmObject();
			TestDefines.tpmPolicy.assignToObject(tpm);
			context_.getTpmObject().clearOwner(false);
			
		} catch (TcTpmException e) {
			if (e.getErrCode() == TcTpmErrors.TPM_E_DISABLED) {
				Log.info("Unable to clear ownership. TPM is disabled.");
			} else if (e.getErrCode() == TcTpmErrors.TPM_E_NOSRK) {
				Log.info("TPM has no SRK set. TPM already cleared?");
			} else {
				if (PRINT_TRACE) e.printStackTrace();
				assertTrue("clearing TPM ownership failed", false);
			}
		} catch (TcTssException e) {
			if (PRINT_TRACE) e.printStackTrace();
			assertTrue("clearing TPM ownership failed", false);
		}
	}
	
	public void NotestForceClearOwner()
	{
		try {
			TcITpm tpm = context_.getTpmObject();
			TestDefines.tpmPolicy.assignToObject(tpm);
			context_.getTpmObject().clearOwner(true);
			
		} catch (TcTpmException e) {
			if (e.getErrCode() == TcTpmErrors.TPM_E_DISABLED) {
				Log.info("Unable to clear ownership. TPM is disabled.");
			} else if (e.getErrCode() == TcTpmErrors.TPM_E_NOSRK) {
				Log.info("TPM has no SRK set. TPM already cleared?");
			} else {
				if (PRINT_TRACE) e.printStackTrace();
				assertTrue("clearing TPM ownership failed", false);
			}
		} catch (TcTssException e) {
			if (PRINT_TRACE) e.printStackTrace();
			assertTrue("clearing TPM ownership failed", false);
		}
	}
	
}
