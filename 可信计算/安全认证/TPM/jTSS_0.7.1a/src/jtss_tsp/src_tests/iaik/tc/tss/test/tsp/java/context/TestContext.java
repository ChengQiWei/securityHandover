/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.test.tsp.java.context;

import iaik.tc.tss.api.constants.tpm.TcTpmErrors;
import iaik.tc.tss.api.constants.tsp.TcTssConstants;
import iaik.tc.tss.api.exceptions.common.TcTssException;
import iaik.tc.tss.api.exceptions.tcs.TcTpmException;
import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.tss.api.structs.tsp.TcTssVersion;
import iaik.tc.tss.api.tspi.TcITpm;
import iaik.tc.tss.test.tsp.java.TestCommon;
import iaik.tc.utils.logging.Log;

public class TestContext extends TestCommon {
	
	public void testContextCreation()
	{
		try {
			context_.setAttribUint32(TcTssConstants.TSS_TSPATTRIB_CONTEXT_SILENT_MODE, 0, TcTssConstants.TSS_TSPATTRIB_CONTEXT_SILENT);
		
			long val = context_.getAttribUint32(TcTssConstants.TSS_TSPATTRIB_CONTEXT_SILENT_MODE, 0);
		
			context_.connect();
			
			TcITpm tpm = context_.getTpmObject();
			TcBlobData aesSupport = tpm.getCapability(TcTssConstants.TSS_TPMCAP_ALG, TcBlobData.newUINT32(TcTssConstants.TSS_ALG_AES));
//			Log.debug(aesSupport.toHexString());
			
			TcTssVersion tpmVersion = tpm.getCapabilityVersion(TcTssConstants.TSS_TPMCAP_VERSION, null);
//			Log.debug(tpmVersion.toString());
			try {
				TcTssVersion tpmVersionVal = tpm.getCapabilityVersion(TcTssConstants.TSS_TPMCAP_VERSION_VAL, null);
				Log.info("TPM version : " + tpmVersionVal.toString());
			} catch (TcTpmException e) {
				if (e.getErrCode() == TcTpmErrors.TPM_E_BAD_MODE) {
					Log.info("TSS_TPMCAP_VERSION_VAL is not supported by this TPM");
				} else {
					throw e;
				}
			}
			
			TcTssVersion tcsVersion = context_.getCapabilityVersion(TcTssConstants.TSS_TCSCAP_VERSION, null);
			Log.info("TCS version : " + tcsVersion.toString());

			TcTssVersion tspVersion = context_.getCapabilityVersion(TcTssConstants.TSS_TSPCAP_VERSION, null);
			Log.info("TSP version : " + tspVersion.toString());

		} catch (TcTssException e) {
			Log.err(e);
		}
	}
	
}
