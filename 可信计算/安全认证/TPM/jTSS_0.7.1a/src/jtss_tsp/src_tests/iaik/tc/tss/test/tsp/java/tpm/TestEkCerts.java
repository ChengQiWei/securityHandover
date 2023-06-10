/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.test.tsp.java.tpm;


import iaik.tc.tss.api.exceptions.common.TcTssException;
import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.tss.api.tspi.TcITpm;
import iaik.tc.tss.impl.java.tsp.TcTpm;
import iaik.tc.tss.test.tsp.java.TestCommon;
import iaik.tc.tss.test.tsp.java.TestDefines;
import iaik.tc.utils.logging.Log;

public class TestEkCerts extends TestCommon {

	/**
	 * Reads the EK certificate from IFX 1.1 TPMs.
	 */
	public void testGetCredentials()
	{
		try {
			TcITpm tpm = context_.getTpmObject();
			TestDefines.tpmPolicy.assignToObject(tpm);

			if (!tcsManufactuerIs(TCS_MAN_IAIK)) {
				Log.debug("Reading the EK certificate from chip is only supported on IFX 1.1 chips (vendor specific) and IFX 1.2 chips (NV) and only supported by IAIK/jTSS.");
			}

			if (tpm instanceof TcTpm) {
				Object[] credentials = ((TcTpm) tpm).getCredentials();
				TcBlobData ekCert = (TcBlobData)credentials[0];

				if (ekCert == null) {
					Log.info("Unable to obtain EK certificate for this TPM.");
					return;
				}

				/*
				try {
					
					FileOutputStream fo = new FileOutputStream("ek.cert");
					fo.write(ekCert.asByteArray());
					fo.close();
					Log.info("EK certificate written into file: ek.cert");
					
				} catch (IOException e) {
					Log.err(e);
				}
				*/
			}
		} catch (TcTssException e) {
			if (PRINT_TRACE) {
				Log.err(e);
			}
			assertTrue("Getting credentials failed.", false);
		}
	}

}
