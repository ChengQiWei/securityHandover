/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.test.tsp.java.hash;


import iaik.tc.tss.api.constants.tsp.TcTssConstants;
import iaik.tc.tss.api.exceptions.common.TcTssException;
import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.tss.api.tspi.TcIHash;
import iaik.tc.tss.api.tspi.TcIRsaKey;
import iaik.tc.tss.test.tsp.java.TestCommon;
import iaik.tc.tss.test.tsp.java.TestDefines;
import iaik.tc.utils.logging.Log;

public class TestHash extends TestCommon {

	/*************************************************************************************************
	 * Test for all Hash related methods.
	 */
	public void testAllMethods()
	{
		try {
			// signing key creation
			TcIRsaKey key = context_.createRsaKeyObject(TcTssConstants.TSS_KEY_TYPE_SIGNING
					| TcTssConstants.TSS_KEY_AUTHORIZATION | TcTssConstants.TSS_KEY_MIGRATABLE);
			key
					.setAttribUint32(TcTssConstants.TSS_TSPATTRIB_KEY_INFO,
							TcTssConstants.TSS_TSPATTRIB_KEYINFO_SIGSCHEME,
							TcTssConstants.TSS_SS_RSASSAPKCS1V15_SHA1);
			TestDefines.keyUsgPolicy.assignToObject(key);
			TestDefines.keyMigPolicy.assignToObject(key);
			key.createKey(srk_, null);
			key.loadKey(srk_);

			// create
			TcIHash hash = context_.createHashObject(TcTssConstants.TSS_HASH_SHA1);

			// update
			TcBlobData data = TcBlobData.newString("Hello World");
			hash.updateHashValue(data);

			// get
			TcBlobData hashValue = hash.getHashValue();

			// compute expected SHA1 and compare it with value from TPM
			TcBlobData expected = data.sha1();
			if (!hashValue.equals(expected)) {
				assertEquals("hash value differs from expected value", expected, hashValue.toHexString()
						.trim());
			}

			// sign
			TcBlobData signature = hash.sign(key);

			// verify
			hash.verifySignature(signature, key);

			// set + verify
			TcIHash hash2 = context_.createHashObject(TcTssConstants.TSS_HASH_SHA1);
			hash2.setHashValue(hashValue);
			hash2.verifySignature(signature, key);

		} catch (TcTssException e) {
			if (PRINT_TRACE) {
				Log.err(e);
			}
			assertTrue("hash function test sequence failed", false);
		}

	}
}
