/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.test.tsp.java.identity.split;


import iaik.tc.tss.api.exceptions.common.TcTssException;
import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.tss.api.tspi.TcTssAbstractFactory;
import iaik.tc.tss.impl.java.tsp.TcTssLocalCallFactory;
import iaik.tc.tss.test.tsp.java.TestCommon;
import iaik.tc.utils.logging.Log;

import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

/***************************************************************************************************
 * This test-case reproduces the steps that are required to generate a TPM identity (AIK key-pair
 * plus AIK credential) using a Privacy CA. The main method of this test-case is the
 * testCreateIdentity method. From there, the client and server side actions are triggered. Note
 * that some aspects of AIK credential generation are not addressed in this test case. This includes
 * the transport of requests and responses using some appropriate protocol. Furthermore, the
 * platform, conformance and endorsement credentials are not verified by the Privacy CA. This can be
 * done by implementing the verifyCredentials method. Finally, the AIK credential created by the
 * Privacy CA only contains dummy content.
 */
public class TestIdentityCreationSplit extends TestCommon {

	/*************************************************************************************************
	 * This is the main test method of this test-case. It contains the high level steps required to
	 * create a TPM identity. These steps are: (1) client: do a CollateIdentityReq call; (2) client:
	 * send blob from CollateIdentityReq call to the privacy CA; (3) privacy CA: decrypt and verify
	 * the received blob; issue AIK credential and send it back to the client; (4) client: receive
	 * encrypted AIK credential from privacy CA and call the ActivateIdentity function.
	 */
	public void testCreateIdentity()
	{
		TcTssAbstractFactory tssFactory = new TcTssLocalCallFactory();

		// create PrivacyCA instance
		PrivacyCa pca = null;
		try {
			pca = new PrivacyCa(tssFactory);
		} catch (TcTssException e) {
			Log.err(e);
			assertTrue("Creating Privacy CA instance failed. TSS error.", false);
		} catch (NoSuchAlgorithmException e) {
			assertTrue("Creating Privacy CA instance failed. Unable to create CA certificates.", false);
		}

		// create Client instance
		Client client = null;
		try {
			client = new Client(tssFactory);
		} catch (TcTssException e) {
			Log.err(e);
			assertTrue("Creating Client instance failed. TSS error.", false);
		}

		// STEP 1 (client): The client does a CollateIdenityRequest.
		// This results in an encrypted blob from the TPM that (among other data) contains the
		// endorsement, platform and conformance credentials.
		// Note that the fields holding some of these credentials simply are null. This is because
		// there currently no hardware/platform manufacturer is shipping these credentials with
		// his platforms. The only exception is Infineon who puts the EK credentials on the their
		// TPM chips (vendor specific for 1.1, in NV storage for 1.2).

		TcBlobData collateIdentityReqBlob = null;
		try {
			collateIdentityReqBlob = client.collateIdentityReq(pca.getPrivacyCaPubKey());
		} catch (TcTssException e) {
			e.printStackTrace();
			assertTrue("client: CollateIdentityRequest failed", false);
		}

		// STEP 2 (client): The blob from the CollateIdentityRequest is sent to the Privacy CA.
		// Note that neither the ASN.1 encoding of the message nor the message transport mechanism are
		// part of this test case.

		// STEP 3 (Privacy CA): The IdentityReq message is received by the Privacy CA.

		TcBlobData symCaAttestationEncrypted = null;
		TcBlobData asymCaContentsEncrypted = null;
		try {
			Object[] caBlobs = pca.mainRoutine(collateIdentityReqBlob);
			symCaAttestationEncrypted = (TcBlobData) caBlobs[0];
			asymCaContentsEncrypted = (TcBlobData) caBlobs[1];
		} catch (TcTssException e) {
			Log.err(e);
			assertTrue("privacy ca: general failure", false);
		} catch (CertificateException e) {
			Log.err(e);
			assertTrue("privacy ca: validation of client certificates failed", false);
		} catch (GeneralSecurityException e) {
			Log.err(e);
			assertTrue("privacy ca: decrypting client blob failed", false);
		}

		// STEP 4 (Privacy CA): Send encrypted sym and asym blobs from the Privacy CA to the client.
		// Note that neither the ASN.1 encoding of the message nor the message transport mechanism are
		// part of this test case.

		// STEP 5 (Client): The encrypted sym and asym blobs are received by the client. The new
		// identity is activated by the client.

		try {
			TcBlobData aikCredential = client.activateIdentity(symCaAttestationEncrypted,
					asymCaContentsEncrypted);

			// This step is only for (unit-) testing to make sure that the certificate received at the
			// client equals the one issued by the PCA.
			if (aikCredential.equals(TcBlobData.newString("AikDummyCert"))) {
				Log.info("AIK credential successfully received and activated at the client");
			} else {
				Log.warn("AIK credential creation failed");
			}

		} catch (TcTssException e) {
			Log.err(e);
			assertTrue("client: activate identity failed", false);
		}
	}
}
