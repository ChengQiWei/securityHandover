/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.test.tsp.java.misc;


import iaik.tc.tss.api.constants.tpm.TcTpmConstants;
import iaik.tc.tss.api.constants.tsp.TcTssConstants;
import iaik.tc.tss.api.exceptions.common.TcTssException;
import iaik.tc.tss.api.structs.common.TcBasicTypeDecoder;
import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.tss.api.structs.tcs.TcTcsAuth;
import iaik.tc.tss.api.structs.tpm.TcTpmKeyHandleList;
import iaik.tc.tss.api.structs.tsp.TcTssUuid;
import iaik.tc.tss.api.structs.tsp.TcTssVersion;
import iaik.tc.tss.api.structs.tsp.TcUuidFactory;
import iaik.tc.tss.api.tspi.TcIContext;
import iaik.tc.tss.api.tspi.TcIPcrComposite;
import iaik.tc.tss.api.tspi.TcIRsaKey;
import iaik.tc.tss.api.tspi.TcITpm;
import iaik.tc.tss.api.tspi.TcTssContextFactory;
import iaik.tc.tss.impl.java.tsp.TcContext;
import iaik.tc.tss.impl.java.tsp.TcTssLocalCallFactory;
import iaik.tc.tss.impl.java.tsp.internal.TcTspInternal;
import iaik.tc.tss.test.tsp.java.TestCommon;
import iaik.tc.tss.test.tsp.java.TestDefines;
import iaik.tc.utils.logging.Log;

import java.util.UUID;
import java.math.BigInteger;

public class TestMisc extends TestCommon {

	
	public void testBigIntegerDecoding()
	{
		BigInteger number = new BigInteger("258");
		
		TcBlobData numberBlog=TcBlobData.newUINT64(number);
					
		BigInteger returnedNumber=new BigInteger(numberBlog.asByteArray());
		
		assertTrue(number.compareTo(returnedNumber) == 0);
		
	}
		
		
	
	public void testTcsiPS()
	{
		try {
			TcITpm tpm = context_.getTpmObject();
			tpm.getUsagePolicyObject().setSecret(TcTssConstants.TSS_SECRET_MODE_PLAIN, TcBlobData.newString("opentc"));
			TcIRsaKey ek = tpm.getPubEndorsementKeyOwner();
			Log.debug(ek.getPubKey().toHexString());
			
		} catch (TcTssException e) {
			if (PRINT_TRACE) {
				Log.err(e);
			}
			assertTrue("creating key failed", false);
		}

	}


	public void NOtestCreateKey()
	{
		try {

			context_.setAttribUint32(TcTssConstants.TSS_TSPATTRIB_CONTEXT_VERSION_MODE, 0,
					TcTssConstants.TSS_TSPATTRIB_CONTEXT_VERSION_V1_2);

			TcIPcrComposite pcrComp = context_.createPcrCompositeObject(0);
			pcrComp.setPcrValue(10, context_.getTpmObject().pcrRead(10));

			TcIRsaKey key = context_.createRsaKeyObject(TcTssConstants.TSS_KEY_TYPE_STORAGE);
			TestDefines.keyUsgPolicy.assignToObject(key);
			TestDefines.keyMigPolicy.assignToObject(key);
			key.createKey(srk_, pcrComp);

			key.loadKey(srk_);

			// context_.getTpmObject().pcrExtend(10, TcBlobData.newString("foobar").sha1(), null);

			TcIRsaKey key2 = context_.createRsaKeyObject(TcTssConstants.TSS_KEY_TYPE_STORAGE);
			TestDefines.keyUsgPolicy.assignToObject(key2);
			TestDefines.keyMigPolicy.assignToObject(key2);
			key2.createKey(key, null);

		} catch (TcTssException e) {
			if (PRINT_TRACE) {
				Log.err(e);
			}
			assertTrue("creating key failed", false);
		}
	}


	public void NOtestUuid()
	{
		for (int i = 0; i < 1; i++) {

			UUID uuid = UUID.randomUUID();

			TcTssUuid tssUuid = TcUuidFactory.getInstance().convertUuidJavaToTss(uuid);

			TcTssUuid tssUuid2 = new TcTssUuid().initString(tssUuid.toStringNoPrefix());

			UUID uuid2 = TcUuidFactory.getInstance().convertUuidTssToJava(tssUuid);

			if (!uuid.toString().equals(tssUuid.toStringNoPrefix())
					|| !uuid.toString().equals(uuid2.toString())
					|| !tssUuid2.toStringNoPrefix().equals(tssUuid.toStringNoPrefix())) {
				Log.debug("mismatch");
				Log.debug("UUID Java:     " + uuid.toString());
				Log.debug("TssUUID Java:  " + tssUuid.toStringNoPrefix());
				Log.debug("UUID2 Java:    " + uuid2.toString());
				Log.debug("TssUUID2 Java: " + tssUuid2.toStringNoPrefix());
			}
		}
	}


	public void NOtestCap()
	{
		try {

			Log.debug("-------------------------");
			TcBlobData subCap = TcBlobData.newUINT32(TcTssConstants.TSS_TPMCAP_PROP_PCR);
			TcBlobData pcrs = context_.getTpmObject().getCapability(TcTssConstants.TSS_TPMCAP_PROPERTY,
					subCap);
			Log.debug("" + new TcBasicTypeDecoder(pcrs).decodeUINT32());

		} catch (TcTssException e) {
			if (PRINT_TRACE) {
				Log.err(e);
			}
			assertTrue("getting TPM version failed.", false);
		}

	}


	public void NOtestVersion()
	{
		try {
			TcTssVersion ver = context_.getTpmObject().getCapabilityVersion(
					TcTssConstants.TSS_TPMCAP_VERSION, null);
			Log.debug(ver.toString());

		} catch (TcTssException e) {
			if (PRINT_TRACE) {
				Log.err(e);
			}
			assertTrue("getting TPM version failed.", false);
		}

	}


	public void NOtestReadPubKey()
	{
		try {
			srk_.getPubKey();
		} catch (TcTssException e) {
			if (PRINT_TRACE) {
				Log.err(e);
			}
			assertTrue("Reading public SRK failed.", false);
		}
	}


	public void NOtestVistaHandles()
	{
		try {
			TcIContext context = new TcTssContextFactory().newContextObject();
			context.connect();
			TcTcsAuth tcsAuth = TcTspInternal.TspOIAP_Internal((TcContext) context);
			Log.debug(tcsAuth.toString());
			tcsAuth = TcTspInternal.TspOIAP_Internal((TcContext) context);
			Log.debug(tcsAuth.toString());

			TcBlobData subCap = TcBlobData.newUINT32(TcTpmConstants.TPM_RT_AUTH);
			TcBlobData capResp = TcTspInternal.TspGetCapability_Internal((TcContext) context,
					TcTpmConstants.TPM_CAP_HANDLE, subCap);

			Log.debug(new TcTpmKeyHandleList(capResp).toString());

		} catch (TcTssException e) {
			if (PRINT_TRACE) {
				Log.err(e);
			}
			assertTrue("VISTA auth session handle test failed", false);
		}
	}
}
