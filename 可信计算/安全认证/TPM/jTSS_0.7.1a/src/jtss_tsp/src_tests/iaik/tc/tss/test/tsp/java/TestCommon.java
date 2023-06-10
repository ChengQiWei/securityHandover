/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.test.tsp.java;


import iaik.tc.tss.api.constants.tsp.TcTssConstants;
import iaik.tc.tss.api.exceptions.common.TcTssException;
import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.tss.api.structs.tsp.TcTssVersion;
import iaik.tc.tss.api.structs.tsp.TcUuidFactory;
import iaik.tc.tss.api.tspi.TcIContext;
import iaik.tc.tss.api.tspi.TcIRsaKey;
import iaik.tc.tss.api.tspi.TcTssContextFactory;
import junit.framework.TestCase;

public class TestCommon extends TestCase {

	protected boolean PRINT_TRACE = true;

	protected TcIContext sharedContext_ = null;

	protected boolean useSharedContext_ = false;

	protected TcIContext context_ = null;

	protected TcIRsaKey srk_ = null;

	/**
	 * IBM/TrouSerS TCS manufacturer constant. IBM/TrouSerS TCS制造商常数
	 */
	public final static TcBlobData TCS_MAN_IBM = TcBlobData.newString("IBM", true);

	/**
	 * IAIK TCS manufacturer constant.  IAIK TCS制造商常数
	 */
	public final static TcBlobData TCS_MAN_IAIK = TcBlobData.newString("IAIK");


	/**
	 * ETHZ TPM manufacturer (TPM Emulator) constant. ETHZ TPM制造商（TPM仿真器）常量
	 */
	public final static TcBlobData TPM_MAN_ETHZ = TcBlobData.newStringASCII("ETHZ");

	/**
	 * Atmel TPM manufacturer constant.
	 */
	public final static TcBlobData TPM_MAN_ATML = TcBlobData.newStringASCII("ATML");

	/**
	 * Infineon TPM manufacturer constant.
	 */
	public final static TcBlobData TPM_MAN_IFX = TcBlobData.newStringASCII("IFX\0");
	
	
	/**
	 * IBM Software TPM manufacturer constant.
	 */
	public final static TcBlobData TPM_MAN_IBM = TcBlobData.newStringASCII("IBM\0");
	protected void setUp() throws Exception
	{
		super.setUp();

//		if (useSharedContext_ && sharedContext_ != null) {
//			context_ = sharedContext_;
//		} else {
//			// IAIK/jTSS
//      try {
//        TcTssAbstractFactory factory = (TcTssAbstractFactory)Class.forName("iaik.tc.tss.impl.java.tsp.TcTssSOAPCallFactory").newInstance();
//        context_ = factory.newContextObject();
//        Log.info("SOAP Factory found. Using SOAP calls");
//      } catch (Exception e) {
//        Log.info("Using local calls");
        context_ = new TcTssContextFactory().newContextObject();
//      }

      
			// jTSS Wrapper (IBM/TrouSerS via JNI)
//			 context_ = new TcTssJniFactory().newContextObject();

			context_.connect();
//			sharedContext_ = context_;
		//}

		srk_ = context_.getKeyByUuid(TcTssConstants.TSS_PS_TYPE_SYSTEM,
				TcUuidFactory.getInstance().getUuidSRK());

		// alternative mechanism to get SRK instance
		// srk_ = context_.createRsaKeyObject(TcTssConstants.TSS_KEY_TSP_SRK);

		// set SRK policy   设置SRK策略
		TestDefines.srkPolicy = context_.createPolicyObject(TcTssConstants.TSS_POLICY_USAGE);
		TestDefines.srkPolicy.setSecret(TestDefines.SRK_SECRET_MODE, TestDefines.srkSecret);
		TestDefines.srkPolicy.assignToObject(srk_);

		// setup TPM policy 设置TPM策略
		TestDefines.tpmPolicy = context_.createPolicyObject(TcTssConstants.TSS_POLICY_USAGE);
		TestDefines.tpmPolicy.setSecret(TestDefines.OWNER_SECRET_MODE, TestDefines.ownerSecret);

		// setup key policy for testing  设置用于测试的密钥策略
		TestDefines.keyUsgPolicy = context_.createPolicyObject(TcTssConstants.TSS_POLICY_USAGE);
		TestDefines.keyUsgPolicy.setSecret(TestDefines.KEY_SECRET_MODE, TestDefines.KEY_USG_SECRET);
		TestDefines.keyMigPolicy = context_.createPolicyObject(TcTssConstants.TSS_POLICY_MIGRATION);
		TestDefines.keyMigPolicy.setSecret(TestDefines.KEY_SECRET_MODE, TestDefines.KEY_MIG_SECRET);
	}

	
	protected void tearDown() throws Exception
	{
		super.tearDown();

		if (useSharedContext_) {
			return;
		}

		context_.closeContext();
	}


	protected boolean isOrdinalSupported(long ord) throws TcTssException
	{
		return context_.getTpmObject().getCapabilityBoolean(TcTssConstants.TSS_TPMCAP_ORD,
				TcBlobData.newUINT32(ord));
	}


	protected boolean tcsManufactuerIs(TcBlobData man) throws TcTssException
	{
		TcBlobData subCap = TcBlobData.newUINT32(TcTssConstants.TSS_TCSCAP_PROP_MANUFACTURER_STR);
		TcBlobData tcsMan = context_.getCapability(TcTssConstants.TSS_TCSCAP_MANUFACTURER, subCap);

		return tcsMan.toHexString().equals(man.toHexString());
	}


	protected boolean tpmManufactuerIs(TcBlobData man) throws TcTssException
	{
		TcBlobData subCap = TcBlobData.newUINT32(TcTssConstants.TSS_TPMCAP_PROP_MANUFACTURER);
		TcBlobData tpmMan = context_.getTpmObject().getCapability(TcTssConstants.TSS_TPMCAP_PROPERTY, subCap);

		return tpmMan.toHexString().equals(man.toHexString());
	}

	
	protected TcTssVersion getRealTpmVersion() throws TcTssException
	{
		TcTssVersion tpmVersion = null;
		try {
			// first try 1.2 style
			tpmVersion = context_.getTpmObject().getCapabilityVersion(
					TcTssConstants.TSS_TPMCAP_VERSION_VAL, null);
		} catch (TcTssException e) {
			// alternatively try 1.1 style
			tpmVersion = context_.getTpmObject().getCapabilityVersion(TcTssConstants.TSS_TPMCAP_VERSION,
					null);
		}

		return tpmVersion;
	}
}
