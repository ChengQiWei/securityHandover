/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.test.tsp.java.pcrs;

import iaik.tc.tss.api.constants.tpm.TcTpmConstants;
import iaik.tc.tss.api.constants.tpm.TcTpmOrdinals;
import iaik.tc.tss.api.constants.tsp.TcTssConstants;
import iaik.tc.tss.api.exceptions.common.TcTssException;
import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.tss.api.tspi.TcIPcrComposite;
import iaik.tc.tss.api.tspi.TcITpm;
import iaik.tc.tss.test.tsp.java.TestCommon;
import iaik.tc.utils.logging.Log;

import java.util.Arrays;

public class TestPcrs extends TestCommon {


//	public void testPcrSelection()
//	{
//		try {
////			TcIPcrComposite pcrCompInfo = context_.createPcrCompositeObject(TcTssConstants.TSS_PCRS_STRUCT_INFO_LONG);
//		TcIPcrComposite pcrCompInfo = context_.createPcrCompositeObject(0);
//			
////			pcrCompInfo.selectPcrIndexEx(10, TcTssConstants.TSS_PCRS_DIRECTION_RELEASE);
////			pcrCompInfo.selectPcrIndexEx(0, TcTssConstants.TSS_PCRS_DIRECTION_RELEASE);
////			pcrCompInfo.selectPcrIndexEx(14, TcTssConstants.TSS_PCRS_DIRECTION_RELEASE);
//
//		pcrCompInfo.selectPcrIndex(10);
//		pcrCompInfo.selectPcrIndex(0);
//		pcrCompInfo.selectPcrIndex(14);
//
//			
//			Log.debug(pcrCompInfo.toString());
//			
//			pcrCompInfo.setPcrValue(1, TcBlobData.newString("foobar").sha1());
//
//			Log.debug(pcrCompInfo.toString());
//			
//		} catch (TcTssException e) {
//			if (PRINT_TRACE) {
//				Log.err(e);
//			}
//			assertTrue("setting PcrSelection failed", false);
//		}
//	}
	
	
	/**
	 * <ul>
	 * 	<li> reads PCR contents
	 *  <li> extends PCR
	 *  <li> re-reads PCR and checks for correct value
	 *  <li> does not add event log entries 
	 * </ul>
	 */
	public void testPcrExtendAndReadWithoutEvent()
	{
		try {
			TcITpm tpm = context_.getTpmObject();
			
			tpm.pcrRead(10);
			tpm.pcrExtend(10, TcBlobData.newString("foobar").sha1(), null);
			tpm.pcrRead(10);
			
			
		} catch (TcTssException e) {
			if (PRINT_TRACE) {
				Log.err(e);
			}
			assertTrue("testPcrExtendAndReadWithoutEvent failed", false);
		}
	}

	
	/**
	 * <ul>
	 * 	<li> reads PCR contents
	 *  <li> extends PCR
	 *  <li> re-reads PCR and checks for correct value
	 *  <li> does not add event log entries 
	 * </ul>
	 */
	public void testPcrReset()
	{
		try {
			if (!isOrdinalSupported(TcTpmOrdinals.TPM_ORD_PCR_Reset) || tpmManufactuerIs(TPM_MAN_ETHZ)) {
				Log.info("PCR Reset is not supported by this TPM");
				return;
			}
			if (tcsManufactuerIs(TCS_MAN_IBM)) {
				Log.info("The IBM/TrouSerS TSS does not support PcrReset");
				return;
			}
			
			byte[] byteData = new byte[(int)TcTpmConstants.TPM_SHA1_160_HASH_LEN];
			Arrays.fill(byteData, (byte)0);
			TcBlobData emptyPcr = TcBlobData.newByteArray(byteData);
			

			//  extend PCR
			TcITpm tpm = context_.getTpmObject();
			tpm.pcrExtend(16, TcBlobData.newString("The sun is shining...").sha1(), null);

			//  check PCR content
			TcBlobData pcrContent = tpm.pcrRead(16);
			if (pcrContent.equals(emptyPcr)) {
				assertTrue("PCR content after extend is still zero.", false);
			}
			
			// reset PCR
			// use 1.2 structs that support PCRs >= 16
			TcIPcrComposite pcrComp = context_.createPcrCompositeObject(TcTssConstants.TSS_PCRS_STRUCT_INFO_SHORT);
			pcrComp.selectPcrIndexEx(16, TcTssConstants.TSS_PCRS_DIRECTION_RELEASE);
			tpm.pcrReset(pcrComp);

			//  check PCR content
			pcrContent = tpm.pcrRead(16);
			if (!pcrContent.equals(emptyPcr)) {
				assertTrue("PCR reset failed.", false);
			}
			
		} catch (TcTssException e) {
			if (PRINT_TRACE) {
				Log.err(e);
			}
			assertTrue("testPcrExtendAndReadWithoutEvent failed", false);
		}
	}
	
	
}
