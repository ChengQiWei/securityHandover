/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Christian Pointner
 */

package iaik.tc.tss.test.tcs.java.counter;

import iaik.tc.tss.api.constants.tpm.TcTpmConstants;
import iaik.tc.tss.api.constants.tpm.TcTpmOrdinals;
import iaik.tc.tss.api.exceptions.common.TcTssException;
import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.tss.api.structs.tcs.TcTcsAuth;
import iaik.tc.tss.api.structs.tpm.TcTpmAuthdata;
import iaik.tc.tss.api.structs.tpm.TcTpmCounterValue;
import iaik.tc.tss.api.structs.tpm.TcTpmEncauth;
import iaik.tc.tss.api.structs.tpm.TcTpmSecret;
import iaik.tc.tss.impl.csp.TcCrypto;
import iaik.tc.tss.test.tcs.java.TestCommon;
import iaik.tc.tss.test.tcs.java.TestDefines;
import iaik.tc.utils.logging.Log;

public class TestCounter extends TestCommon {
	
	public void NOtestCreateCounter()
	{
		try {
			if (!isOrdinalSupported(TcTpmOrdinals.TPM_ORD_CreateCounter)) {
				Log.info("TPM_ORD_CreateCounter is not supported by this TPM");
				return;
			}
			if (tpmManufactuerIs(TPM_MAN_ETHZ)) {
				Log.info("skipping this test on TPM emulator");
				return;
			}

			TcBlobData label = TcBlobData.newStringASCII("test");
		
			Object[] osapData = createOsapSession(TcTpmConstants.TPM_ET_OWNER, 0, TestDefines.OWNER_SECRET.sha1(), 
					TestDefines.COUNTER_SECRET.sha1());
			TcTcsAuth inAuth = (TcTcsAuth) osapData[0];
			TcTpmEncauth encAuth = (TcTpmEncauth) osapData[1];
			TcTpmSecret osapSecret = (TcTpmSecret) osapData[2];
			
			inAuth.setNonceOdd(TcCrypto.createTcgNonce());
			TcBlobData[] blob1H = { // 1H
					TcBlobData.newUINT32(TcTpmOrdinals.TPM_ORD_CreateCounter), // 1S
					encAuth.getEncoded(), // 2S
					label// 3S
				};
			
			TcBlobData authDataH1 = computeAuthData( //
					blob1H, // 1H1
					inAuth.getNonceEven().getEncoded(), // 2H1
					inAuth.getNonceOdd().getEncoded(), // 3H1
					TcBlobData.newBOOL(inAuth.getContAuthSession()),// 4H1
					osapSecret.getEncoded()); // HMAC key

			inAuth.setHmac(new TcTpmAuthdata(authDataH1));			
			
			Object[] retVal = tcs_.TcsipCreateCounter(hContext_, label, encAuth, inAuth);

			long resultCode = ((Long) retVal[0]).longValue();
			TcTcsAuth outAuth = (TcTcsAuth)retVal[1];
			long counterId = ((Long)retVal[2]).longValue(); 
			TcTpmCounterValue value = (TcTpmCounterValue)retVal[3];

			TcBlobData[] blob1Hout = {
					TcBlobData.newUINT32(resultCode), // 1S 
					TcBlobData.newUINT32(TcTpmOrdinals.TPM_ORD_CreateCounter), // 2S
					TcBlobData.newUINT32(counterId), // 3S
					value.getEncoded()  // 4S
				};
			
			validateRespAuth(blob1Hout, inAuth, outAuth, osapSecret);
			
		} catch (Exception e) {
			if (PRINT_TRACE) {
				Log.err(e);
			}
			assertTrue("creating monotonic counter failed", false);
		}
	}

	public void NOtestIncrementCounter()
	{
		try {
			if (!isOrdinalSupported(TcTpmOrdinals.TPM_ORD_IncrementCounter)) {
				Log.info("TPM_ORD_IncrementCounter is not supported by this TPM");
				return;
			}
			if (tpmManufactuerIs(TPM_MAN_ETHZ)) {
				Log.info("skipping this test on TPM emulator");
				return;
			}
				
			long counterId = 0;
			
			TcTcsAuth inAuth = TspOIAP();
			inAuth.setNonceOdd(TcCrypto.createTcgNonce());
			TcBlobData[] blob1H = { 
					TcBlobData.newUINT32(TcTpmOrdinals.TPM_ORD_IncrementCounter),
					TcBlobData.newUINT32(counterId)
				};
			TcTpmSecret secret = new TcTpmSecret(TestDefines.COUNTER_SECRET.sha1());
			TcBlobData authDataH1 = computeAuthData( //
					blob1H, // 1H1
					inAuth.getNonceEven().getEncoded(), // 2H1
					inAuth.getNonceOdd().getEncoded(), // 3H1
					TcBlobData.newBOOL(inAuth.getContAuthSession()), // 4H1
					secret.getEncoded());
			inAuth.setHmac(new TcTpmAuthdata(authDataH1));
		
			Object[] retVal = tcs_.TcsipIncrementCounter(hContext_, counterId, inAuth);

			long resultCode = ((Long) retVal[0]).longValue();
			TcTcsAuth outAuth = (TcTcsAuth)retVal[1];
			TcTpmCounterValue value = (TcTpmCounterValue)retVal[2];
			
			TcBlobData[] blob1Hout = { // 1H
					TcBlobData.newUINT32(resultCode), // 1S
					TcBlobData.newUINT32(TcTpmOrdinals.TPM_ORD_IncrementCounter), // 2S 
					value.getEncoded() // 3S
				};
			
			validateRespAuth(blob1Hout, inAuth, outAuth, secret);
			
		} catch (TcTssException e) {
			if (PRINT_TRACE) {
				Log.err(e);
			}
			assertTrue("incrementing monotonic counter failed", false);
		}	
	}

	public void NOtestReadCounter()
	{
		try {
			if (!isOrdinalSupported(TcTpmOrdinals.TPM_ORD_ReadCounter)) {
				Log.info("TPM_ORD_ReadCounter is not supported by this TPM");
				return;
			}
			if (tpmManufactuerIs(TPM_MAN_ETHZ)) {
				Log.info("skipping this test on TPM emulator");
				return;
			}

			long counterId = 0;
			
			Object[] retVal = tcs_.TcsipReadCounter(hContext_, counterId);
			
			long resultCode = ((Long) retVal[0]).longValue();
			TcTpmCounterValue value = (TcTpmCounterValue)retVal[1];
			
		} catch (TcTssException e) {
			if (PRINT_TRACE) {
				Log.err(e);
			}
			assertTrue("reading monotonic counter failed", false);
		}	
	}

	public void NOtestReleaseCounter()
	{
		try {
			if (!isOrdinalSupported(TcTpmOrdinals.TPM_ORD_ReleaseCounter)) {
				Log.info("TPM_ORD_ReleaseCounter is not supported by this TPM");
				return;
			}
			if (tpmManufactuerIs(TPM_MAN_ETHZ)) {
				Log.info("skipping this test on TPM emulator");
				return;
			}

			long counterId = 0;
			
			TcTcsAuth inAuth = TspOIAP();
			inAuth.setNonceOdd(TcCrypto.createTcgNonce());
			TcBlobData[] blob1H = { 
					TcBlobData.newUINT32(TcTpmOrdinals.TPM_ORD_ReleaseCounter),
					TcBlobData.newUINT32(counterId)
				};
			TcTpmSecret secret = new TcTpmSecret(TestDefines.COUNTER_SECRET.sha1());
			TcBlobData authDataH1 = computeAuthData( //
					blob1H, // 1H1
					inAuth.getNonceEven().getEncoded(), // 2H1
					inAuth.getNonceOdd().getEncoded(), // 3H1
					TcBlobData.newBOOL(inAuth.getContAuthSession()), // 4H1
					secret.getEncoded());
			inAuth.setHmac(new TcTpmAuthdata(authDataH1));
		
			Object[] retVal = tcs_.TcsipReleaseCounter(hContext_, counterId, inAuth);

			long resultCode = ((Long) retVal[0]).longValue();
			TcTcsAuth outAuth = (TcTcsAuth)retVal[1];
			
			TcBlobData[] blob1Hout = { // 1H
					TcBlobData.newUINT32(resultCode), // 1S
					TcBlobData.newUINT32(TcTpmOrdinals.TPM_ORD_ReleaseCounter) // 2S 
				};
			
			validateRespAuth(blob1Hout, inAuth, outAuth, secret);

		} catch (TcTssException e) {
			if (PRINT_TRACE) {
				Log.err(e);
			}
			assertTrue("releasing monotonic counter failed", false);
		}	
	}

	public void NOtestReleaseCounterOwner()
	{
		try {
			if (!isOrdinalSupported(TcTpmOrdinals.TPM_ORD_ReleaseCounterOwner)) {
				Log.info("TPM_ORD_ReleaseCounterOwner is not supported by this TPM");
				return;
			}
			if (tpmManufactuerIs(TPM_MAN_ETHZ)) {
				Log.info("skipping this test on TPM emulator");
				return;
			}

			long counterId = 0;
			
			TcTcsAuth inAuth = TspOIAP();
			inAuth.setNonceOdd(TcCrypto.createTcgNonce());
			TcBlobData[] blob1H = { 
					TcBlobData.newUINT32(TcTpmOrdinals.TPM_ORD_ReleaseCounterOwner),
					TcBlobData.newUINT32(counterId)
				};
			TcTpmSecret secret = new TcTpmSecret(TestDefines.OWNER_SECRET.sha1());
			TcBlobData authDataH1 = computeAuthData( //
					blob1H, // 1H1
					inAuth.getNonceEven().getEncoded(), // 2H1
					inAuth.getNonceOdd().getEncoded(), // 3H1
					TcBlobData.newBOOL(inAuth.getContAuthSession()), // 4H1
					secret.getEncoded());
			inAuth.setHmac(new TcTpmAuthdata(authDataH1));
		
			Object[] retVal = tcs_.TcsipReleaseCounterOwner(hContext_, counterId, inAuth);

			long resultCode = ((Long) retVal[0]).longValue();
			TcTcsAuth outAuth = (TcTcsAuth)retVal[1];
			
			TcBlobData[] blob1Hout = { // 1H
					TcBlobData.newUINT32(resultCode), // 1S
					TcBlobData.newUINT32(TcTpmOrdinals.TPM_ORD_ReleaseCounterOwner) // 2S 
				};
			
			validateRespAuth(blob1Hout, inAuth, outAuth, secret);

		} catch (TcTssException e) {
			if (PRINT_TRACE) {
				Log.err(e);
			}
			assertTrue("owner authorized release of monotonic counter failed", false);
		}	
	}
}
