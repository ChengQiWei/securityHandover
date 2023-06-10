/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Christian Pointner, Ronald Toegl
 */

package iaik.tc.tss.test.tcs.java;

import iaik.tc.tss.api.constants.tcs.TcTcsErrors;
import iaik.tc.tss.api.constants.tpm.TcTpmConstants;
import iaik.tc.tss.api.constants.tpm.TcTpmErrors;
import iaik.tc.tss.api.constants.tsp.TcTssConstants;
import iaik.tc.tss.api.constants.tsp.TcTssErrors;
import iaik.tc.tss.api.exceptions.tcs.TcTcsException;
import iaik.tc.tss.api.exceptions.tcs.TcTddlException;
import iaik.tc.tss.api.exceptions.tcs.TcTpmException;
import iaik.tc.tss.api.structs.common.TcBasicTypeDecoder;
import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.tss.api.structs.tcs.TcTcsAuth;
import iaik.tc.tss.api.structs.tpm.TcTpmAuthdata;
import iaik.tc.tss.api.structs.tpm.TcTpmCapVersionInfo;
import iaik.tc.tss.api.structs.tpm.TcTpmEncauth;
import iaik.tc.tss.api.structs.tpm.TcTpmNonce;
import iaik.tc.tss.api.structs.tpm.TcTpmSecret;
import iaik.tc.tss.api.structs.tpm.TcTpmVersion;
import iaik.tc.tss.api.structs.tsp.TcTssVersion;
import iaik.tc.tss.impl.csp.TcCrypto;
import iaik.tc.tss.impl.java.tsp.tcsbinding.TcITcsBinding;
import iaik.tc.tss.impl.java.tsp.tcsbinding.local.TcTcsBindingLocal;
import junit.framework.TestCase;

public class TestCommon extends TestCase {

	protected boolean PRINT_TRACE = true;
	
	protected TcITcsBinding tcs_ = null;
	
	protected Long hContext_ = null;
	
	/**
	 * ETHZ TPM manufacturer (TPM Emulator) constant.
	 */
	public final static TcBlobData TPM_MAN_ETHZ = TcBlobData.newStringASCII("ETHZ");

	/**
	 * Atmel TPM manufacturer constant.
	 */
	public final static TcBlobData TPM_MAN_ATML = TcBlobData.newStringASCII("ATML");


	protected void setUp() throws Exception
	{
		super.setUp();

		tcs_ = new TcTcsBindingLocal();
		
		Object[] ret = tcs_.TcsiOpenContext();
		if(!new Long(TcTcsErrors.TCS_SUCCESS).equals((Long)ret[0]))
			assertTrue("Unable to open context", false);
			
		hContext_ = (Long) ret[1];
	}

	protected void tearDown() throws Exception
	{
		if(hContext_ != null)
			tcs_.TcsiCloseContext(hContext_);
	}

	
	protected boolean isOrdinalSupported(long ord) throws TcTddlException, TcTpmException, TcTcsException
	{
		Object[] result = tcs_.TcsipGetCapability(hContext_, TcTpmConstants.TPM_CAP_ORD, TcBlobData.newUINT32(ord));
		return (new TcBasicTypeDecoder((TcBlobData)result[1]).decodeBoolean());
	}
	

	protected boolean tpmManufactuerIs(TcBlobData man) throws TcTddlException, TcTpmException, TcTcsException
	{
		TcBlobData subCap = TcBlobData.newUINT32(TcTpmConstants.TPM_CAP_PROP_MANUFACTURER);
		Object[] result = tcs_.TcsipGetCapability(hContext_, TcTpmConstants.TPM_CAP_PROPERTY, subCap);
		return ((TcBlobData)result[1]).toHexString().equals(man.toHexString());
	}
	
	protected TcTssVersion getTPMVersion() throws TcTddlException, TcTpmException, TcTcsException
	{
		TcTpmVersion tpmVersion = null;
		
		try { //TPM 1.2 apparently?
			
			Object[] result = tcs_.TcsipGetCapability(hContext_, TcTpmConstants.TPM_CAP_VERSION_VAL, null);
			TcBlobData retVal =(TcBlobData) result[1];						
			tpmVersion = (new TcTpmCapVersionInfo(retVal)).getVersion();
			
		} catch (TcTpmException e) { //TPM 1.1 apparently?
			Object[] result = tcs_.TcsipGetCapability(hContext_, TcTpmConstants.TPM_CAP_VERSION, null);
			TcBlobData retVal =(TcBlobData) result[1];
			tpmVersion = new TcTpmVersion(retVal);
		}
		
		TcTssVersion tssVersion = new TcTssVersion();
		tssVersion.setMajor(tpmVersion.getMajor());
		tssVersion.setMinor(tpmVersion.getMinor());
		tssVersion.setRevMajor(tpmVersion.getRevMajor());
		tssVersion.setRevMinor(tpmVersion.getRevMinor());
		
		return tssVersion; 
		
	}
	
	protected TcTcsAuth TspOIAP() throws TcTddlException, TcTpmException, TcTcsException
	{
		Object[] outDataTpm = tcs_.TcsipOIAP(hContext_);

		// get return values
		Long authHandle = (Long) outDataTpm[1];
		TcTpmNonce nonceEven = (TcTpmNonce) outDataTpm[2];

		TcTcsAuth auth = new TcTcsAuth();
		auth.setAuthHandle(authHandle.longValue());
		auth.setNonceEven(nonceEven);

		return auth;	
	}

	protected TcBlobData computeAuthData(final TcBlobData[] blob1H, final TcBlobData blob2H,
			final TcBlobData blob3H, final TcBlobData blob4H, final TcBlobData authHash)
	{
		TcBlobData combinedBlob1H = TcBlobData.newBlobData(blob1H[0]);
		for (int i = 1; i < blob1H.length; i++) {
			combinedBlob1H.append(blob1H[i]);
		}

		TcBlobData authData = combinedBlob1H.sha1();
		authData.append(blob2H);
		authData.append(blob3H);
		authData.append(blob4H);
		TcBlobData retVal = authData.hmacSha1(authHash);
		return retVal;
	}

	protected void validateRespAuth(final TcBlobData[] blob1H, final TcTcsAuth inAuthValues,
			final TcTcsAuth outAuthValues, TcTpmSecret secret) throws TcTpmException
	{		
		// compute expected auth data in result blob
		TcBlobData resAuthDataExpected = computeAuthData(blob1H, // 1Hx
				outAuthValues.getNonceEven().getEncoded(), // 2Hx
				inAuthValues.getNonceOdd().getEncoded(), // 3Hx
				TcBlobData.newBOOL(outAuthValues.getContAuthSession()), // 4Hx
				secret.getEncoded()); // HMAC key

		// check if the expected auth data matches the one received from the TPM
		boolean isequal = outAuthValues.getHmac().getDigest().equals(resAuthDataExpected); 
		if (!isequal) {
			throw new TcTpmException(TcTpmErrors.TPM_E_AUTHFAIL);
		}
	}
	
	protected Object[] TspOSAP(int entityType, long entityValue, TcTpmNonce nonceOddOSAP)
		throws TcTddlException, TcTpmException, TcTcsException
	{
		Object[] outDataTpm = tcs_.TcsipOSAP(hContext_, entityType, entityValue,
				nonceOddOSAP);

		// get return values
		Long authHandle = (Long) outDataTpm[1];
		TcTpmNonce nonceEven = (TcTpmNonce) outDataTpm[2];
		TcTpmNonce nonceEvenOSAP = (TcTpmNonce) outDataTpm[3];

		TcTcsAuth auth = new TcTcsAuth();
		auth.setAuthHandle(authHandle.longValue());
		auth.setNonceEven(nonceEven);

		return new Object[] { auth, nonceEvenOSAP };
	}
	
	protected synchronized Object[] createOsapSession(int entityType, long entityValue,
			TcBlobData parentSecret, TcBlobData entitySecret) throws TcTddlException, TcTpmException, TcTcsException
	{
		entityType |= TcTpmConstants.TPM_ET_XOR;
		
		// start new OSAP session
		TcTpmNonce nonceOddOSAP = TcCrypto.createTcgNonce();
		Object[] tpmOutData = TspOSAP(entityType, entityValue, nonceOddOSAP);
		TcTcsAuth osapAuth = (TcTcsAuth) tpmOutData[0];
		TcTpmNonce nonceEvenOSAP = (TcTpmNonce) tpmOutData[1];

		// compute the ADIP shared secret
		TcBlobData sharedSecret = (TcBlobData) nonceEvenOSAP.getNonce().clone();
		sharedSecret.append(nonceOddOSAP.getNonce());
		// HMAC key is usage secret of data parent key
		sharedSecret = sharedSecret.hmacSha1(parentSecret);

		// generate new nonce odd
		TcTpmNonce nonceOdd = TcCrypto.createTcgNonce();
		osapAuth.setNonceOdd(nonceOdd);

		// XOR key for encrypting secret
		TcBlobData xorKeyData = (TcBlobData) sharedSecret.clone();
		xorKeyData.append(osapAuth.getNonceEven().getNonce());
		xorKeyData = xorKeyData.sha1();

		// XOR encrypt the entity secret
		TcTpmEncauth encIdentityAuth = new TcTpmEncauth(entitySecret.xor(xorKeyData));

		return new Object[] { osapAuth, encIdentityAuth, new TcTpmSecret(sharedSecret) };
	}
}
