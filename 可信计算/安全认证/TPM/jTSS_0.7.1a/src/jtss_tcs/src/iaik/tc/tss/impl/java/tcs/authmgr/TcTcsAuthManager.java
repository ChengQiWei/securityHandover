/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.impl.java.tcs.authmgr;

import iaik.tc.tss.api.constants.tpm.TcTpmErrors;
import iaik.tc.tss.api.exceptions.tcs.TcTcsException;
import iaik.tc.tss.api.exceptions.tcs.TcTddlException;
import iaik.tc.tss.api.exceptions.tcs.TcTpmException;
import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.tss.api.structs.tpm.TcTpmNonce;
import iaik.tc.tss.impl.java.tcs.kcmgr.TcTcsKeyCache;
import iaik.tc.tss.impl.java.tcs.pbg.TcTpmCmdAuthorization;
import iaik.tc.tss.impl.java.tddl.TcTddl;

public class TcTcsAuthManager {

	public static Object[] startOIAP(long hContext)
		throws TcTddlException, TcTpmException, TcTcsException
	{
		TcTddl dest = TcTddl.getInstance();
		Object[] retVal = null;
		do {
			try {
				retVal = TcTpmCmdAuthorization.TpmOIAP(dest);
			} catch (TcTpmException e) {
				if (e.getErrCode() == TcTpmErrors.TPM_E_SIZE || e.getErrCode() == TcTpmErrors.TPM_E_NOSPACE) {
					TcTcsAuthCache.getInstance().swapOutAuth(new long[] {});
					retVal = null;
				} else {
					throw e;
				}
			}
		} while (retVal == null);

		// add the new auth session to the list of active sessions
		long authH = ((Long)retVal[1]).longValue();
		TcTpmNonce nonceEven = (TcTpmNonce)retVal[2];
		TcTcsAuthCache.getInstance().addActiveAuthSession(authH, nonceEven);

		return retVal;
	}

	public static Object[] startOSAP(long hContext, int entityType, long entityValue,
			TcTpmNonce nonceOddOSAP) throws TcTddlException, TcTpmException, TcTcsException
	{
		TcTddl dest = TcTddl.getInstance();
		Object[] retVal = null;
		do {
			try {
				retVal = TcTpmCmdAuthorization.TpmOSAP(dest, entityType, entityValue, nonceOddOSAP);
			} catch (TcTpmException e) {
				if (e.getErrCode() == TcTpmErrors.TPM_E_SIZE || e.getErrCode() == TcTpmErrors.TPM_E_NOSPACE
						|| e.getErrCode() == TcTpmErrors.TPM_E_RESOURCES) {
					TcTcsAuthCache.getInstance().swapOutAuth(new long[] {});
					retVal = null;
				} else {
					throw e;
				}
			}
		} while (retVal == null);

		// add the new auth session to the list of active sessions
		long authH = ((Long)retVal[1]).longValue();
		TcTpmNonce nonceEven = (TcTpmNonce)retVal[2];
		TcTcsAuthCache.getInstance().addActiveAuthSession(authH, nonceEven);

		return retVal;
	}

	public static Object[] startDSAP(long hContext, int entityType, long tcsKeyHandle,
			TcTpmNonce nonceOddDSAP, TcBlobData entityValue)
		throws TcTddlException, TcTpmException, TcTcsException
	{
		long tpmKeyHandle = TcTcsKeyCache.getInstance().ensureKeyIsLoadedInTpm(tcsKeyHandle);

		TcTddl dest = TcTddl.getInstance();
		Object[] retVal = null;

		do {
			try {
				retVal = TcTpmCmdAuthorization.TpmDSAP(dest, entityType, tpmKeyHandle, nonceOddDSAP,
						entityValue);
			} catch (TcTpmException e) {
				if (e.getErrCode() == TcTpmErrors.TPM_E_SIZE || e.getErrCode() == TcTpmErrors.TPM_E_NOSPACE) {
					TcTcsAuthCache.getInstance().swapOutAuth(new long[] {});
					retVal = null;
				} else {
					throw e;
				}
			}
		} while (retVal == null);

		// add the new auth session to the list of active sessions
		long authH = ((Long)retVal[1]).longValue();
		TcTpmNonce nonceEven = (TcTpmNonce)retVal[2];
		TcTcsAuthCache.getInstance().addActiveAuthSession(authH, nonceEven);

		return retVal;
	}
}
