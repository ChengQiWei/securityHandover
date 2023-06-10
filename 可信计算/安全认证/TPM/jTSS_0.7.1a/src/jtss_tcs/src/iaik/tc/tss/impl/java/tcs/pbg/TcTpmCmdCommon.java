/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.impl.java.tcs.pbg;


import iaik.tc.tss.api.constants.tpm.TcTpmErrors;
import iaik.tc.tss.api.exceptions.tcs.TcTcsException;
import iaik.tc.tss.api.exceptions.tcs.TcTddlException;
import iaik.tc.tss.api.exceptions.tcs.TcTpmException;
import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.tss.api.structs.tcs.TcTcsAuth;
import iaik.tc.tss.api.structs.tpm.TcTpmGenericReturnBlob;
import iaik.tc.tss.impl.java.tcs.authmgr.TcTcsAuthCache;

public class TcTpmCmdCommon {

	/*************************************************************************************************
	 * Convenience method converting an UINT32 into a TcBlobData.
	 */
	protected static TcBlobData blobUINT32(long data)
	{
		return TcBlobData.newUINT32(data);
	}


	/*************************************************************************************************
	 * Convenience method converting an UINT16 into a TcBlobData.
	 */
	protected static TcBlobData blobUINT16(int data)
	{
		return TcBlobData.newUINT16(data);
	}


	/*************************************************************************************************
	 * Convenience method converting a byte into a TcBlobData.
	 */
	protected static TcBlobData blobBYTE(short data)
	{
		return TcBlobData.newBYTE(data);
	}


	/*************************************************************************************************
	 * Convenience method converting a byte[] into a TcBlobData.
	 */
	protected static TcBlobData blobByteArray(byte[] data)
	{
		return TcBlobData.newByteArray(data);
	}


	/*************************************************************************************************
	 * Convenience method converting a byte into a TcBlobData.
	 */
	protected static TcBlobData blobBOOL(boolean data)
	{
		return TcBlobData.newBOOL(data);
	}


	/*************************************************************************************************
	 * This method checks return code in the provided header. If the return code is not TCPA_SUCCESS
	 * (TPM_SUCCESS) an exception is thrown.
	 */
	protected static void handleRetCode(TcTpmGenericReturnBlob header)
		throws TcTddlException, TcTpmException
	{
		if (header.getRetCode() != TcTpmErrors.TPM_SUCCESS) {
			throw new TcTpmException(header.getRetCode());
		}
	}


	/*************************************************************************************************
	 * This method sets the length field (paramSize) of a byte array to be sent to the TPM. The
	 * paramSize always is the second parameter after the TPM_TAG. Therefore, a fixed offset can be
	 * used when setting paramSize.
	 * 
	 * @param data The data blob where the paramSize should be set.
	 */
	protected static void setParamSize(TcBlobData data)
	{
		data.substBytes(2, blobUINT32(data.getLength()).asByteArray());
	}


	/*************************************************************************************************
	 * This method is called if an authorized TPM command fails. It represents a handling point to
	 * notify the session manager that the auth session has been terminated.
	 * 
	 * @param authSession
	 */
	protected static void invalidataAuthSession(TcTcsAuth authSession)
		throws TcTddlException, TcTpmException
	{
		try {
			TcTcsAuthCache.getInstance().removeActiveAuthSession(authSession);
		} catch (TcTcsException e) {
			throw new RuntimeException(e.getMessage());
		}
	}


	/*************************************************************************************************
	 * This method is called if an auth is used to authorize more than one TPM command. In such a
	 * case, the TPM generates a new nonceEven and consequently the unique identifier we use for auth
	 * sessions changes as well. Therefore, this method updates the identifier of the auth session in
	 * the list of active auth sessions. If the session is not continued it will be invalidated.
	 * 
	 * @param inAuthSession
	 * @param outAuthSession
	 * @throws TcTddlException
	 * @throws TcTpmException
	 */
	protected static void trackAuthSession(TcTcsAuth inAuthSession, TcTcsAuth outAuthSession)
		throws TcTddlException, TcTpmException
	{
		try {
			if (!outAuthSession.getContAuthSession()) {
				invalidataAuthSession(inAuthSession);
			} else {
				TcTcsAuthCache.getInstance().trackActiveAuthSession(inAuthSession, outAuthSession);
			}
		} catch (TcTcsException e) {
			throw new RuntimeException(e.getMessage());
		}
	}
}
