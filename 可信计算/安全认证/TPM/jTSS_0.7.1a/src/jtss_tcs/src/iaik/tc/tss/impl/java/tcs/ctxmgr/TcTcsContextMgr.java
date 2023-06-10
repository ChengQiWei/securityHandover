/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.impl.java.tcs.ctxmgr;


import iaik.tc.tss.api.constants.tcs.TcTcsErrors;
import iaik.tc.tss.api.exceptions.tcs.TcTcsException;
import iaik.tc.tss.api.exceptions.tcs.TcTddlException;
import iaik.tc.tss.api.exceptions.tcs.TcTpmException;
import iaik.tc.tss.api.structs.common.TcBasicTypeDecoder;
import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.tss.impl.csp.TcCrypto;

import java.util.HashMap;

public class TcTcsContextMgr {

	protected static HashMap openContexts_ = new HashMap();


	public static void checkContextHandle(long hContext) throws TcTcsException
	{
		synchronized (openContexts_) {
			if (!openContexts_.containsKey(new Long(hContext))) {
				throw new TcTcsException(TcTcsErrors.TCS_E_INVALID_CONTEXTHANDLE,
						"There is no open context with this handle (" + hContext + ")");
			}
		}
	}


	public static void checkKeyAssociatedWithContext(long hContext, long tcsKeyHandle) throws TcTcsException
	{
		synchronized (openContexts_) {
			TcTcsContext context = getContextForHandle(hContext);
			context.checkKeyIsAssociated(tcsKeyHandle);
		}
	}

	
	
	public static Object[] TcsiOpenContext()
	{
		TcTcsContext context = new TcTcsContext();

		long hContext = 0;
		synchronized (openContexts_) {
			do {
				TcBlobData raw = TcCrypto.getRandom(4);
				hContext = new TcBasicTypeDecoder(raw).decodeUINT32();
			} while (openContexts_.containsKey(new Long(hContext)));

			openContexts_.put(new Long(hContext), context);
		}

		return new Object[] { new Long(TcTcsErrors.TCS_SUCCESS), new Long(hContext) };
	}


	public static long TcsiCloseContext(long hContext) throws TcTpmException, TcTcsException, TcTddlException
	{
		checkContextHandle(hContext);
		
		TcTcsContext context = null;
		synchronized (openContexts_) {
//			Log.debug("CLOSING context with handle: " + hContext);
			context = (TcTcsContext)openContexts_.get(new Long(hContext));
			openContexts_.remove(new Long(hContext));

//			Log.debug("num open contexts: " + openContexts_.size());
		}

		context.close();
		
		return TcTcsErrors.TCS_SUCCESS;
	}

	
	public static TcTcsContext getContextForHandle(long hContext) throws TcTcsException
	{
		synchronized (openContexts_) {
			checkContextHandle(hContext);
			TcTcsContext context = (TcTcsContext)openContexts_.get(new Long(hContext));
			return context;
		}
	}
	
	
	public static long TcsiFreeMemory(long hContext, long pMemory) throws TcTcsException
	{
		// do nothing - rely on the GC
		
		return TcTcsErrors.TCS_SUCCESS;
	}
	
	
	public static TcBlobData TcsiGetCapability(long hContext, long capArea, TcBlobData subCap) throws TcTcsException
	{
		TcTcsContext context = getContextForHandle(hContext);
		return context.getCapability(capArea, subCap);
	}
	
}
