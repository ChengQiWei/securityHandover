/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.impl.java.tcs.ctxmgr;


import iaik.tc.tss.api.constants.tcs.TcTcsConstants;
import iaik.tc.tss.api.constants.tcs.TcTcsErrors;
import iaik.tc.tss.api.constants.tpm.TcTpmConstants;
import iaik.tc.tss.api.exceptions.tcs.TcTcsException;
import iaik.tc.tss.api.exceptions.tcs.TcTddlException;
import iaik.tc.tss.api.exceptions.tcs.TcTpmException;
import iaik.tc.tss.api.structs.common.TcBasicTypeDecoder;
import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.tss.api.structs.tpm.TcTpmVersion;
import iaik.tc.tss.impl.java.tcs.kcmgr.TcTcsKeyManager;
import iaik.tc.utils.misc.Utils;

import java.util.Vector;

/**
 * 
 * 
 */
public class TcTcsContext {

	/**
	 * This field holds all TCS key handles associated with this context.
	 */
	protected Vector associatedTcsKeyHandles_ = new Vector();

	/**
	 * This field indicates the version of the TCS. Shouldn't be set manually,
	 * as it will be set when built with ant.
	 */
	private final String tcsVersion_ = "0.7.1a";

	public TcTcsContext()
	{
	}


	/**
	 * 
	 */
	public void close() throws TcTpmException, TcTcsException, TcTddlException
	{
		Vector keyHandles = null;
		synchronized (associatedTcsKeyHandles_) {
			keyHandles = (Vector) associatedTcsKeyHandles_.clone();
		}
		for (int i = 0; i < keyHandles.size(); i++) {
			Long tcsKeyHandle = (Long) keyHandles.elementAt(i);
			TcTcsKeyManager.EvictKey(TcTcsConstants.NULL_HOBJECT, tcsKeyHandle.longValue());
		}
	}


	public void addTcsKeyHandle(Long tcsKeyHandle) throws TcTcsException
	{
		synchronized (associatedTcsKeyHandles_) {
			if (associatedTcsKeyHandles_.contains(tcsKeyHandle)) {
				throw new TcTcsException(TcTcsErrors.TCS_E_INVALID_KEYHANDLE,
						"Given key handle already is associated with this context.");
			} else {
				associatedTcsKeyHandles_.add(tcsKeyHandle);
			}
		}
	}


	public void removeTcsKeyHandle(Long tcsKeyHandle) throws TcTcsException
	{
		synchronized (associatedTcsKeyHandles_) {
			if (!associatedTcsKeyHandles_.contains(tcsKeyHandle)) {
				throw new TcTcsException(TcTcsErrors.TCS_E_INVALID_KEYHANDLE,
						"Given key handle does not belong to this context.");
			} else {
				associatedTcsKeyHandles_.remove(tcsKeyHandle);
			}
		}
	}


	public void checkKeyIsAssociated(long tcsKeyHandle) throws TcTcsException
	{
		if (tcsKeyHandle == TcTpmConstants.TPM_KH_SRK || tcsKeyHandle == TcTpmConstants.TPM_KH_EK
				|| tcsKeyHandle == TcTpmConstants.TPM_KH_TRANSPORT) {
			return;
		}

		synchronized (associatedTcsKeyHandles_) {
			if (!associatedTcsKeyHandles_.contains(new Long(tcsKeyHandle))) {
				throw new TcTcsException(TcTcsErrors.TCS_E_INVALID_CONTEXTHANDLE,
						"Given key handle does not belong to this context.");
			}
		}
	}


	public TcBlobData getCapability(long capArea, TcBlobData subCap) throws TcTcsException
	{
		TcBlobData retVal = null;

		long subCapNum = 0;
		if (subCap != null) {
			subCapNum = new TcBasicTypeDecoder(subCap).decodeUINT32();
		}

		switch ((int) capArea) {
//			 case (int)TcTcsConstants.TSS_TCSCAP_ALG:
//			 break;

			 case (int) TcTcsConstants.TSS_TCSCAP_VERSION:
				TcTpmVersion ver = new TcTpmVersion();
				ver.setMajor((short) 1);
				ver.setMinor((short) 2);

				int revIndex = tcsVersion_.indexOf(".");
				ver.setRevMajor(Short.parseShort(tcsVersion_.substring(0, revIndex)));
				//only take the first digit after the "." of the TCS Version
				ver.setRevMinor(Short.parseShort(tcsVersion_.substring(revIndex+1, revIndex+2)));
				retVal = ver.getEncoded();
				break;

			case (int) TcTcsConstants.TSS_TCSCAP_MANUFACTURER:
				if (subCapNum == TcTcsConstants.TSS_TCSCAP_PROP_MANUFACTURER_STR) {
					retVal = TcBlobData.newString("IAIK");
				} else if (subCapNum == TcTcsConstants.TSS_TCSCAP_PROP_MANUFACTURER_ID) {
					retVal = TcBlobData.newUINT32(0); // TODO: who defines this ID?
				} else {
					throw new TcTcsException(TcTcsErrors.TCS_E_BAD_PARAMETER, "Unknown subCap");
				}
				break;

			case (int) TcTcsConstants.TSS_TCSCAP_CACHING:
				if (subCap.equals(TcBlobData.newUINT32(TcTcsConstants.TSS_TCSCAP_PROP_AUTHCACHE))) {
					retVal = TcBlobData.newBOOL(true);
				} else if (subCap.equals(TcBlobData.newUINT32(TcTcsConstants.TSS_TCSCAP_PROP_KEYCACHE))) {
					retVal = TcBlobData.newBOOL(true);
				} else {
					throw new TcTcsException(TcTcsErrors.TCS_E_BAD_PARAMETER, "Unknown subCap");
				}
				break;

			case (int) TcTcsConstants.TSS_TCSCAP_PERSSTORAGE:
				retVal = TcBlobData.newBOOL(true);
				break;

//			case (int) TcTcsConstants.TSS_TCSCAP_PLATFORM_CLASS:
//				break;

//			case (int) TcTcsConstants.TSS_TCSCAP_TRANSPORT:
//				break;

			default:
				throw new TcTcsException(TcTcsErrors.TCS_E_BAD_PARAMETER,
						"Unknown/unsupported capability. (" + Utils.longToHex(capArea) + ")");
		}

		return retVal;
	}

}
