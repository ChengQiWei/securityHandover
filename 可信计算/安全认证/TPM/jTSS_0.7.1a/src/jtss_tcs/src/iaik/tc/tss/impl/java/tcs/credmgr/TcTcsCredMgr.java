/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.impl.java.tcs.credmgr;

import iaik.tc.tss.api.constants.pcclient.TcPcclientConstants;
import iaik.tc.tss.api.constants.tcs.TcTcsErrors;
import iaik.tc.tss.api.constants.tpm.TcTpmConstants;
import iaik.tc.tss.api.constants.tpm.TcTpmErrors;
import iaik.tc.tss.api.constants.tpm.TcTpmOrdinals;
import iaik.tc.tss.api.exceptions.tcs.TcTcsException;
import iaik.tc.tss.api.exceptions.tcs.TcTddlException;
import iaik.tc.tss.api.exceptions.tcs.TcTpmException;
import iaik.tc.tss.api.structs.common.TcBasicTypeDecoder;
import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.tss.api.structs.pcclient.TcTcgFullCert;
import iaik.tc.tss.api.structs.pcclient.TcTcgPcclientStoredCert;
import iaik.tc.tss.api.structs.tcs.TcTcsAuth;
import iaik.tc.tss.api.structs.tpm.TcITpmKey;
import iaik.tc.tss.api.structs.tpm.TcITpmKeyNew;
import iaik.tc.tss.api.structs.tpm.TcTpmCapVersionInfo;
import iaik.tc.tss.api.structs.tpm.TcTpmDigest;
import iaik.tc.tss.api.structs.tpm.TcTpmEncauth;
import iaik.tc.tss.api.structs.tpm.TcTpmNvDataPublic;
import iaik.tc.tss.api.structs.tpm.TcTpmVersion;
import iaik.tc.tss.api.structs.tsp.TcTssVersion;
import iaik.tc.tss.impl.csp.TcCrypto;
import iaik.tc.tss.impl.java.tcs.authmgr.TcTcsAuthManager;
import iaik.tc.tss.impl.java.tcs.ctxmgr.TcTcsContextMgr;
import iaik.tc.tss.impl.java.tcs.pbg.TcTpmCmdCapability;
import iaik.tc.tss.impl.java.tcs.pbg.TcTpmCmdIdentity;
import iaik.tc.tss.impl.java.tcs.pbg.TcTpmCmdNvStorage;
import iaik.tc.tss.impl.java.tcs.pbg.TcTpmCmdVendorSpecific;
import iaik.tc.tss.impl.java.tddl.TcIStreamDest;
import iaik.tc.tss.impl.java.tddl.TcTddl;
import iaik.tc.utils.logging.Log;

public class TcTcsCredMgr {

	/*************************************************************************************************
	 */
	public static Object[] TcsipMakeIdentity(long hContext,
			TcTpmEncauth identityAuth, TcTpmDigest labelPrivCADigest,
			TcITpmKeyNew idKeyParams, TcTcsAuth inAuth1, TcTcsAuth inAuth2)
			throws TcTddlException, TcTpmException, TcTcsException {
		Object[] identityVals = TcsipMakeIdentity2(hContext, identityAuth,
				labelPrivCADigest, idKeyParams, inAuth1, inAuth2);

		Long retCode = (Long) identityVals[0];
		TcTcsAuth outAuth1 = (TcTcsAuth) identityVals[1];
		TcTcsAuth outAuth2 = (TcTcsAuth) identityVals[2];
		TcITpmKey idKey = (TcITpmKey) identityVals[3];
		TcBlobData identityBinding = (TcBlobData) identityVals[4];

		Object[] credentials = TcsiGetCredentials(hContext);
		TcBlobData endorsementCredential = (TcBlobData) credentials[0];
		TcBlobData platformCredential = (TcBlobData) credentials[1];
		TcBlobData conformanceCredential = (TcBlobData) credentials[2];

		Object[] retVal = new Object[] { retCode, outAuth1, outAuth2, idKey,
				identityBinding, endorsementCredential, platformCredential,
				conformanceCredential };

		// legal return codes: TCS_SUCCESS, TCS_E_FAIL

		return retVal;
	}

	/*************************************************************************************************
	 */
	public static Object[] TcsipMakeIdentity2(long hContext,
			TcTpmEncauth identityAuth, TcTpmDigest labelPrivCADigest,
			TcITpmKeyNew idKeyParams, TcTcsAuth inAuth1, TcTcsAuth inAuth2)
			throws TcTddlException, TcTpmException, TcTcsException {
		TcTddl dest = TcTddl.getInstance();
		Object[] retVal = TcTpmCmdIdentity.TpmMakeIdentity(dest, identityAuth,
				labelPrivCADigest, idKeyParams, inAuth1, inAuth2);

		// legal return codes: TCS_SUCCESS, TCS_E_FAIL

		return retVal;
	}

	/*************************************************************************************************
	 */
	public static Object[] TcsiGetCredentials(long hContext)
			throws TcTddlException, TcTpmException, TcTcsException {
		TcTcsContextMgr.checkContextHandle(hContext);

		TcBlobData endorsementCredential = null;
		TcBlobData platfromCredential = null;
		TcBlobData conformanceCredential = null;

		TcTddl dest = TcTddl.getInstance();

		// check for IFX TPM
		Object[] tpmOutData = TcTpmCmdCapability.TpmGetCapability(dest,
				TcTpmConstants.TPM_CAP_PROPERTY, TcBlobData
						.newUINT32(TcTpmConstants.TPM_CAP_PROP_MANUFACTURER));
		TcBlobData manufacturer = (TcBlobData) tpmOutData[1];
		if (manufacturer.toStringASCII().equals("IFX\0")) {
			tpmOutData = TcTpmCmdCapability.TpmGetCapability(dest,
					TcTpmConstants.TPM_CAP_ORD, TcBlobData
							.newUINT32(TcTpmOrdinals.TPM_ORD_IFX_ReadCert11));
			boolean ifxEkCert11 = new TcBasicTypeDecoder(
					(TcBlobData) tpmOutData[1]).decodeBoolean();

			boolean tpmVers11 = getTPMVersion(hContext).equals(
					TcTssVersion.TPM_V1_1);

			if (ifxEkCert11 && tpmVers11) {

				// FIXME: also true on IFX12.1 TPM

				// found an IFX 1.1 TPM
				endorsementCredential = readEkCertIfx11();

			} else {
				// assume that we have an IFX 1.2 (or later) TPM
				try {
					endorsementCredential = readEkCertNv(hContext);
				} catch (TcTpmException e) {
					if (e.getErrCode() == TcTpmErrors.TPM_E_AUTH_CONFLICT) {
					/*
					 * this TPM requires owner authorization to read EK Cert from NV Ram.
					 *
					 * since TcsiGetCredentials is an unauthorized command we can't
					 * obtain EK Cert at this point.
					 */
						Log.warn("automatic EK Certificate extraction requires ownership permission on this TPM");
					} else {
						throw e;
					}
				}
			}
		}

		Object[] retVal = new Object[] { endorsementCredential,
				platfromCredential, conformanceCredential };
		return retVal;
	}

	/*************************************************************************************************
	 */
	protected static TcBlobData readEkCertIfx11() throws TcTddlException,
			TcTpmException, TcTcsException {
		TcTddl dest = TcTddl.getInstance();

		// read part 0
		TcBlobData antiReplay = TcCrypto.createTcgNonce().getNonce();
		Object[] tpmOutData = TcTpmCmdVendorSpecific.IfxReadTpm11EkCert(dest,
				(byte) 0, antiReplay);

		short maxIndex = ((Short) tpmOutData[0]).shortValue();
		TcTpmDigest checksum = (TcTpmDigest) tpmOutData[1];
		TcBlobData ekCertPart = (TcBlobData) tpmOutData[2];
		TcBlobData expectedChecksum = (TcBlobData) ekCertPart.clone();
		expectedChecksum.append(antiReplay);
		if (!checksum.getEncoded().equals(expectedChecksum.sha1())) {
			throw new TcTcsException(TcTcsErrors.TCS_E_INTERNAL_ERROR,
					"Checksum comparison for data received from the TPM failed.");
		}

		TcBlobData ekCert = ekCertPart;

		// read parts 1 ... n
		for (byte i = 1; i <= maxIndex; i++) {
			antiReplay = TcCrypto.createTcgNonce().getNonce();
			tpmOutData = TcTpmCmdVendorSpecific.IfxReadTpm11EkCert(dest, i,
					antiReplay);
			checksum = (TcTpmDigest) tpmOutData[1];
			ekCertPart = (TcBlobData) tpmOutData[2];
			expectedChecksum = (TcBlobData) ekCertPart.clone();
			expectedChecksum.append(antiReplay);
			if (!checksum.getEncoded().equals(expectedChecksum.sha1())) {
				throw new TcTcsException(TcTcsErrors.TCS_E_INTERNAL_ERROR,
						"Checksum comparison for data received from the TPM failed.");
			}
			ekCert.append(ekCertPart);
		}

		return ekCert;
	}

	/*************************************************************************************************
	 */
	protected static TcBlobData readEkCertNv(long hContext)
			throws TcTddlException, TcTpmException, TcTcsException {
		TcIStreamDest dest = TcTddl.getInstance();

		TcTcgFullCert fullCert = null;

		// determine the size of the data to be read from NV at
		// TPM_NV_INDEX_EKCert
		TcBlobData subCap = TcBlobData
				.newUINT32(TcTpmConstants.TPM_NV_INDEX_EKCert);
		Object[] tpmOutData = TcTpmCmdCapability.TpmGetCapability(dest,
				TcTpmConstants.TPM_CAP_NV_INDEX, subCap);

		if (tpmOutData[1] == null) {
			throw new TcTcsException(TcTcsErrors.TCS_E_BAD_INDEX,
					"Unable to get NV storage information for EK certificate.");
		}

		TcTpmNvDataPublic nvDataPub = new TcTpmNvDataPublic(
				(TcBlobData) tpmOutData[1]);
		long dataSize = nvDataPub.getDataSize();

		// determine the size of the input/output buffer of the TPM
		subCap = TcBlobData.newUINT32(TcTpmConstants.TPM_CAP_PROP_INPUT_BUFFER);
		tpmOutData = TcTpmCmdCapability.TpmGetCapability(dest,
				TcTpmConstants.TPM_CAP_PROPERTY, subCap);
		long tpmBufferSize = new TcBasicTypeDecoder((TcBlobData) tpmOutData[1])
				.decodeUINT32();

		// reduce the TPM buffer size (struct overhead, ...)
		long bufferSize = tpmBufferSize - 256;

		// start new TPM auth session
		tpmOutData = TcTcsAuthManager.startOIAP(hContext);

		TcBlobData ekCertRaw = null;
		long offset = 0;
		while (dataSize > 0) {
			long bytesToRead = (dataSize > bufferSize) ? bufferSize : dataSize;
			Object[] nvResults = TcTpmCmdNvStorage.TpmNvReadValue(dest,
					TcTpmConstants.TPM_NV_INDEX_EKCert, offset, bytesToRead,
					null);
			offset += bufferSize;
			dataSize -= bufferSize;
			if (ekCertRaw == null) {
				ekCertRaw = (TcBlobData) nvResults[2];
			} else {
				ekCertRaw.append((TcBlobData) nvResults[2]);
			}
		}

		// decode raw certificate blob and write certificate to file

		TcTcgPcclientStoredCert cert = new TcTcgPcclientStoredCert(ekCertRaw);
		if (cert.getTag() != TcPcclientConstants.TCG_TAG_PCCLIENT_STORED_CERT) {
			throw new TcTcsException(TcTcsErrors.TCS_E_INTERNAL_ERROR,
					"Unexpected certificate struct tag (expected: TCG_TAG_PCCLIENT_STORED_CERT).");
		}

		if (cert.getCertType() != TcPcclientConstants.TCG_FULL_CERT) {
			throw new TcTcsException(TcTcsErrors.TCS_E_INTERNAL_ERROR,
					"Unsupported certificate type. Only TCG_FULL_CERT is supported.");
		}

		fullCert = new TcTcgFullCert(cert.getCert());
		if (fullCert.getTag() != TcPcclientConstants.TCG_TAG_PCCLIENT_FULL_CERT) {
			throw new TcTcsException(TcTcsErrors.TCS_E_INTERNAL_ERROR,
					"Unexpected certificate struct tag (expected: TCG_TAG_PCCLIENT_FULL_CERT).");
		}

		return fullCert.getCert();
	}

	protected static TcTssVersion getTPMVersion(long hContext)
			throws TcTddlException, TcTpmException, TcTcsException {
		TcTpmVersion tpmVersion = null;

		TcTddl dest = TcTddl.getInstance();

		Object[] tpmOutData = null;

		tpmOutData = TcTpmCmdCapability.TpmGetCapability(dest,
				TcTpmConstants.TPM_CAP_VERSION_VAL, null);

		long retVal = (Long) tpmOutData[0];

		if (retVal == TcTcsErrors.TCS_SUCCESS) // TPM 1.2
			tpmVersion = (new TcTpmCapVersionInfo(((TcBlobData) tpmOutData[1])))
					.getVersion();
		else { // TPM 1.1
			tpmOutData = TcTpmCmdCapability.TpmGetCapability(dest,
					TcTpmConstants.TPM_CAP_VERSION, null);

			retVal = (Long) tpmOutData[0];
			if (retVal != TcTcsErrors.TCS_SUCCESS)
				throw new TcTpmException(retVal);

			tpmVersion = (new TcTpmVersion(((TcBlobData) tpmOutData[1])));
		}

		TcTssVersion tssVersion = new TcTssVersion();
		tssVersion.setMajor(tpmVersion.getMajor());
		tssVersion.setMinor(tpmVersion.getMinor());
		tssVersion.setRevMajor(tpmVersion.getRevMajor());
		tssVersion.setRevMinor(tpmVersion.getRevMinor());

		return tssVersion;

	}

}
