/*
 * Copyright (C) 2009 IAIK, Graz University of Technology
 */
package iaik.tc.tss.impl.java.tsp;

import iaik.tc.tss.api.constants.tcs.TcTcsErrors;
import iaik.tc.tss.api.constants.tpm.TcTpmConstants;
import iaik.tc.tss.api.constants.tpm.TcTpmErrors;
import iaik.tc.tss.api.constants.tpm.TcTpmOrdinals;
import iaik.tc.tss.api.constants.tsp.TcTssConstants;
import iaik.tc.tss.api.constants.tsp.TcTssErrors;
import iaik.tc.tss.api.exceptions.common.TcTssException;
import iaik.tc.tss.api.exceptions.tcs.TcTcsException;
import iaik.tc.tss.api.exceptions.tsp.TcTspException;
import iaik.tc.tss.api.structs.common.TcBasicTypeDecoder;
import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.tss.api.structs.tcs.TcTcsAuth;
import iaik.tc.tss.api.structs.tpm.TcTpmEncauth;
import iaik.tc.tss.api.structs.tpm.TcTpmNvDataPublic;
import iaik.tc.tss.api.structs.tpm.TcTpmPermanentFlags;
import iaik.tc.tss.api.structs.tpm.TcTpmSecret;
import iaik.tc.tss.api.tspi.TcIAuthObject;
import iaik.tc.tss.api.tspi.TcIContext;
import iaik.tc.tss.api.tspi.TcINvRam;
import iaik.tc.tss.api.tspi.TcIPolicy;
import iaik.tc.tss.impl.java.tsp.internal.TcTspInternal;

/**
 * @author tpm
 *
 */
public class TcNvRam extends TcAuthObject implements TcINvRam {

	long nvIndex_;

	/*
	 * (non-Javadoc)
	 *
	 * @see iaik.tc.tss.impl.java.tsp.TcAttributes#initAttribGetters()
	 */
	protected TcNvRam(TcIContext context, long nvIndex) throws TcTssException {
		super(context);
		nvIndex_ = nvIndex;

	}

	protected void initAttribGetters() {
		// TODO Auto-generated method stub

	}

	/*
	 * (non-Javadoc)
	 *
	 * @see iaik.tc.tss.impl.java.tsp.TcAttributes#initAttribSetters()
	 */

	protected void initAttribSetters() {
		// TODO Auto-generated method stub

	}

	/*
	 * (non-Javadoc)
	 *
	 * @seeiaik.tc.tss.api.tspi.TcINvRam#defineSpace(iaik.tc.tss.api.tspi.
	 * TcIPcrComposite, iaik.tc.tss.api.tspi.TcIPcrComposite)
	 */

	public void defineSpace(TcTpmNvDataPublic pubData) throws TcTssException {

		if (pubData.getNvIndex() != nvIndex_) {
			throw new TcTspException(TcTssErrors.TSS_E_INTERNAL_ERROR,
					"nvIndex of TcTpmNvDataPublic and TcNvRam don't match");
		}

		checkContextOpenAndConnected();

		// special case TPM_NV_INDEX_LOCK - unauthorized command
		if (nvIndex_ == TcTpmConstants.TPM_NV_INDEX_LOCK) {
			if (pubData.getDataSize() != 0) {
				throw new TcTcsException(TcTcsErrors.TCS_E_BAD_PARAMETER,
						"data size must be 0 for index TPM_NV_INDEX_LOCK");
			}

			TcTpmEncauth encAuth = new TcTpmEncauth(TcBlobData.newByteArray(new byte[20]));

			TcTspInternal.TspNvDefineSpace_Internal(context_, pubData, encAuth, null, null);

			return;
		}

		// check whether NV Ram is locked
		TcTpmPermanentFlags pflags = new TcTpmPermanentFlags(context_.getTpmObject()
				.getCapability(TcTssConstants.TSS_TPMCAP_FLAG, null), 0);

		boolean nvLocked = pflags.getNvLocked();

		// get NV_DATA_PUBLIC
		TcBlobData subCap = TcBlobData.newUINT32(nvIndex_);
		TcBlobData tpmOutData = null;

		// check whether index is already defined
		try {
			tpmOutData = context_.getTpmObject().getCapability(
					TcTssConstants.TSS_TPMCAP_NV_INDEX, subCap);

			if (tpmOutData != null) {
				throw new TcTcsException(TcTcsErrors.TCS_E_BAD_INDEX, "index already defined");
			}
		} catch (TcTssException e) {
			if (e.getErrCode() != TcTpmErrors.TPM_E_BADINDEX) {
				if (e.getErrCode() != TcTpmErrors.TPM_E_BAD_PARAMETER)
				{ // Response from an Infineon if index not defined
				  throw e;
				}
			}
		}

		// check dataSize
		if (pubData.getDataSize() == 0) {
			throw new TcTcsException(TcTcsErrors.TCS_E_BAD_PARAMETER,
					"data size must not be 0");
		}

		// check D-Bit
		if (nvLocked) {
			if ((nvIndex_ & TcTssConstants.TSS_NV_DEFINED) != 0) {
				throw new TcTcsException(TcTcsErrors.TCS_E_BAD_INDEX,
						"Flag TPM_PF_NV_LOCKED is set. Can't define index with set defined-bit");
			}
		}

		// check TPM_NV_INDEX0
		if (nvIndex_ == TcTpmConstants.TPM_NV_INDEX0) {
			throw new TcTcsException(TcTcsErrors.TCS_E_BAD_INDEX,
					"index TPM_NV_INDEX0 can not be set");
		}

		// check permissions
		long permissions = pubData.getPermission().getAttributes();

		if (((permissions & TcTpmConstants.TPM_NV_PER_OWNERREAD) != 0)
				&& ((permissions & TcTpmConstants.TPM_NV_PER_AUTHREAD) != 0)) {
			throw new TcTcsException(TcTcsErrors.TCS_E_BAD_PARAMETER,
					"conflicting read permissions");
		}

		if (((permissions & TcTpmConstants.TPM_NV_PER_OWNERWRITE) != 0)
				&& ((permissions & TcTpmConstants.TPM_NV_PER_AUTHWRITE) != 0)) {
			throw new TcTcsException(TcTcsErrors.TCS_E_BAD_PARAMETER,
					"conflicting write permissions");
		}

		// figure out whether locality selection protects write actions
		// if true, permission value can be 0x0
		// represents check at lines 4093 - 4107 in TCG TPM Commands
		// Specification (Revision 116)
		boolean writeLocalities = false;
		if (pubData.getPcrInfoWrite().getLocalityAtRelease() != 0x1f) {
			writeLocalities = true;
		}

		if (((permissions & TcTpmConstants.TPM_NV_PER_AUTHWRITE) == 0)
				&& ((permissions & TcTpmConstants.TPM_NV_PER_OWNERWRITE) == 0)
				&& ((permissions & TcTpmConstants.TPM_NV_PER_WRITEDEFINE) == 0)
				&& ((permissions & TcTpmConstants.TPM_NV_PER_PPWRITE) == 0)
				&& !writeLocalities) {
			throw new TcTcsException(TcTcsErrors.TCS_E_BAD_PARAMETER,
					"no write permissions set");
		}

		TcTpmSecret  ownerAuth = null;
		TcTcsAuth    inAuth1   = null;
		TcTpmEncauth encAuth   = null;

		if (((TcPolicy) this.getUsagePolicyObject()) == null) {
			// the policy which holds the usage secret for this special index is not
			// assigned to "this"
			throw new TcTspException(TcTssErrors.TSS_E_TSP_AUTHREQUIRED,
					"Usage policy for entity not set");
		}

		if (((TcPolicy) context_.getTpmObject().getUsagePolicyObject()) == null) {
			// the policy holding the owner secret is not assigned to the tpm object
			throw new TcTspException(TcTssErrors.TSS_E_TSP_AUTHREQUIRED,
					"policy with owner secret not set");
		}

		// start OSAP session
		Object[] osapData = createOsapSession(TcTpmConstants.TPM_ET_OWNER,
				TcTpmOrdinals.TPM_ORD_NV_DefineSpace,
				context_.getTpmObject().getUsagePolicyObject(),
				this.getUsagePolicyObject());

		inAuth1 = (TcTcsAuth) osapData[0];
		encAuth = (TcTpmEncauth) osapData[1];
		ownerAuth = (TcTpmSecret) osapData[2];

		TcTspInternal.TspNvDefineSpace_Internal(context_, pubData, encAuth, inAuth1, ownerAuth);

		// outgoing auth is already checked
	}

	/*
	 * (non-Javadoc)
	 *
	 * @see iaik.tc.tss.api.tspi.TcINvRam#readValue(long, long)
	 */

	public TcBlobData readValue(long offset, long dataLength)
			throws TcTssException {

		if (dataLength == 0xFFFFFFFF) // Special Flag for SmartRead
			return this.readValueSmart(offset, dataLength);

		checkContextOpenAndConnected();

		TcTpmSecret ownerAuth = null;
		TcTcsAuth inAuth1=null;


		if (((TcPolicy) getUsagePolicyObject())!=null)
		{
			ownerAuth = ((TcPolicy) getUsagePolicyObject()).getTpmSecret();
			inAuth1 = TcTspInternal.TspOIAP_Internal(context_);
					}


		Object[] result = TcTspInternal.TspNvReadValue_Internal(context_,
				nvIndex_, offset, dataLength, inAuth1, ownerAuth);


		TcBlobData returnValue = (TcBlobData) result[1];


		return returnValue;
	}

	/*
	 * (non-Javadoc)
	 *
	 * @see iaik.tc.tss.api.tspi.TcINvRam#releaseSpace()
	 */

	public void releaseSpace() throws TcTssException {

		checkContextOpenAndConnected();

		// get NV_DATA_PUBLIC
		TcBlobData subCap = TcBlobData.newUINT32(nvIndex_);
		TcBlobData tpmOutData = context_.getTpmObject().getCapability(
				TcTssConstants.TSS_TPMCAP_NV_INDEX, subCap);

		// check whether index is already defined
		if (tpmOutData == null) {
			throw new TcTcsException(TcTcsErrors.TCS_E_BAD_INDEX, "index isn't defined");
		}

		// check D-Bit
		if ((nvIndex_ & TcTssConstants.TSS_NV_DEFINED) != 0) {
			throw new TcTcsException(TcTcsErrors.TCS_E_BAD_INDEX,
					"index with set defined-bit is not allowed");
		}

		// check TPM_NV_INDEX0
		if (nvIndex_ == TcTpmConstants.TPM_NV_INDEX0) {
			throw new TcTcsException(TcTcsErrors.TCS_E_BAD_INDEX,
					"index TPM_NV_INDEX0 can not be set");
		}

		TcTpmNvDataPublic pubData = new TcTpmNvDataPublic(tpmOutData);

		// we want to release space -> set size to 0
		pubData.setDataSize(0);

		TcTpmSecret  ownerAuth = null;
		TcTcsAuth    inAuth1   = null;
		TcTpmEncauth encAuth   = null;

		if (((TcPolicy) this.getUsagePolicyObject()) == null) {
			// the policy which holds the usage secret for this special index is not
			// assigned to "this"
			throw new TcTspException(TcTssErrors.TSS_E_TSP_AUTHREQUIRED,
					"Usage policy for entity not set");
		}

		if (((TcPolicy) context_.getTpmObject().getUsagePolicyObject()) == null) {
			// the policy holding the owner secret is not assigned to the tpm object
			throw new TcTspException(TcTssErrors.TSS_E_TSP_AUTHREQUIRED,
					"policy with owner secret not set");
		}

		// start OSAP session
		Object[] osapData = createOsapSession(TcTpmConstants.TPM_ET_OWNER, TcTpmOrdinals.TPM_ORD_NV_DefineSpace,
				context_.getTpmObject().getUsagePolicyObject(), this.getUsagePolicyObject());

		inAuth1 = (TcTcsAuth) osapData[0];
		encAuth = (TcTpmEncauth) osapData[1];
		ownerAuth = (TcTpmSecret) osapData[2];

		TcTspInternal.TspNvDefineSpace_Internal(context_, pubData, encAuth, inAuth1, ownerAuth);

	}

	/*
	 * (non-Javadoc)
	 *
	 * @see iaik.tc.tss.api.tspi.TcINvRam#writeValue(long,
	 * iaik.tc.tss.api.structs.common.TcBlobData)
	 */

	public void writeValue(long offset, TcBlobData dataToWrite) throws TcTssException {

		// 1) get NV_DATA_PUBLIC
		TcBlobData subCap = TcBlobData.newUINT32(nvIndex_);
		TcBlobData tpmOutData = context_.getTpmObject().getCapability(
				TcTssConstants.TSS_TPMCAP_NV_INDEX, subCap);

		if (tpmOutData == null) {
			throw new TcTcsException(TcTcsErrors.TCS_E_BAD_INDEX,
					"Unable to get NV storage information");
		}
		TcTpmNvDataPublic nvDataPub = new TcTpmNvDataPublic(tpmOutData);

		// 2) check authentication mode

		long permissions = nvDataPub.getPermission().getAttributes();

		if ((permissions & TcTpmConstants.TPM_NV_PER_PPWRITE) != 0) {
			// physical presence not yet implemented (if it would be, we still need
			// auth too - unauth methods are not supported by jTSS
			throw new TcTspException(TcTssErrors.TSS_E_NOTIMPL, "Not implemented");
		} else if ((permissions & TcTpmConstants.TPM_NV_PER_OWNERWRITE) != 0) {
			// use 'normal' method

			TcTpmSecret ownerAuth = null;
			TcTcsAuth   inAuth1   = null;

			if (((TcPolicy) getUsagePolicyObject()) != null) {
				ownerAuth = ((TcPolicy) getUsagePolicyObject()).getTpmSecret();
				inAuth1 = TcTspInternal.TspOIAP_Internal(context_);

				TcTspInternal.TspNvWriteValue_Internal(context_, nvIndex_, offset,
						dataToWrite, inAuth1, ownerAuth);

			} else {
				throw new TcTspException(TcTssErrors.TSS_E_TSP_AUTHREQUIRED);
			}

		} else if ((permissions & TcTpmConstants.TPM_NV_PER_AUTHWRITE) != 0) {
			// use auth method

			TcTpmSecret ownerAuth = null;
			TcTcsAuth   inAuth1   = null;

			if (((TcPolicy) getUsagePolicyObject()) != null) {
				ownerAuth = ((TcPolicy) getUsagePolicyObject()).getTpmSecret();
				inAuth1 = TcTspInternal.TspOIAP_Internal(context_);

				TcTspInternal.TspNvWriteValueAuth_Internal(context_, nvIndex_, offset,
						dataToWrite, inAuth1, ownerAuth);

			} else {
				throw new TcTspException(TcTssErrors.TSS_E_TSP_AUTHREQUIRED);
			}

		} else if ((permissions & TcTpmConstants.TPM_NV_PER_WRITEDEFINE) != 0) {
			// not yet implemented
			throw new TcTspException(TcTssErrors.TSS_E_NOTIMPL, "Not implemented");
		} else if (nvDataPub.getPcrInfoWrite().getLocalityAtRelease() != 0x1f) {
			// write protection by excluded locality:
			// noauth command - not supported
			throw new TcTspException(TcTssErrors.TSS_E_NOTIMPL, "Not implemented");
		} else {
			throw new TcTspException(TcTssErrors.TSS_E_FAIL,
					"illegal permissions - should not happen");
		}

	}

	/*
	 * (non-Javadoc)
	 *
	 * @seeiaik.tc.tss.api.tspi.TcIAuthObject#changeAuth(iaik.tc.tss.api.tspi.
	 * TcIAuthObject, iaik.tc.tss.api.tspi.TcIPolicy)
	 */

	public void changeAuth(TcIAuthObject parentObject, TcIPolicy newPolicy)
			throws TcTssException {

		throw new TcTspException(TcTssErrors.TSS_E_NOTIMPL, "Not implemented");

	}


	protected TcBlobData readValueSmart(long offset, long dataLength)
			throws TcTssException {

		// determine the size of the data to be read from NV at
		// provided index
		TcBlobData subCap = TcBlobData.newUINT32(nvIndex_);
		TcBlobData tpmOutData = context_.getTpmObject().getCapability(
				TcTssConstants.TSS_TPMCAP_NV_INDEX, subCap);

		if (tpmOutData == null) {
			throw new TcTcsException(TcTcsErrors.TCS_E_BAD_INDEX,
					"Unable to get NV storage information for EK certificate.");
		}
		TcTpmNvDataPublic nvDataPub = new TcTpmNvDataPublic(tpmOutData);

		long dataSize = nvDataPub.getDataSize();

		// determine the size of the input/output buffer of the TPM
		// subCap =
		// TcBlobData.newUINT32(TcTpmConstants.TPM_CAP_PROP_INPUT_BUFFER);
		subCap = TcBlobData
				.newUINT32(TcTssConstants.TSS_TPMCAP_PROP_INPUTBUFFERSIZE);


		tpmOutData = context_.getTpmObject().getCapability(
				TcTssConstants.TSS_TPMCAP_PROPERTY, subCap);
		long tpmBufferSize = new TcBasicTypeDecoder(tpmOutData)
				.decodeUINT32();

		// reduce the TPM buffer size (struct overhead, ...)
		long bufferSize = tpmBufferSize - 256;

		TcBlobData dataToRead = null;

		while (dataSize > 0) {
			long bytesToRead = (dataSize > bufferSize) ? bufferSize : dataSize;
			TcBlobData nvResults = readValue(offset, bytesToRead);
			offset += bufferSize;
			dataSize -= bufferSize;
			if (dataToRead == null) {
				dataToRead = nvResults;
			} else {
				dataToRead.append(nvResults);
			}
		}

		return dataToRead;
	}



}
