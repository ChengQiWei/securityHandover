/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.impl.java.tsp;


import iaik.tc.tss.api.constants.tpm.TcTpmConstants;
import iaik.tc.tss.api.constants.tsp.TcTssConstants;
import iaik.tc.tss.api.constants.tsp.TcTssErrors;
import iaik.tc.tss.api.exceptions.common.TcTssException;
import iaik.tc.tss.api.exceptions.tsp.TcTspException;
import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.tss.api.structs.tpm.TcTpmCompositeHash;
import iaik.tc.tss.api.structs.tpm.TcTpmPcrInfo;
import iaik.tc.tss.api.structs.tpm.TcTpmPcrSelection;
import iaik.tc.tss.api.structs.tsp.TcTssVersion;
import iaik.tc.tss.api.tspi.TcIContext;
import iaik.tc.utils.misc.CheckPrecondition;

public class TcPcrCompositeInfo extends TcPcrCompositeBase {

	/**
	 * This field holds the PCR_INFO instance used by this class.
	 */
	protected TcTpmPcrInfo pcrInfo_ = new TcTpmPcrInfo();


	/*************************************************************************************************
	 * Constructor.
	 */
	public TcPcrCompositeInfo(TcIContext context) throws TcTssException
	{
		super(context);

		// setup the PCR selection (all bits set to 0 - i.e. no PCRs selected)
		pcrInfo_.setPcrSelection(getDefaultSelection());

		// setup digestAtRelease and digestAtCreation
		// TPM spec: if PCR_SELECTION.pcrSelect is all 0s, COMPOSITE_HASH must be set to be all 0s
		pcrInfo_.setDigestAtCreation(getDefaultCompHash());
		pcrInfo_.setDigestAtRelease(getDefaultCompHash());
	}

	
	/**
	 * Offline creation of struct
	 * @param numPCRs
	 * @throws TcTssException
	 */
	public TcPcrCompositeInfo(int numPCRs) throws TcTssException
	{
		super(numPCRs);

		// setup the PCR selection (all bits set to 0 - i.e. no PCRs selected)
		pcrInfo_.setPcrSelection(getDefaultSelection());

		// setup digestAtRelease and digestAtCreation
		// TPM spec: if PCR_SELECTION.pcrSelect is all 0s, COMPOSITE_HASH must be set to be all 0s
		pcrInfo_.setDigestAtCreation(getDefaultCompHash());
		pcrInfo_.setDigestAtRelease(getDefaultCompHash());
	}


	

	/*************************************************************************************************
	 * Internal method returning the PCR struct version used by this class.
	 */
	protected long getPcrStructVer()
	{
		return TcTssConstants.TSS_PCRS_STRUCT_INFO;
	}


	protected int getNumPcrs() throws TcTssException
	{
		int retVal = 16;

		int realPcrCnt = super.getNumPcrs();

		// Not all 1.2 TPMs allow the usage of sizeOfSelect > 2 (i.e. pcrCount > 16) in TPM_PCR_INFO.
		// Check if the underlying TPM supports this.
		if (realPcrCnt > 16 && context_!=null) {
			try {

				// Note:
				// Intel TPMs return for isSelectSizeSupported
				// (1.1,2) true and (1.1,3) true
				// However, running Quote command with TSS_PCRS_STRUCT_INFO and PCRselection:
				// only PCR  1 set: 00 02 02 00    -> ok
				// only PCR  1 set: 00 03 02 00 00 -> fails with 0x10 PCR information could not be interpreted 
				// only PCR 17 set: 00 03 00 00 02 -> ok
				// Thus, as a workaround we artifically limit Intel TPMs for
				// TSS_PCRS_STRUCT_INFO to 16 PCRs until a better solution is found

				TcBlobData tpmManu = context_.getTpmObject().getCapability(TcTssConstants.TSS_TPMCAP_PROPERTY,
						             TcBlobData.newUINT32(TcTssConstants.TSS_TPMCAP_PROP_MANUFACTURER));

				if (((TcTpm) context_.getTpmObject()).isSelectSizeSupported(TcTssVersion.TPM_V1_1, realPcrCnt / 8)
					&& !tpmManu.toStringASCII().equals("INTC")) {  // see note above
					retVal = realPcrCnt;
				}
			} catch (TcTssException e) {
				// reading the sizeOfSelect property failed (maybe running on TPM emulator...)
				// leave retVal unchanged
			}
		}

		return retVal;
	}


	/*
	 * (non-Javadoc)
	 *
	 * @see iaik.tss.api.tspi.TcIPcrComposite#getPcrCompositeHash()
	 */
	public TcBlobData getPcrCompositeHash() throws TcTssException
	{
		synchronized (pcrInfo_) {
			return getPcrCompositeHash(pcrInfo_.getPcrSelection()).getEncoded();
		}
	}


	/*
	 * (non-Javadoc)
	 *
	 * @see iaik.tss.api.tspi.TcIPcrComposite#getPcrLocality()
	 */
	public long getPcrLocality() throws TcTssException
	{
		throw new TcTspException(TcTssErrors.TSS_E_INVALID_OBJ_ACCESS,
				"This method is not available when using a TPM_PCR_INFO structure.");
	}


	/*
	 * (non-Javadoc)
	 *
	 * @see iaik.tss.api.tspi.TcIPcrComposite#selectPcrIndex(long)
	 */
	public void selectPcrIndex(long pcrIndex) throws TcTssException
	{
		checkPcrIndexValidity(pcrIndex);

		synchronized (pcrInfo_) {
			TcTpmPcrSelection pcrSelect = pcrInfo_.getPcrSelection();
			pcrSelect.setPcrSelect(selectPcr(pcrSelect.getPcrSelect(), pcrIndex));
			pcrInfo_.setPcrSelection(pcrSelect);
		}
	}


	/*
	 * (non-Javadoc)
	 *
	 * @see iaik.tss.api.tspi.TcIPcrComposite#selectPcrIndexEx(long, long)
	 */
	public void selectPcrIndexEx(long pcrIndex, long direction) throws TcTssException
	{
		throw new TcTspException(TcTssErrors.TSS_E_INVALID_OBJ_ACCESS,
				"This method is not available when using a TPM_PCR_INFO structure.");
	}


	/*
	 * (non-Javadoc)
	 *
	 * @see iaik.tss.api.tspi.TcIPcrComposite#setPcrLocality(long)
	 */
	public void setPcrLocality(long localityValue) throws TcTssException
	{
		throw new TcTspException(TcTssErrors.TSS_E_INVALID_OBJ_ACCESS,
				"This method is not available when using a TPM_PCR_INFO structure.");
	}


	/*
	 * (non-Javadoc)
	 *
	 * @see iaik.tss.api.tspi.TcIPcrComposite#setPcrValue(long, iaik.tss.api.structs.TcBlobData)
	 */
	public void setPcrValue(long pcrIndex, TcBlobData pcrValue) throws TcTssException
	{
		checkPcrIndexValidity(pcrIndex);
		CheckPrecondition.notNull(pcrValue, "pcrValue");
		CheckPrecondition.equal(pcrValue.getLengthAsLong(), TcTpmConstants.TPM_SHA1_160_HASH_LEN,
				"pcrValue.getLength");

		synchronized (pcrInfo_) {
			// select pcrIndex
			selectPcrIndex(pcrIndex);

			// set PCR value and get updated composite hash
			TcTpmCompositeHash compHash = setPcrValueAndReturnCompHash(pcrIndex, pcrValue, pcrInfo_
					.getPcrSelection());

			pcrInfo_.setDigestAtRelease(compHash);
		}
	}


	/*
	 * (non-Javadoc)
	 *
	 * @see iaik.tss.impl.java.tsp.TcPcrCompositeBase#toString()
	 */
	public String toString()
	{
		synchronized (pcrInfo_) {
			return pcrInfo_.toString();
		}
	}


	/*
	 * (non-Javadoc)
	 *
	 * @see iaik.tss.impl.java.tsp.TcPcrCompositeBase#getPcrStructEncoded()
	 */
	protected TcBlobData getPcrStructEncoded()
	{
		synchronized (pcrInfo_) {
			return (TcBlobData) pcrInfo_.getEncoded();
		}
	}


	/*
	 * (non-Javadoc)
	 *
	 * @see iaik.tss.impl.java.tsp.TcPcrCompositeBase#getPcrSelection()
	 */
	protected TcTpmPcrSelection getPcrSelection()
	{
		synchronized (pcrInfo_) {
			// pcrInfo_ is synchronized; getEncoded ensures that pcrSelection is a deep copy
			return new TcTpmPcrSelection(pcrInfo_.getPcrSelection().getEncoded());
		}
	}
}
