/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.impl.java.tsp;


import iaik.tc.tss.api.constants.tpm.TcTpmConstants;
import iaik.tc.tss.api.constants.tsp.TcTssConstants;
import iaik.tc.tss.api.constants.tsp.TcTssErrors;
import iaik.tc.tss.api.exceptions.common.TcTssException;
import iaik.tc.tss.api.exceptions.tcs.TcTcsException;
import iaik.tc.tss.api.exceptions.tcs.TcTddlException;
import iaik.tc.tss.api.exceptions.tcs.TcTpmException;
import iaik.tc.tss.api.exceptions.tsp.TcTspException;
import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.tss.api.structs.tpm.TcTpmCompositeHash;
import iaik.tc.tss.api.structs.tpm.TcTpmPcrInfoLong;
import iaik.tc.tss.api.structs.tpm.TcTpmPcrSelection;
import iaik.tc.tss.api.tspi.TcIContext;
import iaik.tc.utils.misc.CheckPrecondition;

public class TcPcrCompositeInfoLong extends TcPcrCompositeBase {

	/**
	 * This field holds the PCR_INFO_LONG instance.
	 */
	protected TcTpmPcrInfoLong pcrInfo_ = new TcTpmPcrInfoLong();
	
	
	/*************************************************************************************************
	 * Constructor.
	 */
	protected TcPcrCompositeInfoLong(TcIContext context) throws TcTssException
	{
		super(context);

		// setup the PCR selection (all bits set to 0 - i.e. no PCRs selected)
		pcrInfo_.setCreationPCRSelection(getDefaultSelection());
		pcrInfo_.setReleasePCRSelection(getDefaultSelection());

		// setup digestAtRelease and digestAtCreation
		// TPM spec: if PCR_SELECTION.pcrSelect is all 0s, COMPOSITE_HASH must be set to be all 0s
		pcrInfo_.setDigestAtCreation(getDefaultCompHash());
		pcrInfo_.setDigestAtRelease(getDefaultCompHash());

		// setup default locality
		pcrInfo_.setLocalityAtCreation(getDefaultLocality());
		pcrInfo_.setLocalityAtRelease(getDefaultLocality());

		// setup the structure tag
		pcrInfo_.setTag(TcTpmConstants.TPM_TAG_PCR_INFO_LONG);
	}


	/**
	 * For offline creation of struct
	 * @param numPCRs
	 * @throws TcTssException
	 */
	public TcPcrCompositeInfoLong(int numPCRs) throws TcTssException
	{
		super(numPCRs);

		// setup the PCR selection (all bits set to 0 - i.e. no PCRs selected)
		pcrInfo_.setCreationPCRSelection(getDefaultSelection());
		pcrInfo_.setReleasePCRSelection(getDefaultSelection());

		// setup digestAtRelease and digestAtCreation
		// TPM spec: if PCR_SELECTION.pcrSelect is all 0s, COMPOSITE_HASH must be set to be all 0s
		pcrInfo_.setDigestAtCreation(getDefaultCompHash());
		pcrInfo_.setDigestAtRelease(getDefaultCompHash());

		// setup default locality
		pcrInfo_.setLocalityAtCreation(getDefaultLocality());
		pcrInfo_.setLocalityAtRelease(getDefaultLocality());

		// setup the structure tag
		pcrInfo_.setTag(TcTpmConstants.TPM_TAG_PCR_INFO_LONG);
	}


	
	/*************************************************************************************************
	 * Internal method returning the PCR struct version used by this class.
	 */
	protected long getPcrStructVer()
	{
		return TcTssConstants.TSS_PCRS_STRUCT_INFO_LONG;
	}


	/*
	 * (non-Javadoc)
	 * 
	 * @see iaik.tss.api.tspi.TcIPcrComposite#getPcrCompositeHash()
	 */
	public TcBlobData getPcrCompositeHash()
		throws TcTssException, TcTcsException, TcTddlException, TcTpmException
	{
		synchronized (pcrInfo_) {
			return getPcrCompositeHash(pcrInfo_.getReleasePcrSelection()).getEncoded();
		}
	}


	/*
	 * (non-Javadoc)
	 * 
	 * @see iaik.tss.api.tspi.TcIPcrComposite#getPcrLocality()
	 */
	public long getPcrLocality() throws TcTssException
	{
		synchronized (pcrInfo_) {
			return pcrInfo_.getLocalityAtRelease();
		}
	}


	/*
	 * (non-Javadoc)
	 * 
	 * @see iaik.tss.api.tspi.TcIPcrComposite#selectPcrIndex(long)
	 */
	public void selectPcrIndex(long pcrIndex) throws TcTssException
	{
		throw new TcTspException(TcTssErrors.TSS_E_INVALID_OBJ_ACCESS,
				"This method is not available when not using a TPM_PCR_INFO structure. " +
				"Use selectPcrIndexEx instead.");
	}


	/*
	 * (non-Javadoc)
	 * 
	 * @see iaik.tss.api.tspi.TcIPcrComposite#selectPcrIndexEx(long, long)
	 */
	public void selectPcrIndexEx(long pcrIndex, long direction) throws TcTssException
	{
		checkPcrIndexValidity(pcrIndex);

		TcTpmPcrSelection pcrSelect = null;

		synchronized (pcrInfo_) {
			if (direction == TcTssConstants.TSS_PCRS_DIRECTION_RELEASE) {
				pcrSelect = pcrInfo_.getReleasePcrSelection();
				pcrSelect.setPcrSelect(selectPcr(pcrSelect.getPcrSelect(), pcrIndex));
				pcrInfo_.setReleasePCRSelection(pcrSelect);

			} else if (direction == TcTssConstants.TSS_PCRS_DIRECTION_CREATION) {
				pcrSelect = pcrInfo_.getCreationPCRSelection();
				pcrSelect.setPcrSelect(selectPcr(pcrSelect.getPcrSelect(), pcrIndex));
				pcrInfo_.setCreationPCRSelection(pcrSelect);

			} else {
				throw new TcTspException(TcTssErrors.TSS_E_BAD_PARAMETER,
						"Direction must be of type TSS_PCRS_DIRECTION_RELEASE or TSS_PCRS_DIRECTION_CREATION.");
			}
		}
	}


	/*
	 * (non-Javadoc)
	 * 
	 * @see iaik.tss.api.tspi.TcIPcrComposite#setPcrLocality(long)
	 */
	public void setPcrLocality(long localityValue) throws TcTssException
	{
		if (localityValue != TcTpmConstants.TPM_LOC_ZERO && localityValue != TcTpmConstants.TPM_LOC_ONE
				&& localityValue != TcTpmConstants.TPM_LOC_TWO
				&& localityValue != TcTpmConstants.TPM_LOC_THREE
				&& localityValue != TcTpmConstants.TPM_LOC_FOUR) {
			throw new TcTspException(TcTssErrors.TSS_E_BAD_PARAMETER, "Unknown locality.");
		}

		synchronized (pcrInfo_) {
			pcrInfo_.setLocalityAtRelease((short) localityValue);
		}
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
			selectPcrIndexEx(pcrIndex, TcTssConstants.TSS_PCRS_DIRECTION_RELEASE);

			// set PCR value and get updated composite hash
			TcTpmCompositeHash compHash = setPcrValueAndReturnCompHash(pcrIndex, pcrValue, pcrInfo_
					.getReleasePcrSelection());

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
			return pcrInfo_.getEncoded();
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
			// pcrInfo_ is synchronized; getEncoded ensures that releasePcrSelection is a deep copy
			return new TcTpmPcrSelection(pcrInfo_.getReleasePcrSelection().getEncoded());
		}
	}
}
