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
import iaik.tc.tss.api.structs.tpm.TcTpmPcrInfoShort;
import iaik.tc.tss.api.structs.tpm.TcTpmPcrSelection;
import iaik.tc.tss.api.tspi.TcIContext;
import iaik.tc.utils.misc.CheckPrecondition;

public class TcPcrCompositeInfoShort extends TcPcrCompositeBase {

	/**
	 * This field holds the PCR_INFO_SHORT instance.
	 */
	protected TcTpmPcrInfoShort pcrInfo_ = new TcTpmPcrInfoShort();


	/*************************************************************************************************
	 * Constructor.
	 */
	protected TcPcrCompositeInfoShort(TcIContext context) throws TcTssException
	{
		super(context);

		// setup the PCR selection (all bits set to 0 - i.e. no PCRs selected)
		pcrInfo_.setPcrSelection(getDefaultSelection());

		// setup digestAtRelease and digestAtCreation
		// TPM spec: if PCR_SELECTION.pcrSelect is all 0s, COMPOSITE_HASH must be set to be all 0s
		pcrInfo_.setDigestAtRelease(getDefaultCompHash());

		// setup default locality
		pcrInfo_.setLocalityAtRelease(getDefaultLocality());
	}


	public TcPcrCompositeInfoShort(int numPCRs) throws TcTssException
	{
		super(numPCRs);

		// setup the PCR selection (all bits set to 0 - i.e. no PCRs selected)
		pcrInfo_.setPcrSelection(getDefaultSelection());

		// setup digestAtRelease and digestAtCreation
		// TPM spec: if PCR_SELECTION.pcrSelect is all 0s, COMPOSITE_HASH must be set to be all 0s
		pcrInfo_.setDigestAtRelease(getDefaultCompHash());

		// setup default locality
		pcrInfo_.setLocalityAtRelease(getDefaultLocality());
	}

	
	/*************************************************************************************************
	 * Internal method returning the PCR struct version used by this class.
	 */
	protected long getPcrStructVer()
	{
		return TcTssConstants.TSS_PCRS_STRUCT_INFO_SHORT;
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
		throw new TcTspException(
				TcTssErrors.TSS_E_INVALID_OBJ_ACCESS,
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
		if (direction == TcTssConstants.TSS_PCRS_DIRECTION_CREATION) {
			throw new TcTspException(TcTssErrors.TSS_E_INVALID_OBJ_ACCESS,
					"For PCR_INFO_SHORT the direction must be set to TSS_PCRS_DIRECTION_RELEASE.");
		} else if (direction != TcTssConstants.TSS_PCRS_DIRECTION_RELEASE) {
			throw new TcTspException(TcTssErrors.TSS_E_BAD_PARAMETER,
					"Direction must be of type TSS_PCRS_DIRECTION_RELEASE.");
		}

		synchronized (pcrInfo_) {
			TcTpmPcrSelection pcrSelect = pcrInfo_.getPcrSelection();
			pcrSelect.setPcrSelect(selectPcr(pcrSelect.getPcrSelect(), pcrIndex));
			pcrInfo_.setPcrSelection(pcrSelect);
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
			// pcrInfo_ is synchronized; getEncoded ensures that pcrSelection is a deep copy
			return new TcTpmPcrSelection(pcrInfo_.getPcrSelection().getEncoded());
		}
	}
}
