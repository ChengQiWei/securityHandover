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
import iaik.tc.tss.api.structs.tpm.TcTpmPcrComposite;
import iaik.tc.tss.api.structs.tpm.TcTpmPcrSelection;
import iaik.tc.tss.api.structs.tpm.TcTpmPcrValue;
import iaik.tc.tss.api.tspi.TcIContext;
import iaik.tc.tss.api.tspi.TcIPcrComposite;
import iaik.tc.utils.misc.CheckPrecondition;

import java.util.Arrays;
import java.util.Vector;

public abstract class TcPcrCompositeBase extends TcWorkingObject implements TcIPcrComposite {

	/**
	 * This field holds the pcrValues at release. If a PCR value is not set, the entry in this array
	 * is null. Before using this array in a PCR_COMPOSITE, those null value elements have to be
	 * removed.
	 */
	/*
	 * Synchronization Note: This field is intentionally kept private. Access to this field has to be
	 * properly synchronized. To reduce complexity, all access to this field (and hence all required
	 * synchronization) is kept local to this class.
	 */
	private TcTpmPcrValue[] pcrValuesAtRelease_;
	
	private int offlineNumOfPCRs_=-1;


	/*************************************************************************************************
	 * Constructor.
	 */
	protected TcPcrCompositeBase(TcIContext context) throws TcTssException
	{
		
		super(context);

		// setup internal array holding the pcrValues@Release
		pcrValuesAtRelease_ = new TcTpmPcrValue[getNumPcrs()];
		Arrays.fill(pcrValuesAtRelease_, null);
	}


	/**
	 * Construct structure offline.
	 * @param numPcrs
	 */
	public TcPcrCompositeBase(int numPcrs) 
	{
				context_=null;
				offlineNumOfPCRs_=numPcrs;
				pcrValuesAtRelease_=new TcTpmPcrValue[numPcrs];
				Arrays.fill(pcrValuesAtRelease_, null);
				
			
	}
	
	/*************************************************************************************************
	 * Internal method that returns the struct of the PcrComposite in its encoded form.
	 */
	protected abstract TcBlobData getPcrStructEncoded();


	/*************************************************************************************************
	 * Internal method that returns the PCR selection
	 */
	protected abstract TcTpmPcrSelection getPcrSelection();


	/*************************************************************************************************
	 * Returns a string representation of the object.
	 */
	public abstract String toString();


	/*
	 * (non-Javadoc)
	 *
	 * @see iaik.tss.api.tspi.TcIPcrComposite#getPcrValue(long)
	 */
	public TcBlobData getPcrValue(long pcrIndex) throws TcTssException
	{
		checkPcrIndexValidity(pcrIndex);

		synchronized (pcrValuesAtRelease_) {
			if (pcrValuesAtRelease_[(int) pcrIndex] == null) {
				return null;
			} else {
				// pcrValuesAtRelease_ is synchronized; do not return its elements directly
				return (TcBlobData)pcrValuesAtRelease_[(int) pcrIndex].getEncoded();
			}
		}
	}


	/*************************************************************************************************
	 * This internal method sets the given PCR value for the given PCR index. A PCR composite hash
	 * reflecting the changed PCR value is created and returned.
	 */
	protected TcTpmCompositeHash setPcrValueAndReturnCompHash(long pcrIndex, TcBlobData pcrValue,
			TcTpmPcrSelection selection) throws TcTssException
	{
		checkPcrIndexValidity(pcrIndex);
		CheckPrecondition.notNull(pcrValue, "pcrValue");
		CheckPrecondition.equal(pcrValue.getLengthAsLong(), TcTpmConstants.TPM_SHA1_160_HASH_LEN,
				"pcrValue.getLength");
		CheckPrecondition.notNull(selection, "selection");

		synchronized (pcrValuesAtRelease_) {
			// set pcr value
			pcrValuesAtRelease_[(int) pcrIndex] = new TcTpmPcrValue(pcrValue);

			// update digest at release
			TcTpmCompositeHash compHash = getPcrCompositeHash(selection);

			return compHash;
		}
	}


	/*************************************************************************************************
	 * Internal helper method that creates a CompositeHash from a PCR selection and
	 * pcrValuesAtRelease.
	 */
	protected TcTpmCompositeHash getPcrCompositeHash(TcTpmPcrSelection selection)
	{
		synchronized (pcrValuesAtRelease_) {
			// create copy of pcrValuesAtRelease_ but omit all null values
			Vector pcrValuesNotNull = new Vector();
			for (int i = 0; i < pcrValuesAtRelease_.length; i++) {
				if (pcrValuesAtRelease_[i] != null) {
					pcrValuesNotNull.add(pcrValuesAtRelease_[i]);
				}
			}

			// create a PCR composite object
			TcTpmPcrComposite pcrComp = new TcTpmPcrComposite();
			pcrComp.setSelect(selection);
			TcTpmPcrValue[] tmp = new TcTpmPcrValue[pcrValuesNotNull.size()];
			tmp = (TcTpmPcrValue[]) pcrValuesNotNull.toArray(tmp);
			pcrComp.setPcrValue(tmp);

			// return hash of PCR composite object
			TcTpmCompositeHash pcrCompHash = new TcTpmCompositeHash(pcrComp.getEncoded().sha1());
			return pcrCompHash;
		}
	}


	/*************************************************************************************************
	 * Internal helper method that select the given PCR in the pcrSelection.
	 */
	protected TcBlobData selectPcr(TcBlobData pcrSelection, long pcrIndex)
	{
		byte[] selection = pcrSelection.asByteArray();

		short byteSelection = (short) (pcrIndex / 8);
		short bitSelection = (short) (pcrIndex % 8);
		selection[byteSelection] |= 1 << (bitSelection);

		return TcBlobData.newByteArray(selection);
	}


	/*************************************************************************************************
	 * Internal helper method that returns the number of PCRs of the TPM.
	 */
	protected int getNumPcrs() throws TcTssException
	{
		
		if (context_==null) return offlineNumOfPCRs_;
		
		
		checkContextOpenAndConnected();

		TcBlobData subCap = TcBlobData.newUINT32(TcTssConstants.TSS_TPMCAP_PROP_PCR);
		long numPcrs = context_.getTpmObject()
				.getCapabilityUINT32(TcTssConstants.TSS_TPMCAP_PROPERTY, subCap);

		return (int) numPcrs;
	}


	/*************************************************************************************************
	 * Internal helper method that checks if the given pcrIndex is valid (i.e. 0 <= pcrIndex <
	 * TPM.numPcrs).
	 */
	protected void checkPcrIndexValidity(long pcrIndex) throws TcTssException
	{
		CheckPrecondition.gtOrEq(pcrIndex, "pcrIndex", 0);
		if (pcrIndex > (getNumPcrs() - 1)) {
			throw new TcTspException(TcTssErrors.TSS_E_BAD_PARAMETER,
					"Given pcrIndex exceeds the number of available PCRs for this TPM.");
		}
	}


	/*************************************************************************************************
	 * Internal helper method that returns the default PCR selection.
	 */
	protected TcTpmPcrSelection getDefaultSelection() throws TcTssException
	{
		byte[] pcrSelectBytes = new byte[(int) getNumPcrs() / 8];
		Arrays.fill(pcrSelectBytes, (byte) 0);
		TcTpmPcrSelection pcrSelect = new TcTpmPcrSelection();
		pcrSelect.setPcrSelect(TcBlobData.newByteArray(pcrSelectBytes));

		return pcrSelect;
	}


	/*************************************************************************************************
	 * Internal helper method that returns the default composite hash.
	 */
	protected TcTpmCompositeHash getDefaultCompHash()
	{
		// setup digestAtRelease and digestAtCreation
		// TPM spec: if PCR_SELECTION.pcrSelect is all 0s, COMPOSITE_HASH must be set to be all 0s
		byte[] compHash = new byte[(int) TcTpmConstants.TPM_SHA1_160_HASH_LEN];
		Arrays.fill(compHash, (byte) 0);
		TcBlobData compHashBlob = TcBlobData.newByteArray(compHash);

		return new TcTpmCompositeHash(compHashBlob);
	}


	/*************************************************************************************************
	 * Internal helper method that returns the default default locality.
	 */
	protected short getDefaultLocality()
	{
		// note: The default locality is 0x1f indicationg that localities 0 to 4 have been selected.
		return (short) TcTpmConstants.TPM_LOC_ALL;
	}


	// ----------------------------------------------------------------------------------------------
	// TSS attribute getters and setter
	// ----------------------------------------------------------------------------------------------


	/*************************************************************************************************
	 * Mapping of attribute flags to getter methods.
	 */
	protected void initAttribGetters()
	{
		addGetterUINT32(TcTssConstants.TSS_TSPATTRIB_PCRS_INFO, "getAttribPcrStruct");
	}


	/*************************************************************************************************
	 * Mapping of attribute flags to setter methods.
	 */
	protected void initAttribSetters()
	{
		addSetterUINT32(TcTssConstants.TSS_TSPATTRIB_PCRS_INFO, "setAttribPcrStruct");
	}


	/*************************************************************************************************
	 * This method is used to set PCR composite attributes. The only attribute defined in the TSS
	 * specification is the PCR composite structure attribute. Since it makes little sense to change
	 * the underlying structure after the PCR composite object was created, this attribute is not
	 * supported. To specify the underlying struct version, use the init flags upon object creation.
	 * Note that this method is not standardized as part of the TSP Interface (TSPI).
	 *
	 * @throws {@link TcTssException}
	 */
	public void setAttribPcrStruct(long subFlag, long attrib) throws TcTssException
	{
		throw new TcTspException(TcTssErrors.TSS_E_INVALID_ATTRIB_DATA,
				"PCR composite structure type can only be specified upon object creation.");
	}


	/*************************************************************************************************
	 * This method is used to get PCR composite attributes. Note that this method is not standardized
	 * as part of the TSP Interface (TSPI).
	 *
	 * @param subFlag Valid subFlags are:
	 *          <ul>
	 *          <li> {@link TcTssConstants#TSS_TSPATTRIB_PCRSINFO_PCRSTRUCT}
	 *          </ul>
	 *
	 * @return The type of internal PCR data structure. This can be of type
	 *         {@link TcTssConstants#TSS_PCRS_STRUCT_INFO},
	 *         {@link TcTssConstants#TSS_PCRS_STRUCT_INFO_SHORT} or
	 *         {@link TcTssConstants#TSS_PCRS_STRUCT_INFO_LONG}.
	 *
	 * @throws {@link TcTssException}
	 */
	public long getAttribPcrStruct(long subFlag) throws TcTssException
	{
		long retVal = 0;
		if (subFlag == TcTssConstants.TSS_TSPATTRIB_PCRSINFO_PCRSTRUCT) {
			retVal = getPcrStructVer();
		} else {
			throw new TcTspException(TcTssErrors.TSS_E_INVALID_ATTRIB_SUBFLAG);
		}
		return retVal;
	}


	/*************************************************************************************************
	 * Internal method used by sub-classes to report the PCR struct version they use internally.
	 */
	protected abstract long getPcrStructVer();
}
