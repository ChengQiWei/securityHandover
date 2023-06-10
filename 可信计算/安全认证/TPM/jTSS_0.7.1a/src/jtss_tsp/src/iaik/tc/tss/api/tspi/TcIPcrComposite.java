/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.api.tspi;


import iaik.tc.tss.api.constants.tpm.TcTpmConstants;
import iaik.tc.tss.api.constants.tsp.TcTssConstants;
import iaik.tc.tss.api.constants.tsp.TcTssErrors;
import iaik.tc.tss.api.exceptions.common.TcTssException;
import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.tss.api.structs.tpm.TcTpmPcrInfo;
import iaik.tc.tss.api.structs.tpm.TcTpmPcrInfoLong;
import iaik.tc.tss.api.structs.tpm.TcTpmPcrInfoShort;

/**
 * The contents of the platform configuration register (PCR) of a TCG system can be used to
 * establish a confidence level for this system. This class provides a comfortable way to deal with
 * PCR values (e.g. select, read, write). An instance of such a class is used from all TSP functions
 * that need PCR information in their parameter list.
 */
public interface TcIPcrComposite extends TcIWorkingObject, TcIAttributes {

	/*************************************************************************************************
	 * This method sets the digest for a given PCR index inside the PCR composite object.<br>
	 * An example for the usage is the preparation of a PCR composite object before calling
	 * {@link TcIRsaKey#createKey(TcIRsaKey, TcIPcrComposite)}. Multiple PCRs with different indices
	 * can be set by calling this method multiple times in the same PCR composite object.<br>
	 * This method may be used to set PCR values in a PCR composite object regardless of the type of
	 * PCR structure ({@link TcTpmPcrInfo}, {@link TcTpmPcrInfoShort} or {@link TcTpmPcrInfoLong})
	 * used by the object.<br>
	 * If a {@link TcTpmPcrInfoLong} is used, this method sets the PCR value for DigestAtRelease.
	 * 
	 * @TSS_V1 182
	 * 
	 * @TSS_1_2_EA 296
	 * 
	 * @param pcrIndex The index of the PCR to set.
	 * @param pcrValue The value of the PCR.
	 * 
	 * 
	 */
	public void setPcrValue(final long pcrIndex, final TcBlobData pcrValue) throws TcTssException;


	/*************************************************************************************************
	 * This method returns the digest value of a given PCR index inside a PCR composite object.
	 * Multiple PCR values for different indices can be retrieved by calling this method multiple
	 * times on a PCR composite object. <br>
	 * This method may be used to get PCR values in a PCR composite object regardless of the PCR
	 * structure type ({@link TcTpmPcrInfo}, {@link TcTpmPcrInfoShort} or {@link TcTpmPcrInfoLong}).<br>
	 * If a {@link TcTpmPcrInfoLong} is used, this method returns the digestAtRelease.
	 * 
	 * @TSS_V1 183
	 * 
	 * @TSS_1_2_EA 297
	 * 
	 * @param pcrIndex The index of the PCR to read.
	 * @return The contents of PCR specified by pcrIndex.
	 * 
	 * 
	 */
	public TcBlobData getPcrValue(final long pcrIndex) throws TcTssException;


	/*************************************************************************************************
	 * This method selects a PCR index inside a PCR composite object using the 1.1
	 * {@link TcTpmPcrInfo} structure. If the PcrComposite object is using another structure than
	 * {@link TcTpmPcrInfo}, this function throws a {@link TcTssException} with an
	 * {@link TcTssErrors#TSS_E_INVALID_OBJ_ACCESS} error code.
	 * 
	 * @TSS_V1 181
	 * 
	 * @TSS_1_2_EA 295
	 * 
	 * @param pcrIndex The index of the PCR to select.
	 * 
	 * 
	 */
	public void selectPcrIndex(final long pcrIndex) throws TcTssException;


	/*************************************************************************************************
	 * This method sets the LocalityAtRelease inside the PCR composite object using a 1.2
	 * {@link TcTpmPcrInfoLong} or {@link TcTpmPcrInfoShort} structure. If the PcrComposite object is
	 * using a {@link TcTpmPcrInfo} (e.g. because the underlying TPM is a 1.1 TPM) a
	 * {@link TcTssException} with {@link TcTssErrors#TSS_E_INVALID_OBJ_ACCESS} error code is thrown.
	 * 
	 * @TSS_1_2_EA 305
	 * 
	 * @param localityValue LocalityAtRelease value to set. Valid locality values are:
	 *          {@link TcTpmConstants#TPM_LOC_ZERO}, {@link TcTpmConstants#TPM_LOC_ONE},
	 *          {@link TcTpmConstants#TPM_LOC_TWO}, {@link TcTpmConstants#TPM_LOC_THREE},
	 *          {@link TcTpmConstants#TPM_LOC_FOUR}.
	 * 
	 * 
	 */
	public void setPcrLocality(final long localityValue) throws TcTssException;


	/*************************************************************************************************
	 * This method gets the LocalityAtRelease from the PCR composite object using a 1.2
	 * {@link TcTpmPcrInfoLong} or {@link TcTpmPcrInfoShort} structure.
	 * 
	 * @TSS_1_2_EA 306
	 * 
	 * @return The LocalityAtRelease value.
	 * 
	 * 
	 */
	public long getPcrLocality() throws TcTssException;


	/*************************************************************************************************
	 * This method gets the digestAtRelease from the PCR composite object using a 1.2
	 * {@link TcTpmPcrInfoLong} or {@link TcTpmPcrInfoShort} structure. If the PcrComposite object is
	 * using a {@link TcTpmPcrInfo} (e.g. because the underlying TPM is a 1.1 TPM) a
	 * {@link TcTssException} with {@link TcTssErrors#TSS_E_INVALID_OBJ_ACCESS} error code is thrown.
	 * 
	 * @TSS_1_2_EA 307
	 * 
	 * @return The digestAtRelease value.
	 * 
	 * 
	 */
	public TcBlobData getPcrCompositeHash() throws TcTssException;


	/*************************************************************************************************
	 * This method selects a PCR index inside a PCR composite object containing a
	 * {@link TcTpmPcrInfoLong} or {@link TcTpmPcrInfoShort} structure. For {@link TcTpmPcrInfoLong},
	 * the index may be selected for creation or release; for {@link TcTpmPcrInfoShort}, the index
	 * may be selected only for release. <br>
	 * If the PcrComposite object is using a {@link TcTpmPcrInfo} (e.g. because the underlying TPM is
	 * a 1.1 TPM) a {@link TcTssException} with {@link TcTssErrors#TSS_E_INVALID_OBJ_ACCESS} error
	 * code is thrown.<br>
	 * If the PcrComposite object is using {@link TcTpmPcrInfoShort} and the direction indicates
	 * Creation, the method will throw a {@link TcTssException} with a
	 * {@link TcTssErrors#TSS_E_INVALID_OBJ_ACCESS}.
	 * 
	 * @TSS_1_2_EA 308
	 * 
	 * @param pcrIndex The index of the PCR to select.
	 * @param direction Chooses whether the index selected is for a PCR at creation or a PCR at
	 *          release. Valid direction flags are {@link TcTssConstants#TSS_PCRS_DIRECTION_CREATION}
	 *          and {@link TcTssConstants#TSS_PCRS_DIRECTION_RELEASE}.
	 * 
	 * 
	 */
	public void selectPcrIndexEx(final long pcrIndex, final long direction) throws TcTssException;
}