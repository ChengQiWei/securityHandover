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
import iaik.tc.tss.api.structs.tpm.TcTpmCapVersionInfo;
import iaik.tc.tss.api.structs.tpm.TcTpmCounterValue;
import iaik.tc.tss.api.structs.tpm.TcTpmMigrationkeyAuth;
import iaik.tc.tss.api.structs.tpm.TcTpmQuoteInfo;
import iaik.tc.tss.api.structs.tpm.TcTpmNonce;
import iaik.tc.tss.api.structs.tsp.TcTssPcrEvent;
import iaik.tc.tss.api.structs.tsp.TcTssValidation;
import iaik.tc.tss.api.structs.tsp.TcTssVersion;
import iaik.tc.tss.api.structs.tpm.TcTpmCurrentTicks;
/**
 * One purpose of the TPM class is to represent the owner for a TCG subsystem (TPM). The owner of a
 * TPM is comparable with an administrator in the PC environment. For that reason there exists only
 * one instance of the TPM class per context. This object is automatically associated with one
 * policy object, which must be used to handle the owner authentication data. On the other hand it
 * provides some basic control and reporting functionality.
 */
public interface TcITpm extends TcIWorkingObject, TcIAttributes, TcIAuthObject {

	/*************************************************************************************************
	 * This method takes ownership of the TPM. The process of taking ownership is the procedure
	 * whereby the owner inserts a shared secret into the TPM. The owner of the TPM has the right to
	 * perform special operations. As part of this command, the owner password is set and a new SRK
	 * key pair is created.
	 *
	 * @TSS_V1 110
	 *
	 * @TSS_1_2_EA 252
	 *
	 * @param srk The storage root key object.
	 * @param pubEk The public endorsement key object. The public endorsement key is required for
	 *          encryption of the SRK and EK secret sent to the TPM. The pubEk parameter can be set to
	 *          null. In this case, the takeOwnership method will query the TPM for the public
	 *          endorsement key.s
	 *
	 *
	 */
	public void takeOwnership(final TcIRsaKey srk, final TcIRsaKey pubEk) throws TcTssException;


	/*************************************************************************************************
	 * This method returns the public endorsement key. The public key information of the endorsement
	 * key can be retrieved via {@link TcIAttributes#getAttribData(long, long)}.
	 *
	 * @TSS_V1 109
	 *
	 * @TSS_1_2_EA 243
	 *
	 * @param ownerAuthorized Flag determining if owner authorization is required. Note that owner
	 *          authorization is not required if the ownership of the TPM has not yet been taken.
	 *          After TPM ownership has been taken, owner authorization is required to obtain the
	 *          public EK.
	 * @param validataionData External data that is used by the TPM to compute the checksum. If this
	 *          parameter is omitted (i.e. it is set to null), the validation is done by the TSP:
	 *
	 * @return The returned Object[] contains the following elements:
	 *         <ul>
	 *         <li> 0 ... endorsement key object {@link TcIRsaKey}
	 *         <li> 1 ... outgoing validation ({@link TcTssValidation}
	 *         </ul>
	 */
	public Object[] getPubEndorsementKey(final boolean ownerAuthorized,
			TcTssValidation validataionData) throws TcTssException;


	/*************************************************************************************************
	 * This method returns the public endorsement key. The public key information of the endorsement
	 * key can be retrieved via {@link TcIAttributes#getAttribData(long, long)}. This method always
	 * tries to read the public EK using owner authorization. If effectively is a shortcut for
	 * {@link TcITpm#getPubEndorsementKey(boolean, TcTssValidation)} with (true, null) as parameters.
	 *
	 * @TSS_V1 109
	 *
	 * @TSS_1_2_EA 243
	 *
	 * @return {@link TcIRsaKey}
	 *
	 *
	 */
	public TcIRsaKey getPubEndorsementKeyOwner() throws TcTssException;


	/*************************************************************************************************
	 * This method returns the TPM status. <br>
	 * Valid statusFlags are:
	 * <ul>
	 * <li>{@link TcTssConstants#TSS_TPMSTATUS_DISABLEOWNERCLEAR}</li>
	 * <li>{@link TcTssConstants#TSS_TPMSTATUS_DISABLEFORCECLEAR}</li>
	 * <li>{@link TcTssConstants#TSS_TPMSTATUS_DISABLED}</li>
	 * <li>{@link TcTssConstants#TSS_TPMSTATUS_PHYSICALSETDEACTIVATED}</li>
	 * <li>{@link TcTssConstants#TSS_TPMSTATUS_SETTEMPDEACTIVATED}</li>
	 * <li>{@link TcTssConstants#TSS_TPMSTATUS_SETOWNERINSTALL}</li>
	 * <li>{@link TcTssConstants#TSS_TPMSTATUS_DISABLEPUBEKREAD}</li>
	 * <li>{@link TcTssConstants#TSS_TPMSTATUS_ALLOWMAINTENANCE}</li>
	 * <li>{@link TcTssConstants#TSS_TPMSTATUS_PHYSPRES_LIFETIMELOCK}</li>
	 * <li>{@link TcTssConstants#TSS_TPMSTATUS_PHYSPRES_HWENABLE}</li>
	 * <li>{@link TcTssConstants#TSS_TPMSTATUS_PHYSPRES_CMDENABLE}</li>
	 * <li>{@link TcTssConstants#TSS_TPMSTATUS_CEKP_USED}</li>
	 * <li>{@link TcTssConstants#TSS_TPMSTATUS_PHYSPRESENCE}</li>
	 * <li>{@link TcTssConstants#TSS_TPMSTATUS_PHYSPRES_LOCK}</li>
	 * </ul>
	 *
	 * @TSS_V1 118
	 *
	 * @param statusFlag status flag to be read
	 * @return value of status flag
	 *
	 *
	 */
	public boolean getStatus(final long statusFlag) throws TcTssException;


	/*************************************************************************************************
	 * This method modifies the TPM status.
	 *
	 * @TSS_V1 116
	 *
	 * @param statusFlag determines the flag to be set. <br>
	 *          Valid statusFlags are:
	 *          <ul>
	 *          <li>{@link TcTssConstants#TSS_TPMSTATUS_DISABLEOWNERCLEAR}, tpmState is ignored</li>
	 *          <li>{@link TcTssConstants#TSS_TPMSTATUS_DISABLEFORCECLEAR}, tpmState is ignored</li>
	 *          <li>{@link TcTssConstants#TSS_TPMSTATUS_OWNERSETDISABLE}</li>
	 *          <li>{@link TcTssConstants#TSS_TPMSTATUS_PHYSICALDISABLE}</li>
	 *          <li>{@link TcTssConstants#TSS_TPMSTATUS_PHYSICALSETDEACTIVATED}</li>
	 *          <li>{@link TcTssConstants#TSS_TPMSTATUS_SETTEMPDEACTIVATED}, tpmState is ignored</li>
	 *          <li>{@link TcTssConstants#TSS_TPMSTATUS_SETOWNERINSTALL}</li>
	 *          <li>{@link TcTssConstants#TSS_TPMSTATUS_DISABLEPUBEKREAD}, tpmState is ignored</li>
	 *          </ul>
	 * @param tpmState the new value of the flag
	 *
	 *
	 */
	public void setStatus(final long statusFlag, final boolean tpmState) throws TcTssException;


	/*************************************************************************************************
	 * This method returns random data obtained from the TPM via the TSS.
	 *
	 * @TSS_V1 131
	 *
	 * @TSS_1_2_EA 281
	 *
	 * @param length The length of the data to be requested. The maximum length of the random data is
	 *          4096.
	 * @return Random data received from the TPM.
	 *
	 *
	 */
	public TcBlobData getRandom(final long length) throws TcTssException;


	/*************************************************************************************************
	 * This methods reads a PCR register.
	 *
	 * @TSS_V1 139
	 *
	 * @TSS_1_2_EA 291
	 *
	 * @param pcrIndex Index of the PCR to read.
	 * @return The PCR data read from the TPM.
	 *
	 *
	 */
	public TcBlobData pcrRead(final long pcrIndex) throws TcTssException;


	/*************************************************************************************************
	 * This methods resets a PCR register. Whether or not is succeeds may depend on the locality
	 * executing the command. PCRs can be defined in a platform specific specification to allow reset
	 * of certain PCRs only for certain localities. The one exception is PCR 16 which can always be
	 * reset in a 1.2 implementation. This is to allow for software testing.
	 *
	 * @TSS_1_2_EA 299
	 *
	 * @param pcrComposite Indices of the PCR to read.
	 */
	public void pcrReset(final TcIPcrComposite pcrComposite) throws TcTssException;


	/*************************************************************************************************
	 * This method extends a PCR register and writes the PCR event log.
	 *
	 * If no pcrEvent parameter is supplied, the pcrEventData parameter is expected to be a SHA-1 hash
	 * that is directly extended into the specified PCR register. In this case, the provided
	 * pcrEventData value is not touched by the TSP.
	 *
	 * If however a pcrEvent is provided, then the value that is extended into the specified PCR is
	 * computed as follows: SHA-1(pcrIndex || pcrEventData || pcrEvent.eventType || pcrEvent).
	 *
	 * @TSS_V1 138
	 *
	 * @TSS_1_2_EA 289
	 *
	 * @param pcrIndex Index of the PCR to extend.
	 * @param data Data blob for the PCR extend operation.
	 * @param pcrEvent Contains the info for an event entry. If this object is null no event entry is
	 *          created and the method only executes an TPM extend operation
	 * @return Memory block containing the PCR data after the extend operation.
	 *
	 *
	 */
	public TcBlobData pcrExtend(final long pcrIndex, final TcBlobData data,
			final TcTssPcrEvent pcrEvent) throws TcTssException;


	/*************************************************************************************************
	 * This method provides a PCR event for a given PCR index and event number.
	 *
	 * @TSS_V1 134
	 *
	 * @param pcrIndex Index of the PCR to request.
	 * @param eventNumber Index of the event to request.
	 * @return PCR event data.
	 *
	 *
	 */
	public TcTssPcrEvent getEvent(final long pcrIndex, final long eventNumber) throws TcTssException;


	/*************************************************************************************************
	 * This method provides a specific number of PCR events for a given index.
	 *
	 * @TSS_V1 135
	 *
	 * @param pcrIndex Index of the PCR to request.
	 * @param startNumber Index of the first event to request.
	 * @param eventNumber Number of elements to request.
	 * @return array of PCR event data.
	 *
	 *
	 */
	public TcTssPcrEvent[] getEvents(final long pcrIndex, final long startNumber,
			final long eventNumber) throws TcTssException;


	/*************************************************************************************************
	 * This method is similar to the getEvents method. The only difference is the return value: This
	 * method returns the number of entries that would be retrieved when calling the getEvents method.
	 * This method is based on the getEvents method of the TSS where the prgPcrEvents parameter is set
	 * to 0.
	 * 此方法类似于getEvents方法。唯一的区别是返回值：这个
     * 方法返回调用getEvents方法时将检索的条目数。
     * 此方法基于设置prgPcrEvents参数的TSS的getEvents方法到0
	 *
	 * @TSS_V1 135
	 *
	 * @param pcrIndex Index of the PCR to request.
	 * @return number of events reported
	 */
	public int getEventCount(final long pcrIndex) throws TcTssException;


	/*************************************************************************************************
	 * This method provides the whole event log.
	 *
	 * @TSS_V1 136
	 *
	 * @return The event log.
	 */
	public TcTssPcrEvent[] getEventLog() throws TcTssException;


	/*************************************************************************************************
	 * This method quotes a TCG system. Which PCRs should be quoted
	 * must be set in the PcrComposite object before calling this method.<br>
	 * If structure type other than {@link TcTssConstants#TSS_PCRS_STRUCT_INFO} is used in the
	 * PcrComposite a {@link TcTssException} with error code
	 * {@link TcTssErrors#TSS_E_INVALID_OBJ_ACCESS} is thrown. The returned signature is computed over
	 * the {@link TcTpmQuoteInfo} structure.<br>
	 * 
	 * 此方法引用TCG系统。应引用哪些PCR
	 * 调用此方法之前必须在PcrComposite对象中设置。
	 * 如果在pcr用错误代码组合{@link TcTssException}
     * {@link TcTssErrors#TSS_E_INVALID_OBJ_ACCESS}被抛出。返回的签名经过计算
     * {@link TcTpmQuoteInfo}结构。
	 *
	 * @TSS_V1 137
	 *
	 * @TSS_1_2_EA 287
	 *
	 * @param identKey Signature key.
	 * @param pcrComposite PCR composite object. Will be used as input only.
	 * @param validation Provides externalData information required to compute the signature. If this
	 *          parameter is omitted (set to null), the TSP will generate external data and do the
	 *          validation.<br>
	 *          An important use of TPM_Quote is to provide a digital signature on arbitrary data,
	 *          where the signature includes the PCR values of the platform at the time of signing.
	 *          Hence, the externalData is not just for anti-replay purposes although it is used for
	 *          that purpose in an integrity challenge. If the validation parameter is omitted (set to
	 *          null), the TSP will generate anti-replay data that is validated upon receiving the
	 *          response from the TPM.
	 * @return The validation data and the data the validation data was computed from.
	 * 验证数据和用于计算验证数据的数据
	 *
	 */
	public TcTssValidation quote(final TcIRsaKey identKey, final TcIPcrComposite pcrComposite,
			final TcTssValidation validation) throws TcTssException;


	/*************************************************************************************************
	 * This method quotes a TCG system using TPM_Quote2 which provides the requestor a more complete
	 * view of the current platform configuration than TPM_Quote. The required information about which
	 * PCRs should be quoted must be set in the PcrComposite object before calling this method.<br>
	 * If structure type other than {@link TcTssConstants#TSS_PCRS_STRUCT_INFO_SHORT} is used in the
	 * PcrComposite a {@link TcTssException} with error code
	 * {@link TcTssErrors#TSS_E_INVALID_OBJ_ACCESS} is thrown. The returned signature is computed over
	 * the {@link TcTpmQuoteInfo} structure.<br>
	 *
	 * @TSS_1_2_EA 303
	 *
	 * @param identKey Signature key.
	 * @param addVersion If true, the TPM version is added to the output otherwise it is omitted.
	 * @param pcrComposite PCR composite object. Will be used as input only.
	 * @param validation Provides externalData information required to compute the signature. If this
	 *          parameter is omitted (set to null), the TSP will generate external data and do the
	 *          validation.<br>
	 *          An important use of TPM_Quote is to provide a digital signature on arbitrary data,
	 *          where the signature includes the PCR values of the platform at the time of signing.
	 *          Hence, the externalData is not just for anti-replay purposes although it is used for
	 *          that purpose in an integrity challenge. If the validation parameter is omitted (set to
	 *          null), the TSP will generate anti-replay data that is validated upon receiving the
	 *          response from the TPM.
	 * @return The returned Object[] contains the following elements:
	 *         <ul>
	 *         <li> 0 ... outgoing validation ({@link TcTssValidation}
	 *         <li> 1 ... TPM version as reported by {@link TcTpmConstants#TPM_CAP_VERSION_VAL}. If
	 *         addVersion is false, this element is null ({@link TcTpmCapVersionInfo}.
	 *         </ul>
	 *
	 *
	 */
	public Object[] quote2(final TcIRsaKey identKey, final boolean addVersion,
			final TcIPcrComposite pcrComposite, final TcTssValidation validation) throws TcTssException;


	/*************************************************************************************************
	 * This method adds entropy to the TPM Random Number Generator.
	 *
	 * @TSS_V1 132
	 *
	 * @TSS_1_2_EA 282
	 *
	 * @param entropyData The entropy data.
	 *
	 *
	 */
	public void stirRandom(final TcBlobData entropyData) throws TcTssException;


	/*************************************************************************************************
	 * This method creates the endorsement key. The key information required for creating the
	 * endorsement key must be set in the key object using
	 * {@link TcIAttributes#setAttribUint32(long, long, long)} and
	 * {@link TcIAttributes#setAttribData(long, long, TcBlobData)}
	 *
	 *
	 * @TSS_V1 108
	 *
	 * @TSS_1_2_EA 242
	 *
	 * @param key Key object specifying the attributes of the endorsement key to create.
	 * @param validationData Provides externalData information required to compute the checksum. If
	 *          the TSP should compute compute the checksum set this parameter to null.
	 *
	 * @return The validation checksum and the data the validation checksum was computed from.
	 *
	 *
	 */
	public TcTssValidation createEndorsementKey(final TcIRsaKey key,
			final TcTssValidation validationData) throws TcTssException;


	/*************************************************************************************************
	 * This method creates the revocable endorsement key. The key information required for creating the
	 * endorsement key must be set in the key object using
	 * {@link TcIAttributes#setAttribUint32(long, long, long)} and
	 * {@link TcIAttributes#setAttribData(long, long, TcBlobData)}
	 *
	 *
	 * @TSS_V1 108
	 *
	 * @TSS_1_2_EA 242
	 *
	 * @param key Key object specifying the attributes of the endorsement key to create.
	 * @param validationData Provides externalData information required to compute the checksum. If
	 *          the TSP should compute compute the checksum set this parameter to null.
	 * @param ekResetData The authorization value to be used with RevokeEndorsementKeyPair. Generated
	 *          by the TPM if null.
	 *
	 * @return The returned Object[] contains the following elements:
	 *         <ul>
	 *         <li> 0 ... validation data plus checksum {@link TcTssValidation}
	 *         <li> 1 ... authorisation value for resetting the endorsement key ({@link TcTpmNonce}
	 *         </ul>
	 *
	 *
	 */
	public Object[] createRevocableEndorsementKey(final TcIRsaKey key,
			final TcTssValidation validationData, final TcTpmNonce ekResetData) throws TcTssException;


	/*************************************************************************************************
	 * This method clears the TPM revocable endorsement key pair.
	 *
	 *
	 * @TSS_V1 108
	 *
	 * @TSS_1_2_EA 242
	 *
	 * @param ekResetData The authorization value which was set with
	 *          createRevocableEndorsementKey
	 *
	 *
	 */
	public void revokeEndorsementKey(final TcTpmNonce ekResetData) throws TcTssException;


	/*************************************************************************************************
	 * This method clears the TPM ownership. Note on using physical presence for proofing TPM
	 * ownership: As the mechanism to determine physical presence is platform dependent you have to
	 * consult the manual of your system for further information. On typical PC type platforms, a
	 * forced clear can only be done from the systems BIOS.
	 *
	 * @TSS_V1 115
	 *
	 * @TSS_1_2_EA 253
	 *
	 * @param forcedClear If FALSE, a clear ownership with proof of the TPM owner secret is done. If
	 *          TRUE, a forced clear ownership with proof of physical access is done.
	 *
	 *
	 */
	public void clearOwner(final boolean forcedClear) throws TcTssException;


	/*************************************************************************************************
	 * This method reads a Data Integrity Register.
	 *
	 * @TSS_V1 141
	 *
	 * @param dirIndex Index of the DIR to read.
	 * @return memory block containing the the DIR data.
	 *
	 *
	 */
	public TcBlobData dirRead(final long dirIndex) throws TcTssException;


	/*************************************************************************************************
	 * This method writes a Data Integrity Register.
	 *
	 * @TSS_V1 140
	 *
	 * @param dirIndex Index of the DIR to write.
	 * @param dirData data to be written to the DIR.
	 *
	 *
	 */
	public void dirWrite(final long dirIndex, final TcBlobData dirData) throws TcTssException;


	/*************************************************************************************************
	 * This method provides the capabilities of the TPM.
	 *
	 * @TSS_V1 123
	 *
	 * @TSS_1_2_EA 268
	 *
	 * @param capArea Flag indicating the attribute to query. <br>
	 *
	 * Valid capAreas are:
	 * <ul>
	 * <li> {@link TcTssConstants#TSS_TPMCAP_ORD}
	 * <li> {@link TcTssConstants#TSS_TPMCAP_FLAG}
	 * <li> {@link TcTssConstants#TSS_TPMCAP_ALG}
	 * <li> {@link TcTssConstants#TSS_TPMCAP_PROPERTY}
	 * <li> {@link TcTssConstants#TSS_TPMCAP_VERSION}
	 * <li> {@link TcTssConstants#TSS_TPMCAP_VERSION_VAL}
	 * <li> {@link TcTssConstants#TSS_TPMCAP_NV_LIST}
	 * <li> {@link TcTssConstants#TSS_TPMCAP_NV_INDEX}
	 * <li> {@link TcTssConstants#TSS_TPMCAP_MFR}
	 * <li> {@link TcTssConstants#TSS_TPMCAP_SYM_MODE}
	 * <li> {@link TcTssConstants#TSS_TPMCAP_HANDLE}
	 * <li> {@link TcTssConstants#TSS_TPMCAP_TRANS_ES}
	 * <li> {@link TcTssConstants#TSS_TPMCAP_AUTH_ENCRYPT}
	 * </ul>
	 * @param subCap Data indicating the attribute to query. <br>
	 *
	 * Valid subCaps are:
	 * <ul>
	 * <li> TcTpmOrdinals.TPM_ORD_*
	 * <li> TcTssConstants.TSS_ALG_*
	 * <li> TcTpmConstants.TPM_SYM_MODE_*
	 * <li> TcTssConstants.TSS_RT_*
	 * <li> TcTssConstants.TSS_ES_*
	 * </ul>
	 * @return data of the specified attribute
	 *
	 *
	 */
	public TcBlobData getCapability(final long capArea, final TcBlobData subCap)
		throws TcTssException;


	/*************************************************************************************************
	 * This method is an alternative to {@link TcITpm#getCapability(long, TcBlobData)}. The only
	 * difference is that the returned data is interpreted as TSS_BOOL (boolean).
	 *
	 *
	 */
	public boolean getCapabilityBoolean(final long capArea, final TcBlobData subCap)
		throws TcTssException;


	/*************************************************************************************************
	 * This method is an alternative to {@link TcITpm#getCapability(long, TcBlobData)}. The only
	 * difference is that the returned data is interpreted as UINT32 (long).
	 *
	 *
	 */
	public long getCapabilityUINT32(final long capArea, final TcBlobData subCap)
		throws TcTssException;


	/*************************************************************************************************
	 * This method is an alternative to {@link TcITpm#getCapability(long, TcBlobData)}. The only
	 * difference is that the returned data is interpreted as TSS_VERSION.
	 *
	 * Note that on 1.2 TPMs, TSS_TPMCAP_VERSION is fixed to always return 1.1.0.0. To obtain the real
	 * TPM version on a 1.2 TPM, TSS_TPMCAP_VERSION_VAL has to be used. TSS_TPMCAP_VERSION_VAL not
	 * only retrieves the version but a {@link TcTpmCapVersionInfo} structure. This method returns the
	 * version field of this structure. To obtain the full {@link TcTpmCapVersionInfo} structure, use
	 * {@link TcITpm#getCapability(long, TcBlobData)}.
	 *
	 * @param capArea Flag indicating the attribute to query <br>
	 *
	 * Valid capAreas are:
	 * <ul>
	 * <li> {@link TcTssConstants#TSS_TPMCAP_VERSION}
	 * <li> {@link TcTssConstants#TSS_TPMCAP_VERSION_VAL} (on 1.2 TPMs)
	 * </ul>
	 * @param subCap Ignored (set to null);
	 *
	 * @return The TPM version.
	 *
	 *
	 */
	public TcTssVersion getCapabilityVersion(final long capArea, final TcBlobData subCap)
		throws TcTssException;


	/*************************************************************************************************
	 * The TPM function TPM_GetCapabilitySigned that actually performs this functions was found to
	 * contain a vulnerability that makes its security questionable therefore its use unadvised.
	 *
	 * @TSS_V1 125
	 *
	 * @TSS_1_2_EA 276
	 *
	 *
	 */
	public void getCapabilitySigned() throws TcTssException;


	/*************************************************************************************************
	 * This method performs a self-test of each internal TPM function.
	 *
	 * @TSS_V1 120
	 *
	 * @TSS_1_2_EA 278
	 *
	 *
	 */
	public void selfTestFull() throws TcTssException;


	/*************************************************************************************************
	 * This method provides manufacturer specific information regarding the results of the self test.
	 *
	 * @TSS_V1 122
	 *
	 * @TSS_1_2_EA 280
	 *
	 * @return Memory block containing the TPM manufacturer specific information.
	 *
	 *
	 */
	public TcBlobData getTestResult() throws TcTssException;


	/*************************************************************************************************
	 * This method performs a self-test of each internal TPM function and returns an authenticated
	 * value (signature) if the test has passed. If the signature scheme of the provided key is not
	 * {@link TcTssConstants#TSS_SS_RSASSAPKCS1V15_SHA1}, the return value can either be a
	 * BAD_PARAMETER error or success with a vendor specific signature.
	 *
	 * @TSS_V1 121
	 *
	 * @TSS_1_2_EA 279
	 *
	 * @param key Signature key.
	 * @param validation ExternalData information required to compute the signature. If not validation
	 *          data is provided (i.e. this parameter is set to null), validation is done by the TSP.
	 * @return Validation data and the data the validation data was computed from. Calculation of hash
	 *         value for the validation data: SHA1 hash of the following three concatenated data
	 *         blobs: ("Test Passed\0" || externalData || ordinal).
	 *
	 *
	 */
	public TcTssValidation certifySelfTest(final TcIRsaKey key, final TcTssValidation validation)
		throws TcTssException;


	/*************************************************************************************************
	 * This method disables the functionality of creating a maintenance archive. After disabling the
	 * functionality of creating a maintenance archive, this functionality can only be enabled again
	 * by releasing the TPM ownership.
	 *
	 * @TSS_V1 128
	 *
	 *
	 */
	public void killMaintenanceFeature() throws TcTssException;


	/*************************************************************************************************
	 * This method loads the public maintenance key into the TPM. The maintenance public key can only
	 * be loaded once. Subsequent calls to Tspi_TPM_LoadMaintenancePubKey will fail.
	 *
	 * @TSS_V1 129
	 *
	 * @param key maintenance key object
	 * @param validationData externalData information required to compute the signature. If
	 *          validationData != NULL: The caller has to proof the digest by its own. If
	 *          validationData == NULL: The TSS Service Provider proofs the digest got from the TPM
	 *          internally.
	 * @return validation data and the data the validation data was computed from. Calculation of hash
	 *         value for the validation data: SHA1 hash of the concatenated data of <maintenance
	 *         public key>|| <externalData>
	 *
	 *
	 */
	public TcTssValidation loadMaintenancePubKey(final TcIRsaKey key,
			final TcTssValidation validationData) throws TcTssException;


	/*************************************************************************************************
	 * This method proofs the maintenance public key.
	 *
	 * @TSS_V1 129
	 *
	 * @param key maintenance key object
	 * @param validationData externalData information required to compute the signature.
	 * @return validation data and the data the validation data was computed from. Note: If validation
	 *         is not null, the state of the provided validation object is modified by this method.
	 *
	 *
	 */
	public TcTssValidation checkMaintenancePubKey(final TcIRsaKey key, TcTssValidation validationData)
		throws TcTssException;


	/*************************************************************************************************
	 * This method creates an identity key, binds it to the label and returns a certificate request
	 * package. The privacy CA requires this certificate request to attest the identity key. Only the
	 * owner of the TPM has the privilege of creating a TPM identity key.
	 *
	 * Executing this method the TSS Service Provider performs two encryptions. The first is to
	 * symmetrically encrypt the information and the second is to encrypt the symmetric encryption key
	 * with an asymmetric algorithm. The symmetric key is a random nonce and the asymmetric key is the
	 * public key of the CA that will provide the identity credential.
	 *
	 * @TSS_V1 111
	 *
	 * @TSS_1_2_EA 244
	 *
	 * @param srk object (Storage Root Key).
	 * @param caPubKey Key object holding the public key of the CA which signs the certificate of the
	 *          created identity key.
	 * @param algId Symmetric algorithm to use as required by the Privacy CA.
	 * @param identityLabel The identity label which should be a UNICODE string.
	 * @param identityKey Identity key object. The template for the identity key to be created. The
	 *          key parameters must be set up correctly when creating the key object before this
	 *          method is called..
	 *
	 * @return A blob containing the certificate request structure of type TPM_IDENTITY_REQ. This
	 *         structure holds two blob: The symBlob is encrypted with a symmetric session key. The
	 *         asymBlob holds this symmetric session key encrypted using the public key of the chosen
	 *         Privacy CA. By that it is ensured that only this Privacy CA can decrypt the request
	 *         blob.
	 *
	 *
	 */
	public TcBlobData collateIdentityRequest(final TcIRsaKey srk, final TcIRsaKey caPubKey,
			final TcBlobData identityLabel, final TcIRsaKey identityKey, final long algId)
		throws TcTssException;


	/*************************************************************************************************
	 * This method proofs the credential to be the credential of the identity key and returns the
	 * decrypted credential created by the Privacy CA for that identity.
	 *
	 * @TSS_V1 113
	 *
	 * @TSS_1_2_EA 247
	 *
	 * @param identityKey The identity key object.
	 * @param asymCaContentsBlob The blob containing the encrypted ASYM_CA_CONTENTS data structure
	 *          received from the Privacy CA.
	 * @param symCaAttestationBlob The blob containing the encrypted SYM_CA_ATTESTATION data structure
	 *          received from the Privacy CA.
	 * @return The blob containing the decrypted credential.
	 *
	 *
	 */
	public TcBlobData activateIdentity(final TcIRsaKey identityKey,
			final TcBlobData asymCaContentsBlob, final TcBlobData symCaAttestationBlob)
		throws TcTssException;


	/*************************************************************************************************
	 * This method provides the migration ticket required for the migration process.
	 *
	 * @TSS_V1 133
	 *
	 * @param migrationKey key object representing the migration key.
	 * @param migrationScheme Flag indicating the migration scheme to be used. <br>
	 *          Valid migrationSchemes are:
	 *          <ul>
	 *          <li>{@link TcTssConstants#TSS_MS_MAINT}</li>
	 *          <li>{@link TcTssConstants#TSS_MS_MIGRATE}</li>
	 *          <li>{@link TcTssConstants#TSS_MS_REWRAP}</li>
	 *          </ul>
	 * @return memory block containing the migration ticket blob.
	 *
	 *
	 */
	public TcTpmMigrationkeyAuth authorizeMigrationTicket(final TcIRsaKey migrationKey,
			final long migrationScheme) throws TcTssException;


	/*************************************************************************************************
	 * This method reads the current tick out of the TPM.
	 *
	 * @TSS_1_2_EA 373
	 *
	 * @return Current value of tick counter in the TPM
	 *
	 *
	 */
	public TcTpmCurrentTicks readCurrentTicks() throws TcTssException;


	/*************************************************************************************************
	 * This method reads the current value of the current active counter register.
	 *
	 * @TSS_1_2_EA 372
	 *
	 * @return Current value of the counter
	 *
	 *
	 */
	public TcTpmCounterValue readCurrentCounter() throws TcTssException;


	/*************************************************************************************************
	 * This method returns the public part of the SRK. Can be used to initialize the system
	 * persistent storage with the SRK without the need to take ownership again.
	 *
	 * @TSS_1_2_EA 274
	 *
	 * @return A key object containing only the public part of the storage root key (SRK).
	 */
	public TcIRsaKey OwnerGetSRKPubKey() throws TcTssException;


	/*************************************************************************************************
	 * This method is used by the owner to globally dictate the usage of a certified migration
	 * key with delegated authorization.
	 * This command can't be owner delegated.
	 *
	 * @TSS_1_2_EA 336
	 *
	 * @param cmkDelegate Bit mask to determine the restrictions on certified-migration-keys
	 *          Valid Flags are:
	 *          <ul>
	 *          <li>{@link TcTssConstants#TSS_CMK_DELEGATE_BIND}</li>
	 *          <li>{@link TcTssConstants#TSS_CMK_DELEGATE_LEGACY}</li>
	 *          <li>{@link TcTssConstants#TSS_CMK_DELEGATE_MIGRATE}</li>
	 *          <li>{@link TcTssConstants#TSS_CMK_DELEGATE_SIGNING}</li>
	 *          <li>{@link TcTssConstants#TSS_CMK_DELEGATE_STORAGE}</li>
	 *          </ul>
	 */
	public void CMKSetRestrictions(final long cmkDelegate) throws TcTssException;


	/*************************************************************************************************
	 * This method creates an authorization ticket, to allow the TPM owner to specify which Migration
	 * Authorities they approve and allow users to create certified-migration-keys without further
	 * involvement with the TPM owner.
	 *
	 * @TSS_1_2_EA 337
	 *
	 * @param maAuthData Migration data properties object to transfer the input and output data blob
	 *          during the migration process. For this command the object calculates the digest of the
	 *          selected MSA (Migration Selection Authority) which are imported into this object.
	 */
	public void CMKApproveMA(final TcIMigData maAuthData) throws TcTssException;


	/*************************************************************************************************
	 * This method uses a public key to verify the signature over a digest. The output ticket data
	 * can be used to prove the same TPM for signature verification.
	 * This operation requires owner authorization which can be delegated.
	 *
	 * @TSS_1_2_EA 338
	 *
	 * @param verifyKey The Key object containing the public key used to check the signature value.
	 * @param sigData Migration data properties object to transfer the input and output data blob
	 *          during the migration process. For this command the object includes the data proper
	 *          to be signed and the signature value to be verified. The caller can access the
	 *          ticket/signature data via GetAttribData().
	 */
	public void CMKCreateTicket(final TcIRsaKey verifyKey, final TcIMigData sigData) throws TcTssException;


	/*************************************************************************************************
	 * This function sets the operator authorization value in the TPM.
	 *
	 * @TSS_1_2_EA 259
	 *
	 * @param operatorPolicy the policy object holding the new operator authorization value.
	 */
	public void setOperatorAuth(final TcIPolicy operatorPolicy) throws TcTssException;
}
