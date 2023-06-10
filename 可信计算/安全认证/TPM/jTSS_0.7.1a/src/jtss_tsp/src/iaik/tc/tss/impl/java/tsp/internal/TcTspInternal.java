/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.impl.java.tsp.internal;


import iaik.tc.tss.api.constants.tpm.TcTpmConstants;
import iaik.tc.tss.api.constants.tpm.TcTpmOrdinals;
import iaik.tc.tss.api.constants.tsp.TcTssErrors;
import iaik.tc.tss.api.exceptions.common.TcTssException;
import iaik.tc.tss.api.exceptions.tsp.TcTspException;
import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.tss.api.structs.tcs.TcTcsAuth;
import iaik.tc.tss.api.structs.tpm.TcITpmKey;
import iaik.tc.tss.api.structs.tpm.TcITpmKeyNew;
import iaik.tc.tss.api.structs.tpm.TcITpmPcrInfo;
import iaik.tc.tss.api.structs.tpm.TcITpmStoredData;
import iaik.tc.tss.api.structs.tpm.TcTpmAuthdata;
import iaik.tc.tss.api.structs.tpm.TcTpmCapVersionInfo;
import iaik.tc.tss.api.structs.tpm.TcTpmCertifyInfo;
import iaik.tc.tss.api.structs.tpm.TcTpmCertifyInfo2;
import iaik.tc.tss.api.structs.tpm.TcTpmCmkAuth;
import iaik.tc.tss.api.structs.tpm.TcTpmCounterValue;
import iaik.tc.tss.api.structs.tpm.TcTpmCurrentTicks;
import iaik.tc.tss.api.structs.tpm.TcTpmDelegateKeyBlob;
import iaik.tc.tss.api.structs.tpm.TcTpmDelegateOwnerBlob;
import iaik.tc.tss.api.structs.tpm.TcTpmDelegatePublic;
import iaik.tc.tss.api.structs.tpm.TcTpmDigest;
import iaik.tc.tss.api.structs.tpm.TcTpmEncauth;
import iaik.tc.tss.api.structs.tpm.TcTpmKey;
import iaik.tc.tss.api.structs.tpm.TcTpmKey12;
import iaik.tc.tss.api.structs.tpm.TcTpmKeyParms;
import iaik.tc.tss.api.structs.tpm.TcTpmMigrationkeyAuth;
import iaik.tc.tss.api.structs.tpm.TcTpmMsaComposite;
import iaik.tc.tss.api.structs.tpm.TcTpmNonce;
import iaik.tc.tss.api.structs.tpm.TcTpmNvDataPublic;
import iaik.tc.tss.api.structs.tpm.TcTpmPcrComposite;
import iaik.tc.tss.api.structs.tpm.TcTpmPcrInfoLong;
import iaik.tc.tss.api.structs.tpm.TcTpmPcrInfoShort;
import iaik.tc.tss.api.structs.tpm.TcTpmPcrSelection;
import iaik.tc.tss.api.structs.tpm.TcTpmPubkey;
import iaik.tc.tss.api.structs.tpm.TcTpmSecret;
import iaik.tc.tss.api.structs.tpm.TcTpmStoredData;
import iaik.tc.tss.api.structs.tpm.TcTpmSymmetricKey;
import iaik.tc.tss.api.structs.tpm.TcTpmTransportPublic;
import iaik.tc.tss.api.structs.tpm.TcTpmVersion;
import iaik.tc.tss.api.structs.tsp.TcTssPcrEvent;
import iaik.tc.tss.impl.csp.TcCrypto;
import iaik.tc.tss.impl.java.tcs.tcsi.TcTcsi;
import iaik.tc.tss.impl.java.tsp.TcContext;
import iaik.tc.tss.impl.java.tsp.tcsbinding.TcITcsBinding;
import iaik.tc.utils.misc.CheckPrecondition;

public class TcTspInternal extends TcTspCommon {

	// ---------- key management ----------

	/*************************************************************************************************
	 *
	 *
	 */
	public static Object[] TspLoadKeyByBlob_Internal(TcContext context, long hUnwrappingKey,
			TcTpmKey wrappedKeyBlob, TcTcsAuth inAuth1, TcTpmSecret parentAuth) throws TcTssException
	{
		CheckPrecondition.notNull(context, "context");
		CheckPrecondition.notNull(wrappedKeyBlob, "wrappedKeyBlob");
		CheckPrecondition.notNull(inAuth1, "inAuth1");
		CheckPrecondition.notNull(parentAuth, "parentAuth");

		long ordinal = TcTpmOrdinals.TPM_ORD_LoadKey;

		inAuth1.setNonceOdd(TcCrypto.createTcgNonce());

		TcBlobData[] blob1H = { // 1H
		blobUINT32(ordinal), // 1S
				wrappedKeyBlob.getEncoded() }; // 2S

		TcBlobData authDataH1 = computeAuthData( //
				blob1H, // 1H1
				inAuth1, // 2H1 - 4H1
				parentAuth.getEncoded()); // HMAC key

		inAuth1.setHmac(new TcTpmAuthdata(authDataH1));

		// call to TCS
		TcITcsBinding tcs = context.getTcsBinding();
		Object[] tpmOutData = tcs.TcsipLoadKeyByBlob(context.getTcsContextHandle(), hUnwrappingKey,
				wrappedKeyBlob, inAuth1);

		// get return values
		long resultCode = ((Long) tpmOutData[0]).longValue();
		TcTcsAuth outAuth1 = (TcTcsAuth) tpmOutData[1];
		Long tcsKeyHandle = (Long) tpmOutData[2];
		Long tpmKeyHandle = (Long) tpmOutData[3];


		// validate output data
		TcBlobData[] blob1Hout = { // 1H
				blobUINT32(resultCode), // 1S
				blobUINT32(ordinal), // 2S
				blobUINT32(tpmKeyHandle.longValue()) }; // 3S

		validateRespAuth(blob1Hout, inAuth1, outAuth1, parentAuth.getEncoded());

		return new Object[] { outAuth1, tcsKeyHandle };
	}


	/*************************************************************************************************
	 *
	 *
	 */
	public static Object[] TspLoadKey2ByBlob_Internal(TcContext context, long hUnwrappingKey,
			TcITpmKey wrappedKeyBlob, TcTcsAuth inAuth1, TcTpmSecret parentAuth) throws TcTssException
	{
		CheckPrecondition.notNull(context, "context");
		CheckPrecondition.notNull(wrappedKeyBlob, "wrappedKeyBlob");
		CheckPrecondition.notNull(inAuth1, "inAuth1");
		CheckPrecondition.notNull(parentAuth, "parentAuth");

		long ordinal = TcTpmOrdinals.TPM_ORD_LoadKey2;

		inAuth1.setNonceOdd(TcCrypto.createTcgNonce());

		TcBlobData[] blob1H = { // 1H
		blobUINT32(ordinal), // 1S
				wrappedKeyBlob.getEncoded() }; // 2S

		TcBlobData authDataH1 = computeAuthData( //
				blob1H, // 1H1
				inAuth1, // 2H1 - 4H1
				parentAuth.getEncoded()); // HMAC key

		inAuth1.setHmac(new TcTpmAuthdata(authDataH1));

		// call to TCS
		TcITcsBinding tcs = context.getTcsBinding();
		Object[] tpmOutData = tcs.TcsipLoadKey2ByBlob(context.getTcsContextHandle(), hUnwrappingKey,
				wrappedKeyBlob, inAuth1);

		// get return values
		long resultCode = ((Long) tpmOutData[0]).longValue();
		TcTcsAuth outAuth1 = (TcTcsAuth) tpmOutData[1];
		Long tcsKeyHandle = (Long) tpmOutData[2];

		// validate output data
		TcBlobData[] blob1Hout = { // 1H
		blobUINT32(resultCode), // 1S
				blobUINT32(ordinal) }; // 2S

		validateRespAuth(blob1Hout, inAuth1, outAuth1, parentAuth.getEncoded());

		return new Object[] { outAuth1, tcsKeyHandle };
	}


	// ---------- credential management ----------

	/*************************************************************************************************
	 *
	 *
	 * @param context The context this call is associated with.
	 * @param identityAuth Encrypted usage AuthData for the new identity
	 * @param labelPrivCADigest The digest of the identity label and privacy CA chosen for the AIK
	 * @param idKeyParams Structure containing all parameters of new identity key. pubKey.keyLength &
	 *          idKeyParams.encData are both 0. This object may be of type TcTpmKeyNew or
	 *          TcTpmKey12New.
	 * @param inAuth1 The data for the first authorization session.
	 * @param inAuth2 The data for the second authorization session.
	 * @param srkAuth HMAC key for the first authorization session.
	 * @param ownerAuth HMAC key for the second authorization session.
	 *
	 * @return The returned Object[] holds the following elements:
	 *         <ul>
	 *         <li> 0 ... The outgoing authorization data for first session. (TcTpmAuth)
	 *         <li> 1 ... The outgoing authorization data for second session. (TcTpmAuth)
	 *         <li> 2 ... The newly created identity key. (TcTpmKey of TcTpmKey12)
	 *         <li> 3 ... Signature of TcTpmIdentityContents using idKey.private. (TcBlobData)
	 *         <li> 4 ... Endorsement Credential. (TcBlobData)
	 *         <li> 5 ... Platform Credential. (TcBlobData)
	 *         <li> 6 ... Conformance Credential. (TcBlobData)
	 *         </ul>
	 *
	 * @throws {@link TcTssException}
	 */
	public static Object[] TspMakeIdentity_Internal(TcContext context, TcTpmEncauth identityAuth,
			TcTpmDigest labelPrivCADigest, TcITpmKeyNew idKeyParams, TcTcsAuth inAuth1,
			TcTcsAuth inAuth2, TcTpmSecret srkAuth, TcTpmSecret ownerAuth) throws TcTssException
	{
		CheckPrecondition.notNull(context, "context");
		CheckPrecondition.notNull(identityAuth, "identityAuth");
		CheckPrecondition.notNull(labelPrivCADigest, "labelPrivCADigest");
		CheckPrecondition.notNull(idKeyParams, "idKeyParams");
		CheckPrecondition.notNull(inAuth1, "inAuth1");
		CheckPrecondition.notNull(inAuth2, "inAuth2");
		CheckPrecondition.notNull(srkAuth, "srkAuth");
		CheckPrecondition.notNull(ownerAuth, "ownerAuth");

		long ordinal = TcTpmOrdinals.TPM_ORD_MakeIdentity;

		inAuth1.setNonceOdd(TcCrypto.createTcgNonce());
		inAuth2.setNonceOdd(TcCrypto.createTcgNonce());

		TcBlobData[] blob1H = { // 1H
		blobUINT32(ordinal), // 1S
				identityAuth.getEncoded(), // 2S
				labelPrivCADigest.getEncoded(), // 3S
				idKeyParams.getEncoded() }; // 4S

		TcBlobData authDataH1 = computeAuthData( //
				blob1H, // 1H1
				inAuth1, // 2H1 - 4H1
				srkAuth.getEncoded()); // HMAC key

		inAuth1.setHmac(new TcTpmAuthdata(authDataH1));

		TcBlobData authDataH2 = computeAuthData( //
				blob1H, // 1H2
				inAuth2, // 2H2 - 4H2
				ownerAuth.getEncoded()); // HMAC key

		inAuth2.setHmac(new TcTpmAuthdata(authDataH2));

		// call to TCS
		TcITcsBinding tcs = context.getTcsBinding();
		Object[] outDataTpm = tcs.TcsipMakeIdentity(context.getTcsContextHandle(), identityAuth,
				labelPrivCADigest, idKeyParams, inAuth1, inAuth2);

		// get return values
		long resultCode = ((Long) outDataTpm[0]).longValue();
		TcTcsAuth outAuth1 = (TcTcsAuth) outDataTpm[1];
		TcTcsAuth outAuth2 = (TcTcsAuth) outDataTpm[2];
		TcITpmKey idKey = (TcITpmKey) outDataTpm[3];
		TcBlobData identityBinding = (TcBlobData) outDataTpm[4];
		TcBlobData endorsementCredential = (TcBlobData) outDataTpm[5];
		TcBlobData platformCredential = (TcBlobData) outDataTpm[6];
		TcBlobData conformanceCredential = (TcBlobData) outDataTpm[7];

		// validate output data
		TcBlobData[] blob1Hout = { // 1H
		blobUINT32(resultCode), // 1S
				blobUINT32(ordinal), // 2S
				idKey.getEncoded(), // 3S
				(identityBinding == null) ? null : blobUINT32(identityBinding.getLengthAsLong()), // 4S
				identityBinding }; // 5S

		validateRespAuth(blob1Hout, inAuth1, outAuth1, srkAuth.getEncoded());
		validateRespAuth(blob1Hout, inAuth2, outAuth2, ownerAuth.getEncoded());

		return new Object[] { outAuth1, outAuth2, idKey, identityBinding, endorsementCredential,
				platformCredential, conformanceCredential };
	}


	/*************************************************************************************************
	 *
	 *
	 * @param context The context this call is associated with.
	 * @param identityAuth Encrypted usage AuthData for the new identity
	 * @param labelPrivCADigest The digest of the identity label and privacy CA chosen for the AIK
	 * @param idKeyParams Structure containing all parameters of new identity key. pubKey.keyLength &
	 *          idKeyParams.encData are both 0. This object may be of type TcTpmKeyNew or
	 *          TcTpmKey12New.
	 * @param inAuth1 The data for the first authorization session.
	 * @param inAuth2 The data for the second authorization session.
	 * @param srkAuth HMAC key for the first authorization session.
	 * @param ownerAuth HMAC key for the second authorization session.
	 *
	 * @return The returned Object[] holds the following elements:
	 *         <ul>
	 *         <li> 0 ... The outgoing authorization data for first session. (TcTpmAuth)
	 *         <li> 1 ... The outgoing authorization data for second session. (TcTpmAuth)
	 *         <li> 2 ... The newly created identity key. (TcTpmKey of TcTpmKey12)
	 *         <li> 3 ... Signature of TcTpmIdentityContentsusing idKey.private. (TcBlobData)
	 *         </ul>
	 *
	 * @throws {@link TcTssException}
	 */
	public static Object[] TspMakeIdentity2_Internal(TcContext context, TcTpmEncauth identityAuth,
			TcTpmDigest labelPrivCADigest, TcITpmKeyNew idKeyParams, TcTcsAuth inAuth1,
			TcTcsAuth inAuth2, TcTpmSecret srkAuth, TcTpmSecret ownerAuth) throws TcTssException
	{
		CheckPrecondition.notNull(context, "context");
		CheckPrecondition.notNull(identityAuth, "identityAuth");
		CheckPrecondition.notNull(labelPrivCADigest, "labelPrivCADigest");
		CheckPrecondition.notNull(idKeyParams, "idKeyParams");
		CheckPrecondition.notNull(inAuth1, "inAuth1");
		CheckPrecondition.notNull(inAuth2, "inAuth2");
		CheckPrecondition.notNull(srkAuth, "srkAuth");
		CheckPrecondition.notNull(ownerAuth, "ownerAuth");

		long ordinal = TcTpmOrdinals.TPM_ORD_MakeIdentity;

		inAuth1.setNonceOdd(TcCrypto.createTcgNonce());
		inAuth2.setNonceOdd(TcCrypto.createTcgNonce());

		TcBlobData[] blob1H = { // 1H
		blobUINT32(ordinal), // 1S
				identityAuth.getEncoded(), // 2S
				labelPrivCADigest.getEncoded(), // 3S
				idKeyParams.getEncoded() }; // 4S

		TcBlobData authDataH1 = computeAuthData( //
				blob1H, // 1H1
				inAuth1, // 2H1 - 4H1
				srkAuth.getEncoded()); // HMAC key

		inAuth1.setHmac(new TcTpmAuthdata(authDataH1));

		TcBlobData authDataH2 = computeAuthData( //
				blob1H, // 1H2
				inAuth2, // 2H2 - 4H2
				ownerAuth.getEncoded()); // HMAC key

		inAuth2.setHmac(new TcTpmAuthdata(authDataH2));

		// call to TCS
		TcITcsBinding tcs = context.getTcsBinding();
		Object[] outDataTpm = tcs.TcsipMakeIdentity2(context.getTcsContextHandle(), identityAuth,
				labelPrivCADigest, idKeyParams, inAuth1, inAuth2);

		// get return values
		long resultCode = ((Long) outDataTpm[0]).longValue();
		TcTcsAuth outAuth1 = (TcTcsAuth) outDataTpm[1];
		TcTcsAuth outAuth2 = (TcTcsAuth) outDataTpm[2];
		TcITpmKey idKey = (TcITpmKey) outDataTpm[3];
		TcBlobData identityBinding = (TcBlobData) outDataTpm[4];

		// validate output data
		TcBlobData[] blob1Hout = { // 1H
		blobUINT32(resultCode), // 1S
				blobUINT32(ordinal), // 2S
				idKey.getEncoded(), // 3S
				(identityBinding == null) ? null : blobUINT32(identityBinding.getLengthAsLong()), // 4S
				identityBinding }; // 5S

		validateRespAuth(blob1Hout, inAuth1, outAuth1, srkAuth.getEncoded());
		validateRespAuth(blob1Hout, inAuth2, outAuth2, ownerAuth.getEncoded());

		return new Object[] { outAuth1, outAuth2, idKey, identityBinding };
	}


	/*************************************************************************************************
	 *
	 */
	public static Object[] TspGetCredentials_Internal(TcContext context) throws TcTssException
	{
		CheckPrecondition.notNull(context, "context");

		// call to TCS
		TcITcsBinding tcs = context.getTcsBinding();
		return tcs.TcsiGetCredentials(context.getTcsContextHandle());
	}


	// ---------- context management ----------

	public static void TspContextConnect_Internal(TcContext context, String hostname)
		throws TcTssException
	{
		CheckPrecondition.notNull(context, "context");

		// call to TCS
		TcITcsBinding tcs = context.getTcsBinding();
		tcs.connect(hostname);
	}


	public static long TspContextOpen_Internal(TcContext context) throws TcTssException
	{
		CheckPrecondition.notNull(context, "context");

		// call to TCS
		TcITcsBinding tcs = context.getTcsBinding();
		return ((Long) tcs.TcsiOpenContext()[1]).longValue();
	}


	public static void TspContextClose_Internal(TcContext context) throws TcTssException
	{
		CheckPrecondition.notNull(context, "context");

		// call to TCS
		TcITcsBinding tcs = context.getTcsBinding();
		tcs.TcsiCloseContext(context.getTcsContextHandle());
	}


	public static TcBlobData TspContextGetCapability_Internal(TcContext context, long capArea,
			TcBlobData subCap) throws TcTssException
	{
		CheckPrecondition.notNull(context, "context");

		// call to TCS
		TcITcsBinding tcs = context.getTcsBinding();
		return tcs.TcsiGetCapability(context.getTcsContextHandle(), capArea, subCap);
	}


	// ---------- event management ----------

	/*************************************************************************************************
	 * This method adds a new event to the end of the array associated with the named PCR. This
	 * command adds supporting information for the named {@link TcTssPcrEvent} event to the end of the
	 * event log. The TCS MUST maintain an array of event-supporting data with events identified by
	 * the register to which they belong and the order in which the events occurred. The log need not
	 * be in a TCG-shielded location, and the Tcsi_LogPcrEvent action need not be a TCG-protected
	 * capability.
	 *
	 * @param context Handle to established context.
	 * @param pcrEvent Details of the event being logged.
	 *
	 * @return The number of the event just logged is returned in this variable. The TCS number events
	 *         for each PCR monotonically from 0.
	 *
	 * @throws {@link TcTssException}
	 */
	public static synchronized long TspLogPcrEvent(TcContext context, TcTssPcrEvent pcrEvent)
		throws TcTssException
	{
		CheckPrecondition.notNull(context, "context");

		// call to TCS
		TcITcsBinding tcs = context.getTcsBinding();
		return tcs.TcsiLogPcrEvent(context.getTcsContextHandle(), pcrEvent);
	}


	/*************************************************************************************************
	 * This method is used to retrieve events logged with
	 * {@link TcTcsi#TcsiLogPcrEvent(long, TcTssPcrEvent)}. This method needs not to be a protected
	 * capability and the log events retrieved need not to be in a shielded location.
	 *
	 * The command retrieves events previously logged using
	 * {@link TcTcsi#TcsiLogPcrEvent(long, TcTssPcrEvent)}. The format of the data returned is
	 * identical to that previously logged. This operation retrieves log entries by PCR index and
	 * event number. On TCS initialization the event log for each PCR is empty. Then, for each PCR,
	 * the first event logged is numbered 0; the next is numbered 1, and so on. Attempts to receive
	 * log items beyond the end of the log return an error.
	 *
	 * @param context Handle to the established context.
	 * @param pcrIndex The index of the PCR.
	 * @param number The number events required. Events are numbered from 0 to the number of events
	 *          logged on the named PCR.
	 *
	 * @return TcTssPcrEvent array holding the retrieved events (the number is returned implicilty).
	 *         If no events could be retrieved an empty array is returned.
	 *
	 * @throws {@link TcTssException}
	 */
	public static synchronized TcTssPcrEvent TspGetPcrEvent(TcContext context, long pcrIndex,
			long number) throws TcTssException
	{
		CheckPrecondition.notNull(context, "context");

		// call to TCS
		TcITcsBinding tcs = context.getTcsBinding();
		return tcs.TcsiGetPcrEvent(context.getTcsContextHandle(), pcrIndex, number);
	}


	/*************************************************************************************************
	 * This method returns the number of events logged with
	 * {@link TcTcsi#TcsiLogPcrEvent(long, TcTssPcrEvent)}.
	 *
	 * @param context Handle to the established context.
	 * @param pcrIndex The index of the PCR.
	 *
	 * @return The number of elements found matching the given criteria.
	 *
	 * @throws {@link TcTssException}
	 */
	public static synchronized long TspGetPcrEventCount(TcContext context, long pcrIndex)
		throws TcTssException
	{
		CheckPrecondition.notNull(context, "context");

		// call to TCS
		TcITcsBinding tcs = context.getTcsBinding();
		return tcs.TcsiGetPcrEventCount(context.getTcsContextHandle(), pcrIndex);
	}


	/*************************************************************************************************
	 * This metho returns an event log bound to a single PCR. The event log is returned as an ordered
	 * sequence of {@link TcTssPcrEvent} structures. The caller can limit the size of the returned
	 * array using eventCount. The caller can also specify the number of the first event on the
	 * returned event log using firstEvent. This allow the caller to retrieve the event log step by
	 * step, or to retrieve a partial event log when required. The array elements are of variable
	 * size, and the {@link TcTssPcrEvent} structure defines the size of the current event and the
	 * register with which it is associated.
	 *
	 * @param context Handle to the established context.
	 * @param pcrIndex The index of the PCR.
	 * @param firstEvent The number of the first event in the returned array.
	 * @param eventCount The max number of events to returned. Set to -1 to return all events for the
	 *          PCR.
	 *
	 * @return The event array as defined by the parameters.
	 *
	 * @throws {@link TcTssException}
	 */
	public static synchronized TcTssPcrEvent[] TspGetPcrEventsByPcr(TcContext context, long pcrIndex,
			long firstEvent, long eventCount) throws TcTssException
	{
		CheckPrecondition.notNull(context, "context");

		// call to TCS
		TcITcsBinding tcs = context.getTcsBinding();
		return tcs.TcsiGetPcrEventsByPcr(context.getTcsContextHandle(), pcrIndex, firstEvent,
				eventCount);
	}


	/*************************************************************************************************
	 * This method returns the event log of all events since the TPM was initialized. The event log is
	 * returned as an ordered sequence of {@link TcTssPcrEvent} structures in the following order: all
	 * events bound to PCR 0 (in the order they have arrived), all events bound to PCR 1 (in the order
	 * they have arrived), etc. If the event log is epmpty, an empty array is returned.
	 *
	 * @param context Handle to the established context.
	 *
	 * @return Array holding all the events collected up to this point.
	 *
	 * @throws {@link TcTssException}
	 */
	public static synchronized TcTssPcrEvent[] TspGetPcrEventLog(TcContext context)
		throws TcTssException
	{
		CheckPrecondition.notNull(context, "context");

		// call to TCS
		TcITcsBinding tcs = context.getTcsBinding();
		return tcs.TcsiGetPcrEventLog(context.getTcsContextHandle());
	}


	// ---------- other methods ----------

	/*************************************************************************************************
	 * This method triggers a test of all TPM protected capabilities.
	 *
	 * @param context The context this call is associated with.
	 *
	 *
	 * @throws {@link TcTssException}
	 */
	public static void TspSelfTestFull_Internal(TcContext context) throws TcTssException
	{
		CheckPrecondition.notNull(context, "context");

		// call to TCS
		TcITcsBinding tcs = context.getTcsBinding();
		tcs.TcsipSelfTestFull(context.getTcsContextHandle());
	}


	/*************************************************************************************************
	 * This method informs the TPM that it may complete the self test of all TPM functions.
	 *
	 * @param context The context this call is associated with.
	 *
	 *
	 * @throws {@link TcTssException}
	 */
	public static void TspContinueSelfTest_Internal(TcContext context) throws TcTssException
	{
		CheckPrecondition.notNull(context, "context");

		// call to TCS
		TcITcsBinding tcs = context.getTcsBinding();
		tcs.TcsipContinueSelfTest(context.getTcsContextHandle());
	}


	/*************************************************************************************************
	 * This method provides manufacturer specific information regarding the results of the self-test.
	 * This command will work when the TPM is in self-test failure mode.
	 *
	 * @param context The context this call is associated with.
	 *
	 * @return The outData this is manufacturer specific
	 *
	 * @throws {@link TcTssException}
	 */
	public static TcBlobData TspGetTestResult_Internal(TcContext context) throws TcTssException
	{
		CheckPrecondition.notNull(context, "context");

		// call to TCS
		TcITcsBinding tcs = context.getTcsBinding();
		Object[] outDataTpm = tcs.TcsipGetTestResult(context.getTcsContextHandle());

		// get return values
		TcBlobData outData = (TcBlobData) outDataTpm[1];

		return outData;
	}


	/*************************************************************************************************
	 * This method determines if the TPM has a current owner. The TPM validates the assertion of
	 * physical access and then sets the value of TPM_PERSISTENT_FLAGS.ownership to the value in the
	 * state.
	 *
	 * @param context The context this call is associated with.
	 * @param state The state to which ownership flag is to be set.
	 *
	 * @throws {@link TcTssException}
	 */
	public static void TspSetOwnerInstall_Internal(TcContext context, boolean state)
		throws TcTssException
	{
		CheckPrecondition.notNull(context, "context");
		// call to TCS
		TcITcsBinding tcs = context.getTcsBinding();
		tcs.TcsipSetOwnerInstall(context.getTcsContextHandle(), state);
	}


	/*************************************************************************************************
	 * This method is used to change the status of the TPM_PERSISTENT_DISABLE flag.
	 *
	 * @param context The context this call is associated with.
	 * @param disableState Value for disable state - enable if TRUE
	 * @param inAuth1 The data for the authorization session.
	 * @param ownerAuth HMAC key for the authorization session.
	 *
	 * @return The outgoing authorization data for first session.
	 *
	 * @throws {@link TcTssException}
	 */
	public static TcTcsAuth TspOwnerSetDisable_Internal(TcContext context, boolean disableState,
			TcTcsAuth inAuth1, TcTpmSecret ownerAuth) throws TcTssException
	{
		CheckPrecondition.notNull(context, "context");
		CheckPrecondition.notNull(inAuth1, "inAuth1");
		CheckPrecondition.notNull(ownerAuth, "ownerAuth");

		long ordinal = TcTpmOrdinals.TPM_ORD_OwnerSetDisable;

		inAuth1.setNonceOdd(TcCrypto.createTcgNonce());

		TcBlobData[] blob1H = { // 1H
		blobUINT32(ordinal), // 1S
				blobBOOL(disableState) }; // 2S

		TcBlobData authDataH1 = computeAuthData( //
				blob1H, // 1H1
				inAuth1, // 2H1 - 4H1
				ownerAuth.getEncoded()); // HMAC key

		inAuth1.setHmac(new TcTpmAuthdata(authDataH1));

		// call to TCS
		TcITcsBinding tcs = context.getTcsBinding();
		Object[] outDataTpm = tcs.TcsipOwnerSetDisable(context.getTcsContextHandle(), disableState,
				inAuth1);

		// get return values
		long resultCode = ((Long) outDataTpm[0]).longValue();
		TcTcsAuth outAuth1 = (TcTcsAuth) outDataTpm[1];

		// validate output data
		TcBlobData[] blob1Hout = { // 1H
		blobUINT32(resultCode), // 1S
				blobUINT32(ordinal) }; // 2S

		validateRespAuth(blob1Hout, inAuth1, outAuth1, ownerAuth.getEncoded());

		return outAuth1;
	}


	/*************************************************************************************************
	 * This method enables the TPM physical presence.
	 *
	 * @param context The context this call is associated with.
	 *
	 * @throws {@link TcTssException}
	 */
	public static void TspPhysicalEnable_Internal(TcContext context) throws TcTssException
	{
		CheckPrecondition.notNull(context, "context");

		// call to TCS
		TcITcsBinding tcs = context.getTcsBinding();
		tcs.TcsipPhysicalEnable(context.getTcsContextHandle());
	}


	/*************************************************************************************************
	 * This method disables the TPM physical presence.
	 *
	 * @param context The context this call is associated with.
	 *
	 *
	 * @throws {@link TcTssException}
	 */
	public static void TspPhysicalDisable_Internal(TcContext context) throws TcTssException
	{
		CheckPrecondition.notNull(context, "context");

		// call to TCS
		TcITcsBinding tcs = context.getTcsBinding();
		tcs.TcsipPhysicalDisable(context.getTcsContextHandle());
	}


	/*************************************************************************************************
	 * This method sets the TPM_PERSITSTENT_FLAGS.deactivated flag to the value in the state
	 * parameter.
	 *
	 * @param context The context this call is associated with.
	 * @param state State to which deactivated flag is to be set.
	 *
	 *
	 * @throws {@link TcTssException}
	 */
	public static void TspPhysicalSetDeactivated_Internal(TcContext context, boolean state)
		throws TcTssException
	{
		CheckPrecondition.notNull(context, "context");

		// call to TCS
		TcITcsBinding tcs = context.getTcsBinding();
		tcs.TcsipPhysicalSetDeactivated(context.getTcsContextHandle(), state);
	}


	/*************************************************************************************************
	 * This method sets the TPM_VOLATILE_FLAGS.deactivated to the value TRUE which temporarily
	 * deactivates the TPM.
	 *
	 * @param context The context this call is associated with.
	 * @param inAuth1 The data for the authorization session.
	 * @param operatorAuth HMAC key for the authorization session.
	 *
	 * @return The outgoing authorization data for first session.
	 *
	 * @throws {@link TcTssException}
	 */
	public static TcTcsAuth TspSetTempDeactivated2_Internal(TcContext context, TcTcsAuth inAuth1,
			TcTpmSecret operatorAuth) throws TcTssException
	{
		CheckPrecondition.notNull(context, "context");
		CheckPrecondition.notNull(inAuth1, "inAuth1");
		// TODO: inAuth may be null (TempDeactivated vs. TempDeactivated2)
		CheckPrecondition.notNull(operatorAuth, "operatorAuth");

		long ordinal = TcTpmOrdinals.TPM_ORD_SetTempDeactivated;

		inAuth1.setNonceOdd(TcCrypto.createTcgNonce());

		TcBlobData[] blob1H = { // 1H
		blobUINT32(ordinal) }; // 1S

		TcBlobData authDataH1 = computeAuthData( //
				blob1H, // 1H1
				inAuth1, // 2H1 - 4H1
				operatorAuth.getEncoded()); // HMAC key

		inAuth1.setHmac(new TcTpmAuthdata(authDataH1));

		// call to TCS
		TcITcsBinding tcs = context.getTcsBinding();
		Object[] outDataTpm = tcs.TcsipSetTempDeactivated2(context.getTcsContextHandle(), inAuth1);

		// get return values
		long resultCode = ((Long) outDataTpm[0]).longValue();
		TcTcsAuth outAuth1 = (TcTcsAuth) outDataTpm[1];

		// validate output data
		TcBlobData[] blob1Hout = { // 1H
		blobUINT32(resultCode), // 1S
				blobUINT32(ordinal) }; // 2S

		validateRespAuth(blob1Hout, inAuth1, outAuth1, operatorAuth.getEncoded());

		return outAuth1;
	}


	/*************************************************************************************************
	 * This method sets the TPM_VOLATILE_FLAGS.deactivated to the value TRUE which temporarily
	 * deactivates the TPM. This command requires physical presence.
	 *
	 * @param context The context this call is associated with.
	 *
	 * @throws {@link TcTssException}
	 */
	public static void TspSetTempDeactivated_Internal(TcContext context) throws TcTssException
	{
		CheckPrecondition.notNull(context, "context");

		// call to TCS
		TcITcsBinding tcs = context.getTcsBinding();
		tcs.TcsipSetTempDeactivated(context.getTcsContextHandle());
	}


	/*************************************************************************************************
	 * Sets the operator authorization value for the platform.
	 *
	 * @param context The context this call is associated with.
	 * @param operatorAuth The operator AuthData
	 *
	 * @throws {@link TcTssException}
	 */
	public static void TspSetOperatorAuth_Internal(TcContext context, TcTpmSecret operatorAuth)
		throws TcTssException
	{
		CheckPrecondition.notNull(context, "context");
		CheckPrecondition.notNull(operatorAuth, "operatorAuth");

		// call to TCS
		TcITcsBinding tcs = context.getTcsBinding();
		tcs.TcsipSetOperatorAuth(context.getTcsContextHandle(), operatorAuth);
	}


	/*************************************************************************************************
	 * This method inserts the Owner-authorization data and creates a new Storage Root Key (SRK). This
	 * function fails if there is already a TPM owner set. After inserting the authorization data,
	 * this function creates the SRK. To validate that the operation completes successfully, The TPM
	 * HMACs the response.
	 *
	 * @param context The context this call is associated with.
	 * @param protocolID The ownership protocol in use.
	 * @param encOwnerAuth The owner AuthData encrypted with PUBEK.
	 * @param encSrkAuth The SRK AuthData encrypted with PUBEK.
	 * @param srkParams Structure containing all parameters of new SRK. pubKey.keyLength & encSize are
	 *          both 0. This structure MAY be TcTpmKey12.
	 * @param inAuth1 The data for the authorization session.
	 * @param ownerAuth HMAC key for the authorization session.
	 *
	 * @return The returned Object[] holds the following elements:
	 *         <ul>
	 *         <li> 0 ... The outgoing authorization data for first session. (TcTpmAuth)
	 *         <li> 1 ... Structure containing all parameters of new SRK. srkPub.encData is set to 0.
	 *         This structure MAY be TcTpmKey12. (TcTpmKey)
	 *         </ul>
	 *
	 * @throws {@link TcTssException}
	 */
	public static Object[] TspTakeOwnership_Internal(TcContext context, int protocolID,
			TcBlobData encOwnerAuth, TcBlobData encSrkAuth, TcITpmKeyNew srkParams, TcTcsAuth inAuth1,
			TcTpmSecret ownerAuth) throws TcTssException
	{
		CheckPrecondition.notNull(context, "context");
		CheckPrecondition.notNull(encOwnerAuth, "encOwnerAuth");
		CheckPrecondition.notNull(encSrkAuth, "encSrkAuth");
		CheckPrecondition.notNull(srkParams, "srkParams");
		CheckPrecondition.notNull(inAuth1, "inAuth1");
		CheckPrecondition.notNull(ownerAuth, "ownerAuth");

		long ordinal = TcTpmOrdinals.TPM_ORD_TakeOwnership;

		inAuth1.setNonceOdd(TcCrypto.createTcgNonce());

		TcBlobData[] blob1H = { // 1H
		blobUINT32(ordinal), // 1S
				blobUINT16(protocolID), // 2S
				blobUINT32(encOwnerAuth.getLengthAsLong()), // 3S
				encOwnerAuth, // 4S
				blobUINT32(encSrkAuth.getLengthAsLong()), // 5S
				encSrkAuth, // 6S
				srkParams.getEncoded() }; // 7S

		TcBlobData authDataH1 = computeAuthData( //
				blob1H, // 1H1
				inAuth1, // 2H1 - 4H1
				ownerAuth.getEncoded()); // HMAC key

		inAuth1.setHmac(new TcTpmAuthdata(authDataH1));

		// call to TCS
		TcITcsBinding tcs = context.getTcsBinding();
		Object[] outDataTpm = tcs.TcsipTakeOwnership(context.getTcsContextHandle(), protocolID,
				encOwnerAuth, encSrkAuth, srkParams, inAuth1);

		// get return values
		long resultCode = ((Long) outDataTpm[0]).longValue();
		TcTcsAuth outAuth1 = (TcTcsAuth) outDataTpm[1];
		TcITpmKey srkPub = (TcITpmKey) outDataTpm[2];

		// validate output data
		TcBlobData[] blob1Hout = { // 1H
		blobUINT32(resultCode), // 1S
				blobUINT32(ordinal), // 2S
				srkPub.getEncoded() }; // 3S

		validateRespAuth(blob1Hout, inAuth1, outAuth1, ownerAuth.getEncoded());

		return new Object[] { outAuth1, srkPub };
	}


	/*************************************************************************************************
	 * This command clears the TPM under owner authorization.
	 *
	 * @param context The context this call is associated with.
	 * @param inAuth1 The data for the authorization session.
	 * @param ownerAuth HMAC key for the authorization session.
	 *
	 * @return The outgoing authorization data for first session.
	 *
	 * @throws {@link TcTssException}
	 */
	public static TcTcsAuth TspOwnerClear_Internal(TcContext context, TcTcsAuth inAuth1,
			TcTpmSecret ownerAuth) throws TcTssException
	{
		CheckPrecondition.notNull(context, "context");
		CheckPrecondition.notNull(inAuth1, "inAuth1");
		CheckPrecondition.notNull(ownerAuth, "ownerAuth");

		long ordinal = TcTpmOrdinals.TPM_ORD_OwnerClear;

		inAuth1.setNonceOdd(TcCrypto.createTcgNonce());

		TcBlobData[] blob1H = { // 1H
		blobUINT32(ordinal) }; // 1S

		TcBlobData authDataH1 = computeAuthData( //
				blob1H, // 1H1
				inAuth1, // 2H1 - 4H1
				ownerAuth.getEncoded()); // HMAC key

		inAuth1.setHmac(new TcTpmAuthdata(authDataH1));

		// call to TCS
		TcITcsBinding tcs = context.getTcsBinding();
		Object[] outDataTpm = tcs.TcsipOwnerClear(context.getTcsContextHandle(), inAuth1);

		// get return values
		long resultCode = ((Long) outDataTpm[0]).longValue();
		TcTcsAuth outAuth1 = (TcTcsAuth) outDataTpm[1];

		// validate output data
		TcBlobData[] blob1Hout = { // 1H
		blobUINT32(resultCode), // 1S
				blobUINT32(ordinal) }; // 2S

		validateRespAuth(blob1Hout, inAuth1, outAuth1, ownerAuth.getEncoded());

		return outAuth1;
	}


	/*************************************************************************************************
	 * This method performs the clear operation under physical presence.
	 *
	 * @param context The context this call is associated with.
	 *
	 *
	 * @throws {@link TcTssException}
	 */
	public static void TspForceClear_Internal(TcContext context) throws TcTssException
	{
		CheckPrecondition.notNull(context, "context");

		// call to TCS
		TcITcsBinding tcs = context.getTcsBinding();
		tcs.TcsipForceClear(context.getTcsContextHandle());
	}


	/*************************************************************************************************
	 * This command disables the ability to execute the OwnerClear command permanently.
	 *
	 * @param context The context this call is associated with.
	 * @param inAuth1 The data for the authorization session.
	 * @param ownerAuth HMAC key for the authorization session.
	 *
	 * @return The outgoing authorization data for first session.
	 *
	 * @throws {@link TcTssException}
	 */
	public static TcTcsAuth TspDisableOwnerClear_Internal(TcContext context, TcTcsAuth inAuth1,
			TcTpmSecret ownerAuth) throws TcTssException
	{
		CheckPrecondition.notNull(context, "context");
		CheckPrecondition.notNull(inAuth1, "inAuth1");
		CheckPrecondition.notNull(ownerAuth, "ownerAuth");

		long ordinal = TcTpmOrdinals.TPM_ORD_DisableOwnerClear;

		inAuth1.setNonceOdd(TcCrypto.createTcgNonce());

		TcBlobData[] blob1H = { // 1H
		blobUINT32(ordinal) }; // 1S

		TcBlobData authDataH1 = computeAuthData( //
				blob1H, // 1H1
				inAuth1, // 2H1 - 4H1
				ownerAuth.getEncoded()); // HMAC key

		inAuth1.setHmac(new TcTpmAuthdata(authDataH1));

		// call to TCS
		TcITcsBinding tcs = context.getTcsBinding();
		Object[] outDataTpm = tcs.TcsipDisableOwnerClear(context.getTcsContextHandle(), inAuth1);

		// get return values
		long resultCode = ((Long) outDataTpm[0]).longValue();
		TcTcsAuth outAuth1 = (TcTcsAuth) outDataTpm[1];

		// validate output data
		TcBlobData[] blob1Hout = { // 1H
		blobUINT32(resultCode), // 1S
				blobUINT32(ordinal) }; // 2S

		validateRespAuth(blob1Hout, inAuth1, outAuth1, ownerAuth.getEncoded());

		return outAuth1;
	}


	/*************************************************************************************************
	 * This command disables the execution of the ForceClear command until next startup cycle.
	 *
	 * @param context The context this call is associated with.
	 *
	 *
	 * @throws {@link TcTssException}
	 */
	public static void TspDisableForceClear_Internal(TcContext context) throws TcTssException
	{
		CheckPrecondition.notNull(context, "context");

		// call to TCS
		TcITcsBinding tcs = context.getTcsBinding();
		tcs.TcsipDisableForceClear(context.getTcsContextHandle());
	}


	/*************************************************************************************************
	 * This method sets the physical presence flags.
	 *
	 * @param context The context this call is associated with.
	 * @param physicalPresence The state to set the TPM's PhysicalPresence flags.
	 *
	 *
	 * @throws {@link TcTssException}
	 */
	public static void TspPhysicalPresence_Internal(TcContext context, int physicalPresence)
		throws TcTssException
	{
		CheckPrecondition.notNull(context, "context");

		// call to TCS
		TcITcsBinding tcs = context.getTcsBinding();
		tcs.TcsipPhysicalPresence(context.getTcsContextHandle(), physicalPresence);
	}


	/*************************************************************************************************
	 * This method allows the TPM to report back the requestor what type of TPM it is dealing with.
	 *
	 * @param context The context this call is associated with.
	 * @param capArea Partition of capabilities to be interrogated
	 * @param subCap Further definition of information
	 *
	 * @return The capability response (TcBlobData)
	 *
	 * @throws {@link TcTssException}
	 */
	public static TcBlobData TspGetCapability_Internal(TcContext context, long capArea,
			TcBlobData subCap) throws TcTssException
	{
		CheckPrecondition.notNull(context, "context");
		// subCap can be null

		// call to TCS
		TcITcsBinding tcs = context.getTcsBinding();
		Object[] outDataTpm = tcs.TcsipGetCapability(context.getTcsContextHandle(), capArea, subCap);

		// get return values
		TcBlobData resp = (TcBlobData) outDataTpm[1];

		return resp;
	}


	/*************************************************************************************************
	 * This method allows the caller to set values in the TPM. Information about the capArea and
	 * subCap is transmitted to the TPM without any interpretation by the TCS. The TPM will return an
	 * appropriate error on wrong values.
	 *
	 * @param context The context this call is associated with.
	 * @param capArea Partition of capabilities to be set
	 * @param subCap Further definition of information
	 * @param setValue The value to set
	 * @param inAuth1 The data for the authorization session.
	 * @param ownerAuth HMAC key for the authorization session.
	 *
	 * @return The outgoing authorization data for first session.
	 *
	 * @throws {@link TcTssException}
	 */
	public static TcTcsAuth TspSetCapability_Internal(TcContext context, long capArea,
			TcBlobData subCap, TcBlobData setValue, TcTcsAuth inAuth1, TcTpmSecret ownerAuth)
		throws TcTssException
	{
		CheckPrecondition.notNull(context, "context");
		CheckPrecondition.notNull(subCap, "subCap");
		CheckPrecondition.notNull(setValue, "setValue");
		CheckPrecondition.notNull(inAuth1, "inAuth1");
		CheckPrecondition.notNull(ownerAuth, "ownerAuth");

		long ordinal = TcTpmOrdinals.TPM_ORD_SetCapability;

		inAuth1.setNonceOdd(TcCrypto.createTcgNonce());

		TcBlobData[] blob1H = { // 1H
		blobUINT32(ordinal), // 1S
				blobUINT32(capArea), // 2S
				blobUINT32(subCap.getLengthAsLong()), // 3S
				subCap, // 4S
				blobUINT32(setValue.getLengthAsLong()), // 5S
				setValue }; // 6S

		TcBlobData authDataH1 = computeAuthData( //
				blob1H, // 1H1
				inAuth1, // 2H1 - 4H1
				ownerAuth.getEncoded()); // HMAC key

		inAuth1.setHmac(new TcTpmAuthdata(authDataH1));

		// call to TCS
		TcITcsBinding tcs = context.getTcsBinding();
		Object[] outDataTpm = tcs.TcsipSetCapability(context.getTcsContextHandle(), capArea, subCap,
				setValue, inAuth1);

		// get return values
		long resultCode = ((Long) outDataTpm[0]).longValue();
		TcTcsAuth outAuth1 = (TcTcsAuth) outDataTpm[1];

		// validate output data
		TcBlobData[] blob1Hout = { // 1H
		blobUINT32(resultCode), // 1S
				blobUINT32(ordinal) }; // 2S

		validateRespAuth(blob1Hout, inAuth1, outAuth1, ownerAuth.getEncoded());

		return outAuth1;
	}


	/*************************************************************************************************
	 * This method enables the TPM owner to retrieve information belonging to the TPM owner.
	 *
	 * @param context The context this call is associated with.
	 * @param inAuth1 The data for the authorization session.
	 * @param ownerAuth HMAC key for the authorization session.
	 *
	 * @return The returned Object[] holds the following elements:
	 *         <ul>
	 *         <li> 0 ... The outgoing authorization data for first session. (TcTpmAuth)
	 *         <li> 1 ... A properly filled out version structure. (TcTpmVersion)
	 *         <li> 2 ... The current state of the non-volatile flags. (Long)
	 *         <li> 3 ... The current state of the volatile flags. (Long)
	 *         </ul>
	 *
	 * @throws {@link TcTssException}
	 */
	public static Object[] TspGetCapabilityOwner_Internal(TcContext context, TcTcsAuth inAuth1,
			TcTpmSecret ownerAuth) throws TcTssException
	{
		CheckPrecondition.notNull(context, "context");
		CheckPrecondition.notNull(inAuth1, "inAuth1");
		CheckPrecondition.notNull(ownerAuth, "ownerAuth");

		long ordinal = TcTpmOrdinals.TPM_ORD_GetCapabilityOwner;

		inAuth1.setNonceOdd(TcCrypto.createTcgNonce());

		TcBlobData[] blob1H = { // 1H
		blobUINT32(ordinal) }; // 1S

		TcBlobData authDataH1 = computeAuthData( //
				blob1H, // 1H1
				inAuth1, // 2H1 - 4H1
				ownerAuth.getEncoded()); // HMAC key

		inAuth1.setHmac(new TcTpmAuthdata(authDataH1));

		// call to TCS
		TcITcsBinding tcs = context.getTcsBinding();
		Object[] outDataTpm = tcs.TcsipGetCapabilityOwner(context.getTcsContextHandle(), inAuth1);

		// get return values
		long resultCode = ((Long) outDataTpm[0]).longValue();
		TcTcsAuth outAuth1 = (TcTcsAuth) outDataTpm[1];
		TcTpmVersion version = (TcTpmVersion) outDataTpm[2];
		Long nonVolatileFlags = (Long) outDataTpm[3];
		Long volatileFlags = (Long) outDataTpm[4];

		// validate output data
		TcBlobData[] blob1Hout = { // 1H
		blobUINT32(resultCode), // 1S
				blobUINT32(ordinal), // 2S
				version.getEncoded(), // 3S
				blobUINT32(nonVolatileFlags.longValue()), // 4S
				blobUINT32(volatileFlags.longValue()) }; // 5S

		validateRespAuth(blob1Hout, inAuth1, outAuth1, ownerAuth.getEncoded());

		return new Object[] { outAuth1, version, nonVolatileFlags, volatileFlags };
	}


	/*************************************************************************************************
	 * This method gets the digest of audited ordinals.
	 *
	 * @param context The context this call is associated with.
	 * @param startOrdinal The starting ordinal for the list of audited ordinals
	 *
	 * @return The returned Object[] holds the following elements:
	 *         <ul>
	 *         <li> 0 ... The current value of the audit monotonic counter (TcTpmCounterValue)
	 *         <li> 1 ... Log of all audited events (TcTpmDigest)
	 *         <li> 2 ... TRUE if the output does not contain a full list of audited ordinals
	 *         (Boolean)
	 *         <li> 3 ... List of ordinals that are audited. (TcBlobData)
	 *         </ul>
	 *
	 * @throws {@link TcTssException}
	 */
	public static Object[] TspGetAuditDigest_Internal(TcContext context, long startOrdinal)
		throws TcTssException
	{
		CheckPrecondition.notNull(context, "context");

		// call to TCS
		TcITcsBinding tcs = context.getTcsBinding();
		Object[] outDataTpm = tcs.TcsipGetAuditDigest(context.getTcsContextHandle(), startOrdinal);

		// remove outDataTpm[0] (the return code) from the return values
		return new Object[] { outDataTpm[1], outDataTpm[2], outDataTpm[3], outDataTpm[4] };
	}


	/*************************************************************************************************
	 * This method gets the signed digest of audited ordinals.
	 *
	 * @param context The context this call is associated with.
	 * @param keyHandle The handle of a loaded key that can perform digital signatures.
	 * @param closeAudit Indication if audit session should be closed
	 * @param antiReplay A nonce to prevent replay attacks
	 * @param inAuth1 The data for the authorization session.
	 * @param keyAuth HMAC key for the authorization session.
	 *
	 * @return The returned Object[] holds the following elements:
	 *         <ul>
	 *         <li> 0 ... The outgoing authorization data for first session. (TcTpmAuth)
	 *         <li> 1 ... The value of the audit monotonic counter (TcTpmCounterValue)
	 *         <li> 2 ... Log of all audited events (TcTpmDigest)
	 *         <li> 3 ... Digest of all audited ordinals (TcTpmDigest)
	 *         <li> 4 ... The signature of the area (TcBlobData)
	 *         </ul>
	 *
	 * @throws {@link TcTssException}
	 */
	public static Object[] TspGetAuditDigestSigned_Internal(TcContext context, long keyHandle,
			boolean closeAudit, TcTpmNonce antiReplay, TcTcsAuth inAuth1, TcTpmSecret keyAuth)
		throws TcTssException
	{
		CheckPrecondition.notNull(context, "context");
		CheckPrecondition.notNull(antiReplay, "antiReplay");
		CheckPrecondition.notNull(inAuth1, "inAuth1");
		CheckPrecondition.notNull(keyAuth, "keyAuth");

		long ordinal = TcTpmOrdinals.TPM_ORD_GetAuditDigestSigned;

		inAuth1.setNonceOdd(TcCrypto.createTcgNonce());

		TcBlobData[] blob1H = { // 1H
		blobUINT32(ordinal), // 1S
				blobBOOL(closeAudit), // 2S
				antiReplay.getEncoded() }; // 3S

		TcBlobData authDataH1 = computeAuthData( //
				blob1H, // 1H1
				inAuth1, // 2H1 - 4H1
				keyAuth.getEncoded()); // HMAC key

		inAuth1.setHmac(new TcTpmAuthdata(authDataH1));

		// call to TCS
		TcITcsBinding tcs = context.getTcsBinding();
		Object[] outDataTpm = tcs.TcsipGetAuditDigestSigned(context.getTcsContextHandle(), keyHandle,
				closeAudit, antiReplay, inAuth1);

		// get return values
		long resultCode = ((Long) outDataTpm[0]).longValue();
		TcTcsAuth outAuth1 = (TcTcsAuth) outDataTpm[1];
		TcTpmCounterValue counterValue = (TcTpmCounterValue) outDataTpm[2];
		TcTpmDigest auditDigest = (TcTpmDigest) outDataTpm[3];
		TcTpmDigest ordinalDigest = (TcTpmDigest) outDataTpm[4];
		TcBlobData sig = (TcBlobData) outDataTpm[5];

		// validate output data
		TcBlobData[] blob1Hout = { // 1H
		blobUINT32(resultCode), // 1S
				blobUINT32(ordinal), // 2S
				counterValue.getEncoded(), // 3S
				auditDigest.getEncoded(), // 4S
				ordinalDigest.getEncoded(), // 5S
				blobUINT32(sig.getLengthAsLong()), // 6S
				sig }; // 7S

		validateRespAuth(blob1Hout, inAuth1, outAuth1, keyAuth.getEncoded());

		return new Object[] { outAuth1, counterValue, auditDigest, ordinalDigest, sig };
	}


	/*************************************************************************************************
	 * This command sets the audit flag for a given ordinal. This command requires owner
	 * authorization.
	 *
	 * @param context The context this call is associated with.
	 * @param ordinalToAudit The ordinal whose audit flag is to be set.
	 * @param auditState Value for audit flag.
	 * @param inAuth1 The data for the authorization session.
	 * @param ownerAuth HMAC key for the authorization session.
	 *
	 * @return The outgoing authorization data for first session.
	 *
	 * @throws {@link TcTssException}
	 */
	public static TcTcsAuth TspSetOrdinalAuditStatus_Internal(TcContext context, long ordinalToAudit,
			boolean auditState, TcTcsAuth inAuth1, TcTpmSecret ownerAuth) throws TcTssException
	{
		CheckPrecondition.notNull(context, "context");
		CheckPrecondition.notNull(inAuth1, "inAuth1");
		CheckPrecondition.notNull(ownerAuth, "ownerAuth");

		long ordinal = TcTpmOrdinals.TPM_ORD_SetOrdinalAuditStatus;

		inAuth1.setNonceOdd(TcCrypto.createTcgNonce());

		TcBlobData[] blob1H = { // 1H
		blobUINT32(ordinal), // 1S
				blobUINT32(ordinalToAudit), // 2S
				blobBOOL(auditState) }; // 3S

		TcBlobData authDataH1 = computeAuthData( //
				blob1H, // 1H1
				inAuth1, // 2H1 - 4H1
				ownerAuth.getEncoded()); // HMAC key

		inAuth1.setHmac(new TcTpmAuthdata(authDataH1));

		// call to TCS
		TcITcsBinding tcs = context.getTcsBinding();
		Object[] outDataTpm = tcs.TcsipSetOrdinalAuditStatus(context.getTcsContextHandle(), inAuth1,
				ordinalToAudit, auditState);

		// get return values
		long resultCode = ((Long) outDataTpm[0]).longValue();
		TcTcsAuth outAuth1 = (TcTcsAuth) outDataTpm[1];

		// validate output data
		TcBlobData[] blob1Hout = { // 1H
		blobUINT32(resultCode), // 1S
				blobUINT32(ordinal) }; // 2S

		validateRespAuth(blob1Hout, inAuth1, outAuth1, ownerAuth.getEncoded());

		return outAuth1;
	}


	/*************************************************************************************************
	 * This command is vendor specific. It allows vendors to upgrade TPMs that are already in the
	 * field.
	 *
	 * @param context The context this call is associated with.
	 * @param inData Vendor specific data blob with upgrade information.
	 * @param inAuth1 The data for the authorization session.
	 * @param ownerAuth HMAC key for the authorization session.
	 *
	 * @return Vendor specific return blob.
	 *
	 * @throws {@link TcTssException}
	 */
	public TcTcsAuth FieldUpgrade(TcContext context, TcBlobData inData, TcTcsAuth inAuth1,
			TcTpmSecret ownerAuth) throws TcTssException
	{
		CheckPrecondition.notNull(context, "context");
		CheckPrecondition.notNull(inData, "inData");
		CheckPrecondition.notNull(inAuth1, "inAuth1");
		CheckPrecondition.notNull(ownerAuth, "ownerAuth");

		long ordinal = TcTpmOrdinals.TPM_ORD_FieldUpgrade;

		inAuth1.setNonceOdd(TcCrypto.createTcgNonce());

		TcBlobData[] blob1H = { // 1H
		blobUINT32(ordinal), // 1S
				blobUINT32(inData.getLengthAsLong()), // 2S
				inData }; // 3S

		TcBlobData authDataH1 = computeAuthData( //
				blob1H, // 1H1
				inAuth1, // 2H1 - 4H1
				ownerAuth.getEncoded()); // HMAC key

		inAuth1.setHmac(new TcTpmAuthdata(authDataH1));

		// call to TCS
		TcITcsBinding tcs = context.getTcsBinding();
		Object[] outDataTpm = tcs.TcsipFieldUpgrade(context.getTcsContextHandle(), inData, inAuth1);

		// get return values
		long resultCode = ((Long) outDataTpm[0]).longValue();
		TcTcsAuth outAuth1 = (TcTcsAuth) outDataTpm[1];

		// validate output data
		TcBlobData[] blob1Hout = { // 1H
		blobUINT32(resultCode), // 1S
				blobUINT32(ordinal) }; // 2S

		validateRespAuth(blob1Hout, inAuth1, outAuth1, ownerAuth.getEncoded());

		return outAuth1;
	}


	/*************************************************************************************************
	 * Redirected keys enable the output of a TPM to be directed to non-TCG security functions in the
	 * platform, without exposing that output to non-security functions. It sometimes is desirable to
	 * direct the TPM's output to specific platform functions without exposing that output to other
	 * platform functions. To enable this, the key in a leaf node of the TCG protected storage can be
	 * tagged as a "redirected" key. Any plaintext output data secured by a redirected key is passed
	 * by the TPM directly to specific platform functions and is not interpreted by the TPM. Since
	 * redirection can only affect leaf keys, redirection applies to: Unbind, Unseal, Quote and Sign.
	 *
	 * @param context The context this call is associated with.
	 * @param keyHandle The keyHandle identifier of a loaded key that can implement redirection.
	 * @param redirCmd The command to execute
	 * @param inputData Manufacturer parameter
	 * @param inAuth1 The data for the authorization session.
	 * @param ownerAuth HMAC key for the authorization session.
	 *
	 * @return The outgoing authorization data for first session.
	 *
	 * @throws {@link TcTssException}
	 */
	public static TcTcsAuth TspSetRedirection_Internal(TcContext context, long keyHandle,
			long redirCmd, TcBlobData inputData, TcTcsAuth inAuth1, TcTpmSecret ownerAuth)
		throws TcTssException
	{
		CheckPrecondition.notNull(context, "context");
		CheckPrecondition.notNull(inputData, "inputData");
		CheckPrecondition.notNull(inAuth1, "inAuth1");
		CheckPrecondition.notNull(ownerAuth, "ownerAuth");

		long ordinal = TcTpmOrdinals.TPM_ORD_SetRedirection;

		inAuth1.setNonceOdd(TcCrypto.createTcgNonce());

		TcBlobData[] blob1H = { // 1H
		blobUINT32(ordinal), // 1S
				blobUINT32(redirCmd), // 2S
				blobUINT32(inputData.getLengthAsLong()), // 3S
				inputData }; // 4S

		TcBlobData authDataH1 = computeAuthData( //
				blob1H, // 1H1
				inAuth1, // 2H1 - 4H1
				ownerAuth.getEncoded()); // HMAC key

		inAuth1.setHmac(new TcTpmAuthdata(authDataH1));

		// call to TCS
		TcITcsBinding tcs = context.getTcsBinding();
		Object[] outDataTpm = tcs.TcsipSetRedirection(context.getTcsContextHandle(), keyHandle,
				redirCmd, inputData, inAuth1);

		// get return values
		long resultCode = ((Long) outDataTpm[0]).longValue();
		TcTcsAuth outAuth1 = (TcTcsAuth) outDataTpm[1];

		// validate output data
		TcBlobData[] blob1Hout = { // 1H
		blobUINT32(resultCode), // 1S
				blobUINT32(ordinal) }; // 2S

		validateRespAuth(blob1Hout, inAuth1, outAuth1, ownerAuth.getEncoded());

		return outAuth1;
	}


	/*************************************************************************************************
	 * Resets the lock that get set in a TPM after multiple false authorization attempts. This is used
	 * to prevent hammering attacks. This command requires owner authorization.
	 *
	 * @param context The context this call is associated with.
	 * @param inAuth1 The data for the authorization session.
	 * @param ownerAuth HMAC key for the authorization session.
	 *
	 * @return The outgoing authorization data for first session.
	 *
	 * @throws {@link TcTssException}
	 */
	public static TcTcsAuth TspResetLockValue_Internal(TcContext context, TcTcsAuth inAuth1,
			TcTpmSecret ownerAuth) throws TcTssException
	{
		CheckPrecondition.notNull(context, "context");
		CheckPrecondition.notNull(inAuth1, "inAuth1");
		CheckPrecondition.notNull(ownerAuth, "ownerAuth");

		long ordinal = TcTpmOrdinals.TPM_ORD_ResetLockValue;

		inAuth1.setNonceOdd(TcCrypto.createTcgNonce());

		TcBlobData[] blob1H = { // 1H
		blobUINT32(ordinal) }; // 1S

		TcBlobData authDataH1 = computeAuthData( //
				blob1H, // 1H1
				inAuth1, // 2H1 - 4H1
				ownerAuth.getEncoded()); // HMAC key

		inAuth1.setHmac(new TcTpmAuthdata(authDataH1));

		// call to TCS
		TcITcsBinding tcs = context.getTcsBinding();
		Object[] outDataTpm = tcs.TcsipResetLockValue(context.getTcsContextHandle(), inAuth1);

		// get return values
		long resultCode = ((Long) outDataTpm[0]).longValue();
		TcTcsAuth outAuth1 = (TcTcsAuth) outDataTpm[1];

		// validate output data
		TcBlobData[] blob1Hout = { // 1H
		blobUINT32(resultCode), // 1S
				blobUINT32(ordinal) }; // 2S

		validateRespAuth(blob1Hout, inAuth1, outAuth1, ownerAuth.getEncoded());

		return outAuth1;
	}


	/*************************************************************************************************
	 * This method allows software to explicitly state the future trusted configuration that the
	 * platform must be in for the secret to be revealed. The seal operation also implicitly includes
	 * the relevant platform configuration when the seal operation was performed.
	 *
	 * @param context The context this call is associated with.
	 * @param keyHandle Handle of a loaded key that can perform seal operations.
	 * @param encAuth The encrypted AuthData for the sealed data.
	 * @param pcrInfo The PCR selection information. The caller MAY use TcTpmPcrInfoLong.
	 * @param inData The data to be sealed to the platform and any specified PCRs
	 * @param inAuth1 The data for the authorization session.
	 * @param pubAuth HMAC key for the authorization session.
	 *
	 * @return The returned Object[] holds the following elements:
	 *         <ul>
	 *         <li> 0 ... The outgoing authorization data for first session. (TcTpmAuth)
	 *         <li> 1 ... Encrypted, integrity-protected data object that is the result of the
	 *         TPM_Seal operation. (TcTpmStoredData)
	 *         </ul>
	 *
	 * @throws {@link TcTssException}
	 */
	public static Object[] TspSeal_Internal(TcContext context, long keyHandle, TcTpmEncauth encAuth,
			TcITpmPcrInfo pcrInfo, TcBlobData inData, TcTcsAuth inAuth1, TcTpmSecret pubAuth)
		throws TcTssException
	{
		CheckPrecondition.notNull(context, "context");
		CheckPrecondition.notNull(encAuth, "encAuth");
		// pcrInfo can be null
		CheckPrecondition.notNull(inData, "inData");
		CheckPrecondition.notNull(inAuth1, "inAuth1");
		CheckPrecondition.notNull(pubAuth, "pubAuth");

		long ordinal = TcTpmOrdinals.TPM_ORD_Seal;

		inAuth1.setNonceOdd(TcCrypto.createTcgNonce());

		TcBlobData[] blob1H = null;
		if (pcrInfo == null) {
			TcBlobData[] tmp = { // 1H
			blobUINT32(ordinal), // 1S
					encAuth.getEncoded(), // 2S
					blobUINT32(0), // 3S
					blobUINT32(inData.getLengthAsLong()), // 5S
					inData }; // 6S
			blob1H = tmp;
		} else {
			TcBlobData[] tmp = { // 1H
			blobUINT32(ordinal), // 1S
					encAuth.getEncoded(), // 2S
					blobUINT32(pcrInfo.getEncoded().getLengthAsLong()), // 3S
					pcrInfo.getEncoded(), // 4S
					blobUINT32(inData.getLengthAsLong()), // 5S
					inData }; // 6S
			blob1H = tmp;
		}

		TcBlobData authDataH1 = computeAuthData( //
				blob1H, // 1H1
				inAuth1, // 2H1 - 4H1
				pubAuth.getEncoded()); // HMAC key

		inAuth1.setHmac(new TcTpmAuthdata(authDataH1));

		// call to TCS
		TcITcsBinding tcs = context.getTcsBinding();
		Object[] outDataTpm = tcs.TcsipSeal(context.getTcsContextHandle(), keyHandle, encAuth, pcrInfo,
				inData, inAuth1);

		// get return values
		long resultCode = ((Long) outDataTpm[0]).longValue();
		TcTcsAuth outAuth1 = (TcTcsAuth) outDataTpm[1];
		TcITpmStoredData sealedData = (TcITpmStoredData) outDataTpm[2];

		// validate output data
		TcBlobData[] blob1Hout = { // 1H
		blobUINT32(resultCode), // 1S
				blobUINT32(ordinal), // 2S
				sealedData.getEncoded() }; // 3S

		validateRespAuth(blob1Hout, inAuth1, outAuth1, pubAuth.getEncoded());

		return new Object[] { outAuth1, sealedData };
	}


	/*************************************************************************************************
	 * This method will reveal sealed data only if it was encrypted on this platform and the current
	 * configuration (defined by the named PCRs) is the one named as qualified to decrypt it. It
	 * decrypts the structure internally, checks the integrity of the resulting data and checks that
	 * the PCR named has the value named during TcsipSeal. Additionally, the caller must supply
	 * appropriate authorization data for the blob and the key that was used to seal that data.
	 *
	 * @param context The context this call is associated with.
	 * @param parentHandle Handle of a loaded key that can unseal the data.
	 * @param inData The encrypted data generated by TPM_Seal.
	 * @param inAuth1 The data for the first authorization session.
	 * @param inAuth2 The data for the second authorization session.
	 * @param parentAuth HMAC key for the first authorization session.
	 * @param dataAuth HMAC key for the second authorization session.
	 *
	 * @return The returned Object[] holds the following elements:
	 *         <ul>
	 *         <li> 0 ... The outgoing authorization data for first session. (TcTpmAuth)
	 *         <li> 1 ... The outgoing authorization data for second session. (TcTpmAuth)
	 *         <li> 2 ... Decrypted data that had been sealed (TcBlobData)
	 *         </ul>
	 *
	 * @throws {@link TcTssException}
	 */
	public static Object[] TspUnseal_Internal(TcContext context, long parentHandle,
			TcITpmStoredData inData, TcTcsAuth inAuth1, TcTcsAuth inAuth2, TcTpmSecret parentAuth,
			TcTpmSecret dataAuth) throws TcTssException
	{
		CheckPrecondition.notNull(context, "context");
		CheckPrecondition.notNull(inData, "inData");
		CheckPrecondition.notNull(inAuth1, "inAuth1");
		CheckPrecondition.notNull(inAuth2, "inAuth2");
		CheckPrecondition.notNull(parentAuth, "parentAuth");
		CheckPrecondition.notNull(dataAuth, "dataAuth");

		long ordinal = TcTpmOrdinals.TPM_ORD_Unseal;

		inAuth1.setNonceOdd(TcCrypto.createTcgNonce());
		inAuth2.setNonceOdd(TcCrypto.createTcgNonce());

		TcBlobData[] blob1H = { // 1H
		blobUINT32(ordinal), // 1S
				inData.getEncoded() }; // 2S

		TcBlobData authDataH1 = computeAuthData( //
				blob1H, // 1H1
				inAuth1, // 2H1 - 4H1
				parentAuth.getEncoded()); // HMAC key

		inAuth1.setHmac(new TcTpmAuthdata(authDataH1));

		TcBlobData authDataH2 = computeAuthData( //
				blob1H, // 1H2
				inAuth2, // 2H2 - 4H2
				dataAuth.getEncoded()); // HMAC key

		inAuth2.setHmac(new TcTpmAuthdata(authDataH2));

		// call to TCS
		TcITcsBinding tcs = context.getTcsBinding();
		Object[] outDataTpm = tcs.TcsipUnseal(context.getTcsContextHandle(), parentHandle, inData,
				inAuth1, inAuth2);

		// get return values
		long resultCode = ((Long) outDataTpm[0]).longValue();
		TcTcsAuth outAuth1 = (TcTcsAuth) outDataTpm[1];
		TcTcsAuth outAuth2 = (TcTcsAuth) outDataTpm[2];
		TcBlobData secret = (TcBlobData) outDataTpm[3];

		// validate output data
		TcBlobData[] blob1Hout = { // 1H
		blobUINT32(resultCode), // 1S
				blobUINT32(ordinal), // 2S
				blobUINT32(secret.getLengthAsLong()), // 3S
				secret }; // 4S

		validateRespAuth(blob1Hout, inAuth1, outAuth1, parentAuth.getEncoded());
		validateRespAuth(blob1Hout, inAuth2, outAuth2, dataAuth.getEncoded());

		return new Object[] { outAuth1, outAuth2, secret };
	}


	/*************************************************************************************************
	 * This method takes the data blob that is the result of a bind command and decrypts it for export
	 * to the user. The caller must authorize the use of the key that will decrypt the incoming blob.
	 *
	 * @param context The context this call is associated with.
	 * @param keyHandle The keyHandle identifier of a loaded key that can perform UnBindoperations.
	 * @param inData Encrypted blob to be decrypted
	 * @param inAuth1 The data for the authorization session.
	 * @param privAuth HMAC key for the authorization session.
	 *
	 * @return The returned Object[] holds the following elements:
	 *         <ul>
	 *         <li> 0 ... The outgoing authorization data for first session. (TcTpmAuth)
	 *         <li> 1 ... The resulting decrypted data. (TcBlobData)
	 *         </ul>
	 *
	 * @throws {@link TcTssException}
	 */
	public static Object[] TspUnBind_Internal(TcContext context, long keyHandle, TcBlobData inData,
			TcTcsAuth inAuth1, TcTpmSecret privAuth) throws TcTssException
	{
		CheckPrecondition.notNull(context, "context");
		CheckPrecondition.notNull(inData, "inData");
		CheckPrecondition.notNull(inAuth1, "inAuth1");
		CheckPrecondition.notNull(privAuth, "privAuth");

		long ordinal = TcTpmOrdinals.TPM_ORD_UnBind;

		inAuth1.setNonceOdd(TcCrypto.createTcgNonce());

		TcBlobData[] blob1H = { // 1H
		blobUINT32(ordinal), // 1S
				blobUINT32(inData.getLengthAsLong()), // 2S
				inData }; // 3S

		TcBlobData authDataH1 = computeAuthData( //
				blob1H, // 1H1
				inAuth1, // 2H1 - 4H1
				privAuth.getEncoded()); // HMAC key

		inAuth1.setHmac(new TcTpmAuthdata(authDataH1));

		// call to TCS
		TcITcsBinding tcs = context.getTcsBinding();
		Object[] outDataTpm = tcs
				.TcsipUnBind(context.getTcsContextHandle(), keyHandle, inData, inAuth1);

		// get return values
		long resultCode = ((Long) outDataTpm[0]).longValue();
		TcTcsAuth outAuth1 = (TcTcsAuth) outDataTpm[1];
		TcBlobData outData = (TcBlobData) outDataTpm[2];

		// validate output data
		TcBlobData[] blob1Hout = { // 1H
		blobUINT32(resultCode), // 1S
				blobUINT32(ordinal), // 2S
				blobUINT32(outData.getLengthAsLong()), // 3S
				outData }; // 4S

		validateRespAuth(blob1Hout, inAuth1, outAuth1, privAuth.getEncoded());

		return new Object[] { outAuth1, outData };
	}


	/*************************************************************************************************
	 *
	 *
	 * @param context The context this call is associated with.
	 * @param parentHandle Handle of a loaded key that can perform key wrapping.
	 * @param dataUsageAuth Encrypted usage AuthData for the sealed data.
	 * @param dataMigrationAuth Encrypted migration AuthData for the sealed data.
	 * @param keyInfo Information about key to be created, pubKey.keyLength and keyInfo.encData
	 *          elements are 0. MAY be TcTpmKey12
	 * @param inAuth1 The data for the authorization session.
	 * @param pubAuth HMAC key for the authorization session.
	 *
	 * @return The returned Object[] holds the following elements:
	 *         <ul>
	 *         <li> 0 ... The outgoing authorization data for first session. (TcTpmAuth)
	 *         <li> 1 ... The TPM_KEY structure which includes the public and encrypted private key.
	 *         MAY be TcTpmKey12 (TcTpmKey)
	 *         </ul>
	 *
	 * @throws {@link TcTssException}
	 */
	public static Object[] TspCreateWrapKey_Internal(TcContext context, long parentHandle,
			TcTpmEncauth dataUsageAuth, TcTpmEncauth dataMigrationAuth, TcITpmKeyNew keyInfo,
			TcTcsAuth inAuth1, TcTpmSecret pubAuth) throws TcTssException
	{
		CheckPrecondition.notNull(context, "context");
		CheckPrecondition.notNull(dataUsageAuth, "dataUsageAuth");
		CheckPrecondition.notNull(dataMigrationAuth, "dataMigrationAuth");
		CheckPrecondition.notNull(keyInfo, "keyInfo");
		CheckPrecondition.notNull(inAuth1, "inAuth1");
		CheckPrecondition.notNull(pubAuth, "pubAuth");

		long ordinal = TcTpmOrdinals.TPM_ORD_CreateWrapKey;

		// Note: nonceOdd is used for the XOR key for the migrationAuth. Therefore, it typically is
		// set already by the caller. Consequently, the nonceOdd is not set here in this case.
		if (inAuth1.getNonceOdd() == null) {
			inAuth1.setNonceOdd(TcCrypto.createTcgNonce());
		}

		TcBlobData[] blob1H = { // 1H
		blobUINT32(ordinal), // 1S
				dataUsageAuth.getEncoded(), // 2S
				dataMigrationAuth.getEncoded(), // 3S
				keyInfo.getEncoded() }; // 4S

		TcBlobData authDataH1 = computeAuthData( //
				blob1H, // 1H1
				inAuth1, // 2H1 - 4H1
				pubAuth.getEncoded()); // HMAC key

		inAuth1.setHmac(new TcTpmAuthdata(authDataH1));

		// call to TCS
		TcITcsBinding tcs = context.getTcsBinding();
		Object[] outDataTpm = tcs.TcsipCreateWrapKey(context.getTcsContextHandle(), parentHandle,
				dataUsageAuth, dataMigrationAuth, keyInfo, inAuth1);

		// get return values
		long resultCode = ((Long) outDataTpm[0]).longValue();
		TcTcsAuth outAuth1 = (TcTcsAuth) outDataTpm[1];
		TcITpmKey wrappedKey = (TcITpmKey) outDataTpm[2];

		// validate output data
		TcBlobData[] blob1Hout = { // 1H
		blobUINT32(resultCode), // 1S
				blobUINT32(ordinal), // 2S
				wrappedKey.getEncoded() }; // 4S

		validateRespAuth(blob1Hout, inAuth1, outAuth1, pubAuth.getEncoded());

		return new Object[] { outAuth1, wrappedKey };
	}


	// /*************************************************************************************************
	// *
	// *
	// * @param context The context this call is associated with.
	// * @param parentHandle TPM handle of parent key.
	// * @param inKey Incoming key structure, both encrypted private and clear public portions. MAY be
	// * TcTpmKey12
	// * @param inAuth1 The data for the authorization session.
	// * @param parentAuth HMAC key for the authorization session.
	// *
	// * @return The returned Object[] holds the following elements:
	// * <ul>
	// * <li> 0 ... The outgoing authorization data for first session. (TcTpmAuth)
	// * <li> 1 ... Internal TPM handle where decrypted key was loaded. (Long)
	// * </ul>
	// *
	// * @throws {@link TcTssException}
	// */
	// public static Object[] TspLoadKey2_Internal(TcContext context, long
	// parentHandle,
	// TcTpmKey inKey, TcTpmAuth inAuth1, TcTpmSecret parentAuth)
	// throws TcTpmCallException, TcTcsException, TcTddlException
	// {
	// CheckPrecondition.notNull(context, "context");
	// CheckPrecondition.notNull(inKey, "inKey");
	// CheckPrecondition.notNull(inAuth1, "inAuth1");
	// CheckPrecondition.notNull(parentAuth, "parentAuth");
	//
	// long ordinal = TcTpmOrdinals.TPM_ORD_LoadKey2;
	//
	// inAuth1.setNonceOdd(TcCrypto.createTcgNonce());
	//
	// TcBlobData[] blob1H = { // 1H
	// blobUINT32(ordinal), // 1S
	// inKey.getEncoded() }; // 2S
	//
	// TcBlobData authDataH1 = computeAuthData( //
	// blob1H, // 1H1
	// inAuth1, // 2H1 - 4H1
	// parentAuth.getEncoded()); // HMAC key
	//
	// inAuth1.setHmac(new TcTpmAuthdata(authDataH1));
	//
	// // call to TCS
	// TcITcsBinding tcs = context.getTcsBinding();
	// Object[] outDataTpm = tcs.TcsLoadKey2(context.getTcsContextHandle(), parentHandle, inKey,
	// inAuth1);
	//
	// // get return values
	// long resultCode = ((Long) outDataTpm[0]).longValue();
	// TcTpmAuth outAuth1 = (TcTpmAuth) outDataTpm[1];
	// Long inkeyHandle = (Long) outDataTpm[2];
	//
	// // validate output data
	// TcBlobData[] blob1Hout = { // 1H
	// blobUINT32(resultCode), // 1S
	// blobUINT32(ordinal) }; // 2S
	//
	// validateRespAuth(blob1Hout, inAuth1, outAuth1, parentAuth.getEncoded());
	//
	// return new Object[] { outAuth1, inkeyHandle };
	// }

	/*************************************************************************************************
	 *
	 *
	 * @param context The context this call is associated with.
	 * @param keyHandle TPM handle of key.
	 * @param inAuth1 The data for the authorization session.
	 * @param keyAuth HMAC key for the authorization session.
	 *
	 * @return The returned Object[] holds the following elements:
	 *         <ul>
	 *         <li> 0 ... The outgoing authorization data for first session. (TcTpmAuth)
	 *         <li> 1 ... Public portion of key in keyHandle. (TcTpmPubkey)
	 *         </ul>
	 *
	 * @throws {@link TcTssException}
	 */
	public static Object[] TspGetPubKey_Internal(TcContext context, long keyHandle,
			TcTcsAuth inAuth1, TcTpmSecret keyAuth) throws TcTssException
	{
		CheckPrecondition.notNull(context, "context");
		CheckPrecondition.notNull(inAuth1, "inAuth1");
		CheckPrecondition.notNull(keyAuth, "keyAuth");

		long ordinal = TcTpmOrdinals.TPM_ORD_GetPubKey;

		inAuth1.setNonceOdd(TcCrypto.createTcgNonce());

		TcBlobData[] blob1H = { // 1H
		blobUINT32(ordinal) }; // 1S

		TcBlobData authDataH1 = computeAuthData( //
				blob1H, // 1H1
				inAuth1, // 2H1 - 4H1
				keyAuth.getEncoded()); // HMAC key

		inAuth1.setHmac(new TcTpmAuthdata(authDataH1));

		// call to TCS
		TcITcsBinding tcs = context.getTcsBinding();
		Object[] outDataTpm = tcs.TcsipGetPubKey(context.getTcsContextHandle(), keyHandle, inAuth1);

		// get return values
		long resultCode = ((Long) outDataTpm[0]).longValue();
		TcTcsAuth outAuth1 = (TcTcsAuth) outDataTpm[1];
		TcTpmPubkey pubKey = (TcTpmPubkey) outDataTpm[2];

		// validate output data
		TcBlobData[] blob1Hout = { // 1H
		blobUINT32(resultCode), // 1S
				blobUINT32(ordinal), // 2S
				pubKey.getEncoded() }; // 3S

		validateRespAuth(blob1Hout, inAuth1, outAuth1, keyAuth.getEncoded());

		return new Object[] { outAuth1, pubKey };
	}


	/*************************************************************************************************
	 * This method allows software to explicitly state the future trusted configuration that the
	 * platform must be in for the secret to be revealed. It also includes the relevant platform
	 * configuration when the SealX command was performed.
	 *
	 * @param context The context this call is associated with.
	 * @param keyHandle Handle of a loaded key that can perform seal operations.
	 * @param encAuth The encrypted AuthData for the sealed data.
	 * @param pcrInfo MUST use TcTpmPcrInfoLong.
	 * @param inData The data to be sealed to the platform and any specified PCRs
	 * @param inAuth1 The data for the authorization session.
	 * @param pubAuth HMAC key for the authorization session.
	 *
	 * @return The returned Object[] holds the following elements:
	 *         <ul>
	 *         <li> 0 ... The outgoing authorization data for first session. (TcTpmAuth)
	 *         <li> 1 ... Encrypted, integrity-protected data object that is the result of the
	 *         TPM_Sealx operation. (TcTpmStoredData(12))
	 *         </ul>
	 *
	 * @throws {@link TcTssException}
	 */
	public static Object[] TspSealx_Internal(TcContext context, long keyHandle, TcTpmEncauth encAuth,
			TcTpmPcrInfoLong pcrInfo, TcBlobData inData, TcTcsAuth inAuth1, TcTpmSecret pubAuth)
		throws TcTssException
	{
		CheckPrecondition.notNull(context, "context");
		CheckPrecondition.notNull(encAuth, "encAuth");
		CheckPrecondition.notNull(pcrInfo, "pcrInfo");
		CheckPrecondition.notNull(inData, "inData");
		CheckPrecondition.notNull(inAuth1, "inAuth1");
		CheckPrecondition.notNull(pubAuth, "pubAuth");

		long ordinal = TcTpmOrdinals.TPM_ORD_Sealx;

		inAuth1.setNonceOdd(TcCrypto.createTcgNonce());

		TcBlobData[] blob1H = { // 1H
		blobUINT32(ordinal), // 1S
				encAuth.getEncoded(), // 2S
				blobUINT32(pcrInfo.getEncoded().getLengthAsLong()), // 3S
				pcrInfo.getEncoded(), // 4S
				blobUINT32(inData.getLengthAsLong()), // 5S
				inData }; // 6S

		TcBlobData authDataH1 = computeAuthData( //
				blob1H, // 1H1
				inAuth1, // 2H1 - 4H1
				pubAuth.getEncoded()); // HMAC key

		inAuth1.setHmac(new TcTpmAuthdata(authDataH1));

		// call to TCS
		TcITcsBinding tcs = context.getTcsBinding();
		Object[] outDataTpm = tcs.TcsipSealx(context.getTcsContextHandle(), keyHandle, encAuth,
				pcrInfo, inData, inAuth1);

		// get return values
		long resultCode = ((Long) outDataTpm[0]).longValue();
		TcTcsAuth outAuth1 = (TcTcsAuth) outDataTpm[1];
		TcTpmStoredData sealedData = (TcTpmStoredData) outDataTpm[2];

		// validate output data
		TcBlobData[] blob1Hout = { // 1H
		blobUINT32(resultCode), // 1S
				blobUINT32(ordinal), // 2S
				sealedData.getEncoded() }; // 3S

		validateRespAuth(blob1Hout, inAuth1, outAuth1, pubAuth.getEncoded());

		return new Object[] { outAuth1, sealedData };
	}


	/*************************************************************************************************
	 * This method implements the first step in the process of moving a migratable key to a new parent
	 * key or platform. Execution of this command requires knowledge of the migrationAuth field of the
	 * key to be migrated.
	 *
	 * @param context The context this call is associated with.
	 * @param parentHandle Handle of the parent key that can decrypt encData.
	 * @param migrationType The migration type, either MIGRATE or REWRAP.
	 * @param migrationKeyAuth Migration public key and its authorization session digest.
	 * @param encData The encrypted entity that is to be modified.
	 * @param inAuth1 The data for the first authorization session.
	 * @param inAuth2 The data for the second authorization session.
	 * @param parentAuth HMAC key for the first authorization session.
	 * @param entityAuth HMAC key for the second authorization session.
	 *
	 * @return The returned Object[] holds the following elements:
	 *         <ul>
	 *         <li> 0 ... The outgoing authorization data for first session. (TcTpmAuth)
	 *         <li> 1 ... The outgoing authorization data for second session. (TcTpmAuth)
	 *         <li> 2 ... String used for XOR encryption (TcBlobData)
	 *         <li> 3 ... The modified, encrypted entity. (TcBlobData)
	 *         </ul>
	 *
	 * @throws {@link TcTssException}
	 */
	public static Object[] TspCreateMigrationBlob_Internal(TcContext context, long parentHandle,
			int migrationType, TcTpmMigrationkeyAuth migrationKeyAuth, TcBlobData encData,
			TcTcsAuth inAuth1, TcTcsAuth inAuth2, TcTpmSecret parentAuth, TcTpmSecret entityAuth)
		throws TcTssException
	{
		CheckPrecondition.notNull(context, "context");
		CheckPrecondition.notNull(migrationKeyAuth, "migrationKeyAuth");
		CheckPrecondition.notNull(encData, "encData");
		CheckPrecondition.notNull(inAuth1, "inAuth1");
		CheckPrecondition.notNull(inAuth2, "inAuth2");
		CheckPrecondition.notNull(parentAuth, "parentAuth");
		CheckPrecondition.notNull(entityAuth, "entityAuth");

		long ordinal = TcTpmOrdinals.TPM_ORD_CreateMigrationBlob;

		inAuth1.setNonceOdd(TcCrypto.createTcgNonce());
		inAuth2.setNonceOdd(TcCrypto.createTcgNonce());

		TcBlobData[] blob1H = { // 1H
		blobUINT32(ordinal), // 1S
				blobUINT16(migrationType), // 2S
				migrationKeyAuth.getEncoded(), // 3S
				blobUINT32(encData.getLengthAsLong()), // 4S
				encData }; // 5S

		TcBlobData authDataH1 = computeAuthData( //
				blob1H, // 1H1
				inAuth1, // 2H1 - 4H1
				parentAuth.getEncoded()); // HMAC key

		inAuth1.setHmac(new TcTpmAuthdata(authDataH1));

		TcBlobData authDataH2 = computeAuthData( //
				blob1H, // 1H2
				inAuth2, // 2H2 - 4H2
				entityAuth.getEncoded()); // HMAC key

		inAuth2.setHmac(new TcTpmAuthdata(authDataH2));

		// call to TCS
		TcITcsBinding tcs = context.getTcsBinding();
		Object[] outDataTpm = tcs.TcsipCreateMigrationBlob(context.getTcsContextHandle(), parentHandle,
				migrationType, migrationKeyAuth, encData, inAuth1, inAuth2);

		// get return values
		long resultCode = ((Long) outDataTpm[0]).longValue();
		TcTcsAuth outAuth1 = (TcTcsAuth) outDataTpm[1];
		TcTcsAuth outAuth2 = (TcTcsAuth) outDataTpm[2];
		TcBlobData random = (TcBlobData) outDataTpm[3];
		TcBlobData outData = (TcBlobData) outDataTpm[4];

		// validate output data
		TcBlobData[] blob1Hout;
		if (random != null) { // migrationType == MIGRATE
			TcBlobData[] tmpBlob1Hout = { // 1H
					blobUINT32(resultCode), // 1S
					blobUINT32(ordinal), // 2S
					blobUINT32(random.getLengthAsLong()), // 3S
					random, // 4S
					blobUINT32(outData.getLengthAsLong()), // 5S
					outData }; // 6S
			blob1Hout = tmpBlob1Hout;
		} else { // migrationType == REWRAP
			TcBlobData[] tmpBlob1Hout = { // 1H
					blobUINT32(resultCode), // 1S
					blobUINT32(ordinal), // 2S
					blobUINT32(0), // 3S
					blobUINT32(outData.getLengthAsLong()), // 5S
					outData }; // 6S
			blob1Hout = tmpBlob1Hout;
		}

		validateRespAuth(blob1Hout, inAuth1, outAuth1, parentAuth.getEncoded());
		validateRespAuth(blob1Hout, inAuth2, outAuth2, entityAuth.getEncoded());

		return new Object[] { outAuth1, outAuth2, random, outData };
	}


	/*************************************************************************************************
	 * This method takes a migration blob and creates a normal wrapped blob. The migrated blob must be
	 * loaded into the TPM using the normal LoadKey function.
	 *
	 * @param context The context this call is associated with.
	 * @param parentHandle Handle of a loaded key that can decrypt keys.
	 * @param inData The XOR'd and encrypted key.
	 * @param random Random value used to hide key data.
	 * @param inAuth1 The data for the authorization session.
	 * @param parentAuth HMAC key for the authorization session.
	 *
	 * @return The returned Object[] holds the following elements:
	 *         <ul>
	 *         <li> 0 ... The outgoing authorization data for first session. (TcTpmAuth)
	 *         <li> 1 ... The encrypted private key that can be loaded with TPM_LoadKey (TcBlobData)
	 *         </ul>
	 *
	 * @throws {@link TcTssException}
	 */
	public static Object[] TspConvertMigrationBlob_Internal(TcContext context, long parentHandle,
			TcBlobData inData, TcBlobData random, TcTcsAuth inAuth1, TcTpmSecret parentAuth)
		throws TcTssException
	{
		CheckPrecondition.notNull(context, "context");
		CheckPrecondition.notNull(inData, "inData");
		CheckPrecondition.notNull(random, "random");
		CheckPrecondition.notNull(inAuth1, "inAuth1");
		CheckPrecondition.notNull(parentAuth, "parentAuth");

		long ordinal = TcTpmOrdinals.TPM_ORD_ConvertMigrationBlob;

		inAuth1.setNonceOdd(TcCrypto.createTcgNonce());

		TcBlobData[] blob1H = { // 1H
		blobUINT32(ordinal), // 1S
				blobUINT32(inData.getLengthAsLong()), // 2S
				inData, // 3S
				blobUINT32(random.getLengthAsLong()), // 4S
				random }; // 5S

		TcBlobData authDataH1 = computeAuthData( //
				blob1H, // 1H1
				inAuth1, // 2H1 - 4H1
				parentAuth.getEncoded()); // HMAC key

		inAuth1.setHmac(new TcTpmAuthdata(authDataH1));

		// call to TCS
		TcITcsBinding tcs = context.getTcsBinding();
		Object[] outDataTpm = tcs.TcsipConvertMigrationBlob(context.getTcsContextHandle(),
				parentHandle, inData, random, inAuth1);

		// get return values
		long resultCode = ((Long) outDataTpm[0]).longValue();
		TcTcsAuth outAuth1 = (TcTcsAuth) outDataTpm[1];
		TcBlobData outData = (TcBlobData) outDataTpm[2];

		// validate output data
		TcBlobData[] blob1Hout = { // 1H
		blobUINT32(resultCode), // 1S
				blobUINT32(ordinal), // 2S
				blobUINT32(outData.getLengthAsLong()), // 3S
				outData }; // 4S

		validateRespAuth(blob1Hout, inAuth1, outAuth1, parentAuth.getEncoded());

		return new Object[] { outAuth1, outData };
	}


	/*************************************************************************************************
	 * This method creates an authorization blob to allow the TPM owner to specify which migration
	 * facility they will use and allow users to migrate information without further involvement with
	 * the TPM owner.
	 *
	 * @param context The context this call is associated with.
	 * @param migrationScheme Type of migration operation that is to be permitted for this key.
	 * @param migrationKey The public key to be authorized.
	 * @param inAuth1 The data for the authorization session.
	 * @param ownerAuth HMAC key for the authorization session.
	 *
	 * @return The returned Object[] holds the following elements:
	 *         <ul>
	 *         <li> 0 ... The outgoing authorization data for first session. (TcTpmAuth)
	 *         <li> 1 ... Returned public key and authorization session digest.
	 *         (TcTpmMigrationkeyAuth)
	 *         </ul>
	 *
	 * @throws {@link TcTssException}
	 */
	public static Object[] TspAuthorizeMigrationKey_Internal(TcContext context, int migrationScheme,
			TcTpmPubkey migrationKey, TcTcsAuth inAuth1, TcTpmSecret ownerAuth) throws TcTssException
	{
		CheckPrecondition.notNull(context, "context");
		CheckPrecondition.notNull(migrationKey, "migrationKey");
		CheckPrecondition.notNull(inAuth1, "inAuth1");
		CheckPrecondition.notNull(ownerAuth, "ownerAuth");

		long ordinal = TcTpmOrdinals.TPM_ORD_AuthorizeMigrationKey;

		inAuth1.setNonceOdd(TcCrypto.createTcgNonce());

		TcBlobData[] blob1H = { // 1H
		blobUINT32(ordinal), // 1S
				blobUINT16(migrationScheme), // 2S
				migrationKey.getEncoded() }; // 3S

		TcBlobData authDataH1 = computeAuthData( //
				blob1H, // 1H1
				inAuth1, // 2H1 - 4H1
				ownerAuth.getEncoded()); // HMAC key

		inAuth1.setHmac(new TcTpmAuthdata(authDataH1));

		// call to TCS
		TcITcsBinding tcs = context.getTcsBinding();
		Object[] outDataTpm = tcs.TcsipAuthorizeMigrationKey(context.getTcsContextHandle(),
				migrationScheme, migrationKey, inAuth1);

		// get return values
		long resultCode = ((Long) outDataTpm[0]).longValue();
		TcTcsAuth outAuth1 = (TcTcsAuth) outDataTpm[1];
		TcTpmMigrationkeyAuth outData = (TcTpmMigrationkeyAuth) outDataTpm[2];

		// validate output data
		TcBlobData[] blob1Hout = { // 1H
		blobUINT32(resultCode), // 1S
				blobUINT32(ordinal), // 2S
				outData.getEncoded() }; // 3S

		validateRespAuth(blob1Hout, inAuth1, outAuth1, ownerAuth.getEncoded());

		return new Object[] { outAuth1, outData };
	}


	/*************************************************************************************************
	 * This method performs the function of a migration authority. THis command is used to permit a
	 * TPM enabled system to be a migration authority. To prevent execution of this command using any
	 * other key as a parent key, this TPM operation works only if the keyUsage for the macKey is
	 * TPM_KEY_MIGRATABLE.
	 *
	 * @param context The context this call is associated with.
	 * @param maKeyHandle Handle of the key to be used to migrate the key.
	 * @param pubKey Public key to which the blob is to be migrated
	 * @param inData The input blob
	 * @param inAuth1 The data for the authorization session.
	 * @param keyAuth HMAC key for the authorization session.
	 *
	 * @return The returned Object[] holds the following elements:
	 *         <ul>
	 *         <li> 0 ... The outgoing authorization data for first session. (TcTpmAuth)
	 *         <li> 1 ... The re-encrypted blob (TcBlobData)
	 *         </ul>
	 *
	 * @throws {@link TcTssException}
	 */
	public static Object[] TspMigrateKey_Internal(TcContext context, long maKeyHandle,
			TcTpmPubkey pubKey, TcBlobData inData, TcTcsAuth inAuth1, TcTpmSecret keyAuth)
		throws TcTssException
	{
		CheckPrecondition.notNull(context, "context");
		CheckPrecondition.notNull(pubKey, "pubKey");
		CheckPrecondition.notNull(inData, "inData");
		CheckPrecondition.notNull(inAuth1, "inAuth1");
		CheckPrecondition.notNull(keyAuth, "keyAuth");

		long ordinal = TcTpmOrdinals.TPM_ORD_MigrateKey;

		inAuth1.setNonceOdd(TcCrypto.createTcgNonce());

		TcBlobData[] blob1H = { // 1H
		blobUINT32(ordinal), // 1S
				pubKey.getEncoded(), // 2S
				blobUINT32(inData.getLengthAsLong()), // 3S
				inData }; // 4S

		TcBlobData authDataH1 = computeAuthData( //
				blob1H, // 1H1
				inAuth1, // 2H1 - 4H1
				keyAuth.getEncoded()); // HMAC key

		inAuth1.setHmac(new TcTpmAuthdata(authDataH1));

		// call to TCS
		TcITcsBinding tcs = context.getTcsBinding();
		Object[] outDataTpm = tcs.TcsipMigrateKey(context.getTcsContextHandle(), maKeyHandle, pubKey,
				inData, inAuth1);

		// get return values
		long resultCode = ((Long) outDataTpm[0]).longValue();
		TcTcsAuth outAuth1 = (TcTcsAuth) outDataTpm[1];
		TcBlobData outData = (TcBlobData) outDataTpm[2];

		// validate output data
		TcBlobData[] blob1Hout = { // 1H
		blobUINT32(resultCode), // 1S
				blobUINT32(ordinal), // 2S
				blobUINT32(outData.getLengthAsLong()), // 3S
				outData }; // 4S

		validateRespAuth(blob1Hout, inAuth1, outAuth1, keyAuth.getEncoded());

		return new Object[] { outAuth1, outData };
	}


	/*************************************************************************************************
	 * This command is used by the owner to order the usage of a CMK with delegated authorization.
	 *
	 * @param context The context this call is associated with.
	 * @param restriction The bit mask of how to set the restrictions on CMK keys
	 * @param inAuth1 The data for the authorization session.
	 * @param ownerAuth HMAC key for the authorization session.
	 *
	 * @return The outgoing authorization data for first session.
	 *
	 * @throws {@link TcTssException}
	 */
	public static TcTcsAuth TspCmkSetRestrictions_Internal(TcContext context, long restriction,
			TcTcsAuth inAuth1, TcTpmSecret ownerAuth) throws TcTssException
	{
		CheckPrecondition.notNull(context, "context");
		CheckPrecondition.notNull(inAuth1, "inAuth1");
		CheckPrecondition.notNull(ownerAuth, "ownerAuth");

		long ordinal = TcTpmOrdinals.TPM_ORD_CMK_SetRestrictions;

		inAuth1.setNonceOdd(TcCrypto.createTcgNonce());

		TcBlobData[] blob1H = { // 1H
		blobUINT32(ordinal), // 1S
				blobUINT32(restriction) }; // 2S

		TcBlobData authDataH1 = computeAuthData( //
				blob1H, // 1H1
				inAuth1, // 2H1 - 4H1
				ownerAuth.getEncoded()); // HMAC key

		inAuth1.setHmac(new TcTpmAuthdata(authDataH1));

		// call to TCS
		TcITcsBinding tcs = context.getTcsBinding();
		Object[] outDataTpm = tcs.TcsipCmkSetRestrictions(context.getTcsContextHandle(), restriction,
				inAuth1);

		// get return values
		long resultCode = ((Long) outDataTpm[0]).longValue();
		TcTcsAuth outAuth1 = (TcTcsAuth) outDataTpm[1];

		// validate output data
		TcBlobData[] blob1Hout = { // 1H
		blobUINT32(resultCode), // 1S
				blobUINT32(ordinal) }; // 2S

		validateRespAuth(blob1Hout, inAuth1, outAuth1, ownerAuth.getEncoded());

		return outAuth1;
	}


	/*************************************************************************************************
	 * This command is used to create an authorization ticket, to allow the TPM owner to
	 * specify/select one or more migration authorities they approve and allow user to generate CMKs
	 * without further involvement of the owner.
	 *
	 * @param context The context this call is associated with.
	 * @param migrationAuthorityDigest A digest of a TcTpmMsaComposite structure (itself one or more
	 *          digests of public keys belonging to migration authorities)
	 * @param inAuth1 The data for the authorization session.
	 * @param ownerAuth HMAC key for the authorization session.
	 *
	 * @return The returned Object[] holds the following elements:
	 *         <ul>
	 *         <li> 0 ... The outgoing authorization data for first session. (TcTpmAuth)
	 *         <li> 1 ... HMAC of migrationAuthorityDigest (TcTpmDigest)
	 *         </ul>
	 *
	 * @throws {@link TcTssException}
	 */
	public static Object[] TspCmkApproveMA_Internal(TcContext context,
			TcTpmDigest migrationAuthorityDigest, TcTcsAuth inAuth1, TcTpmSecret ownerAuth)
		throws TcTssException
	{
		CheckPrecondition.notNull(context, "context");
		CheckPrecondition.notNull(migrationAuthorityDigest, "migrationAuthorityDigest");
		CheckPrecondition.notNull(inAuth1, "inAuth1");
		CheckPrecondition.notNull(ownerAuth, "ownerAuth");

		long ordinal = TcTpmOrdinals.TPM_ORD_CMK_ApproveMA;

		inAuth1.setNonceOdd(TcCrypto.createTcgNonce());

		TcBlobData[] blob1H = { // 1H
		blobUINT32(ordinal), // 1S
				migrationAuthorityDigest.getEncoded() }; // 2S

		TcBlobData authDataH1 = computeAuthData( //
				blob1H, // 1H1
				inAuth1, // 2H1 - 4H1
				ownerAuth.getEncoded()); // HMAC key

		inAuth1.setHmac(new TcTpmAuthdata(authDataH1));

		// call to TCS
		TcITcsBinding tcs = context.getTcsBinding();
		Object[] outDataTpm = tcs.TcsipCmkApproveMA(context.getTcsContextHandle(),
				migrationAuthorityDigest, inAuth1);

		// get return values
		long resultCode = ((Long) outDataTpm[0]).longValue();
		TcTcsAuth outAuth1 = (TcTcsAuth) outDataTpm[1];
		TcTpmDigest outData = (TcTpmDigest) outDataTpm[2];

		// validate output data
		TcBlobData[] blob1Hout = { // 1H
		blobUINT32(resultCode), // 1S
				blobUINT32(ordinal), // 2S
				outData.getEncoded() }; // 3S

		validateRespAuth(blob1Hout, inAuth1, outAuth1, ownerAuth.getEncoded());

		return new Object[] { outAuth1, outData };
	}


	/*************************************************************************************************
	 * This command both generates and creates a secure storage bundle for asymmetric keys whose
	 * migration is controlled/restricted by a migration authority. Only this command can be used to
	 * create these kind of keys.
	 *
	 * @param context The context this call is associated with.
	 * @param parentHandle Handle of a loaded key that can perform key wrapping.
	 * @param dataUsageAuth Encrypted usage AuthData for the sealed data.
	 * @param keyInfo Information about key to be created, pubKey.keyLength and keyInfo.encData
	 *          elements are 0. MUST be TcTpmKey12
	 * @param migrationAuthorityApproval A ticket, created by the TPM Owner using TPM_CMK_ApproveMA,
	 *          approving a TcTpmMsaComposite structure
	 * @param migrationAuthorityDigest The digest of a TcTpmMsaComposite structure
	 * @param inAuth1 The data for the authorization session.
	 * @param pubAuth HMAC key for the authorization session.
	 *
	 * @return The returned Object[] holds the following elements:
	 *         <ul>
	 *         <li> 0 ... The outgoing authorization data for first session. (TcTpmAuth)
	 *         <li> 1 ... The TcTpmKey structure which includes the public and encrypted private key.
	 *         MUST be TcTpmKey12 (TcTpmKey12)
	 *         </ul>
	 *
	 * @throws {@link TcTssException}
	 */
	public static Object[] TspCmkCreateKey_Internal(TcContext context, long parentHandle,
			TcTpmEncauth dataUsageAuth, TcTpmKey12 keyInfo, TcTpmDigest migrationAuthorityApproval,
			TcTpmDigest migrationAuthorityDigest, TcTcsAuth inAuth1, TcTpmSecret pubAuth)
		throws TcTssException
	{
		CheckPrecondition.notNull(context, "context");
		CheckPrecondition.notNull(dataUsageAuth, "dataUsageAuth");
		CheckPrecondition.notNull(keyInfo, "keyInfo");
		CheckPrecondition.notNull(migrationAuthorityApproval, "migrationAuthorityApproval");
		CheckPrecondition.notNull(migrationAuthorityDigest, "migrationAuthorityDigest");
		CheckPrecondition.notNull(inAuth1, "inAuth1");
		CheckPrecondition.notNull(pubAuth, "pubAuth");

		long ordinal = TcTpmOrdinals.TPM_ORD_CMK_CreateKey;

		inAuth1.setNonceOdd(TcCrypto.createTcgNonce());

		TcBlobData[] blob1H = { // 1H
		blobUINT32(ordinal), // 1S
				dataUsageAuth.getEncoded(), // 2S
				keyInfo.getEncoded(), // 3S
				migrationAuthorityApproval.getEncoded(), // 4S
				migrationAuthorityDigest.getEncoded() }; // 5S

		TcBlobData authDataH1 = computeAuthData( //
				blob1H, // 1H1
				inAuth1, // 2H1 - 4H1
				pubAuth.getEncoded()); // HMAC key

		inAuth1.setHmac(new TcTpmAuthdata(authDataH1));

		// call to TCS
		TcITcsBinding tcs = context.getTcsBinding();
		Object[] outDataTpm = tcs.TcsipCmkCreateKey(context.getTcsContextHandle(), parentHandle,
				dataUsageAuth, migrationAuthorityApproval, migrationAuthorityDigest, keyInfo, inAuth1);

		// get return values
		long resultCode = ((Long) outDataTpm[0]).longValue();
		TcTcsAuth outAuth1 = (TcTcsAuth) outDataTpm[1];
		TcTpmKey12 wrappedKey = (TcTpmKey12) outDataTpm[2];

		// validate output data
		TcBlobData[] blob1Hout = { // 1H
		blobUINT32(resultCode), // 1S
				blobUINT32(ordinal), // 2S
				wrappedKey.getEncoded() }; // 3S

		validateRespAuth(blob1Hout, inAuth1, outAuth1, pubAuth.getEncoded());

		return new Object[] { outAuth1, wrappedKey };
	}


	/*************************************************************************************************
	 * This owner controlled command uses a public key to verify the signature over a digest.
	 *
	 * @param context The context this call is associated with.
	 * @param verificationKey The public key to be used to check signatureValue
	 * @param signedData The data to be verified
	 * @param signatureValue The signatureValue to be verified
	 * @param inAuth1 The data for the authorization session.
	 * @param pubAuth HMAC key for the authorization session.
	 *
	 * @return The returned Object[] holds the following elements:
	 *         <ul>
	 *         <li> 0 ... The outgoing authorization data for first session. (TcTpmAuth)
	 *         <li> 1 ... Ticket that proves digest created on this TPM (TcTpmDigest)
	 *         </ul>
	 *
	 * @throws {@link TcTssException}
	 */
	public static Object[] TspCMK_CreateTicket_Internal(TcContext context,
			TcTpmPubkey verificationKey, TcTpmDigest signedData, TcBlobData signatureValue,
			TcTcsAuth inAuth1, TcTpmSecret pubAuth) throws TcTssException
	{
		CheckPrecondition.notNull(context, "context");
		CheckPrecondition.notNull(verificationKey, "verificationKey");
		CheckPrecondition.notNull(signedData, "signedData");
		CheckPrecondition.notNull(signatureValue, "signatureValue");
		CheckPrecondition.notNull(inAuth1, "inAuth1");
		CheckPrecondition.notNull(pubAuth, "pubAuth");

		long ordinal = TcTpmOrdinals.TPM_ORD_CMK_CreateTicket;

		inAuth1.setNonceOdd(TcCrypto.createTcgNonce());

		TcBlobData[] blob1H = { // 1H
		blobUINT32(ordinal), // 1S
				verificationKey.getEncoded(), // 2S
				signedData.getEncoded(), // 3S
				blobUINT32(signatureValue.getLengthAsLong()), // 4S
				signatureValue }; // 5S

		TcBlobData authDataH1 = computeAuthData( //
				blob1H, // 1H1
				inAuth1, // 2H1 - 4H1
				pubAuth.getEncoded()); // HMAC key

		inAuth1.setHmac(new TcTpmAuthdata(authDataH1));

		// call to TCS
		TcITcsBinding tcs = context.getTcsBinding();
		Object[] outDataTpm = tcs.TcsipCmkCreateTicket(context.getTcsContextHandle(), verificationKey,
				signedData, signatureValue, inAuth1);

		// get return values
		long resultCode = ((Long) outDataTpm[0]).longValue();
		TcTcsAuth outAuth1 = (TcTcsAuth) outDataTpm[1];
		TcTpmDigest sigTicket = (TcTpmDigest) outDataTpm[2];

		// validate output data
		TcBlobData[] blob1Hout = { // 1H
		blobUINT32(resultCode), // 1S
				blobUINT32(ordinal), // 2S
				sigTicket.getEncoded() }; // 3S

		validateRespAuth(blob1Hout, inAuth1, outAuth1, pubAuth.getEncoded());

		return new Object[] { outAuth1, sigTicket };
	}


	/*************************************************************************************************
	 * This command is similar to TcspiCreateMigrationBlob, except that it uses migration authority
	 * data whose migration data are independent from tpmProof. It is possible for the parameter
	 * restrictTicket to be null.
	 *
	 * @param context The context this call is associated with.
	 * @param parentHandle Handle of the parent key that can decrypt encData.
	 * @param migrationType The migration type, either TPM_MS_RESTRICT_MIGRATE or
	 *          TPM_MS_RESTRICT_APPROVE_DOUBLE
	 * @param migrationKeyAuth Migration public key and its authorization session digest.
	 * @param pubSourceKeyDigest The digest of the TcTpmPubkey of the entity to be migrated
	 * @param msaList One or more digests of public keys belonging to migration authorities
	 * @param restrictTicket Either a NULL parameter or a TcTpmCmkAuth structure, containing the
	 *          digests of the public keys belonging to the Migration Authority, the destination
	 *          parent key and the key-to-be-migrated.
	 * @param sigTicket Either a NULL parameter or a TcTpmDigest structure, generated by the TPM,
	 *          signaling a valid signature over restrictTicket
	 * @param encData The encrypted entity that is to be modified.
	 * @param inAuth1 The data for the authorization session.
	 * @param parentAuth HMAC key for the authorization session.
	 *
	 * @return The returned Object[] holds the following elements:
	 *         <ul>
	 *         <li> 0 ... The outgoing authorization data for first session. (TcTpmAuth)
	 *         <li> 1 ... String used for XOR encryption (TcBlobData)
	 *         <li> 2 ... The modified, encrypted entity. (TcBlobData)
	 *         </ul>
	 *
	 * @throws {@link TcTssException}
	 */
	public static Object[] TspCmkCreateBlob_Internal(TcContext context, long parentHandle,
			int migrationType, TcTpmMigrationkeyAuth migrationKeyAuth, TcTpmDigest pubSourceKeyDigest,
			TcTpmMsaComposite msaList, TcBlobData restrictTicket, TcBlobData sigTicket,
			TcBlobData encData, TcTcsAuth inAuth1, TcTpmSecret parentAuth) throws TcTssException
	{
		CheckPrecondition.notNull(context, "context");
		CheckPrecondition.notNull(migrationKeyAuth, "migrationKeyAuth");
		CheckPrecondition.notNull(pubSourceKeyDigest, "pubSourceKeyDigest");
		CheckPrecondition.notNull(msaList, "msaList");
		// restrictTicket can be null
		CheckPrecondition.notNull(sigTicket, "sigTicket");
		CheckPrecondition.notNull(encData, "encData");
		CheckPrecondition.notNull(inAuth1, "inAuth1");
		CheckPrecondition.notNull(parentAuth, "parentAuth");

		long ordinal = TcTpmOrdinals.TPM_ORD_CMK_CreateBlob;

		inAuth1.setNonceOdd(TcCrypto.createTcgNonce());

		TcBlobData[] blob1H = null;
		if (restrictTicket == null) {
			TcBlobData[] tmp = { // 1H
			blobUINT32(ordinal), // 1S
					blobUINT16(migrationType), // 2S
					migrationKeyAuth.getEncoded(), // 3S
					pubSourceKeyDigest.getEncoded(), // 4S
					blobUINT32(msaList.getEncoded().getLengthAsLong()), // 5S
					msaList.getEncoded(), // 6S
					blobUINT32(0), // 7S
					blobUINT32(sigTicket.getLengthAsLong()), // 8S
					sigTicket, // 9S
					blobUINT32(encData.getLengthAsLong()), // 10S
					encData }; // 11S
			blob1H = tmp;
		} else {
			TcBlobData[] tmp = { // 1H
			blobUINT32(ordinal), // 1S
					blobUINT16(migrationType), // 2S
					migrationKeyAuth.getEncoded(), // 3S
					pubSourceKeyDigest.getEncoded(), // 4S
					blobUINT32(msaList.getEncoded().getLengthAsLong()), // 5S
					msaList.getEncoded(), // 6S
					blobUINT32(restrictTicket.getLengthAsLong()), // 7S
					restrictTicket, // 8S
					blobUINT32(sigTicket.getLengthAsLong()), // 9S
					sigTicket, // 10S
					blobUINT32(encData.getLengthAsLong()), // 11S
					encData }; // 12S
			blob1H = tmp;
		}

		TcBlobData authDataH1 = computeAuthData( //
				blob1H, // 1H1
				inAuth1, // 2H1 - 4H1
				parentAuth.getEncoded()); // HMAC key

		inAuth1.setHmac(new TcTpmAuthdata(authDataH1));

		// call to TCS
		TcITcsBinding tcs = context.getTcsBinding();
		Object[] outDataTpm = tcs.TcsipCmkCreateBlob(context.getTcsContextHandle(), parentHandle,
				migrationType, migrationKeyAuth, pubSourceKeyDigest, msaList, restrictTicket, sigTicket,
				encData, inAuth1);

		// get return values
		long resultCode = ((Long) outDataTpm[0]).longValue();
		TcTcsAuth outAuth1 = (TcTcsAuth) outDataTpm[1];
		TcBlobData random = (TcBlobData) outDataTpm[2];
		TcBlobData outData = (TcBlobData) outDataTpm[3];

		// validate output data
		TcBlobData[] blob1Hout = { // 1H
		blobUINT32(resultCode), // 1S
				blobUINT32(ordinal), // 2S
				blobUINT32(random.getLengthAsLong()), // 3S
				random, // 4S
				blobUINT32(outData.getLengthAsLong()), // 5S
				outData }; // 6S

		validateRespAuth(blob1Hout, inAuth1, outAuth1, parentAuth.getEncoded());

		return new Object[] { outAuth1, random, outData };
	}


	/*************************************************************************************************
	 * This command is used as the final step to finish migrating a key to a new TPM.
	 *
	 * Note that the related TPM command migrates private keys only. The migration of the associated
	 * public keys us not specified by the TPM. The application (i.e. TSP) must generate a TPM_KEYxx
	 * structure before the migrated key can be used be the target TPM in a LoadKeyX command.
	 *
	 * @param context The context this call is associated with.
	 * @param parentHandle Handle of a loaded key that can decrypt keys.
	 * @param restrictTicket The digests of public keys belonging to the Migration Authority, the
	 *          destination parent key and the key-to-be-migrated.
	 * @param sigTicket A signature ticket, generated by the TPM, signaling a valid signature over
	 *          restrictTicket
	 * @param migratedKey The public key of the key-to-be-migrated. The private portion MUST be
	 *          TcTpmMigrateAsymkey properly XOR'd
	 * @param msaList One or more digests of public keys belonging to migration authorities
	 * @param random Random value used to hide key data.
	 * @param inAuth1 The data for the authorization session.
	 * @param parentAuth HMAC key for the authorization session.
	 *
	 * @return The returned Object[] holds the following elements:
	 *         <ul>
	 *         <li> 0 ... The outgoing authorization data for first session. (TcTpmAuth)
	 *         <li> 1 ... The encrypted private key that can be loaded with TPM_LoadKey (TcBlobData)
	 *         </ul>
	 *
	 * @throws {@link TcTssException}
	 */
	public static Object[] TspCmkConvertMigration_Internal(TcContext context, long parentHandle,
			TcTpmCmkAuth restrictTicket, TcTpmDigest sigTicket, TcTpmKey12 migratedKey,
			TcTpmMsaComposite msaList, TcBlobData random, TcTcsAuth inAuth1, TcTpmSecret parentAuth)
		throws TcTssException
	{
		CheckPrecondition.notNull(context, "context");
		CheckPrecondition.notNull(restrictTicket, "restrictTicket");
		CheckPrecondition.notNull(sigTicket, "sigTicket");
		CheckPrecondition.notNull(migratedKey, "migratedKey");
		CheckPrecondition.notNull(msaList, "msaList");
		CheckPrecondition.notNull(random, "random");
		CheckPrecondition.notNull(inAuth1, "inAuth1");
		CheckPrecondition.notNull(parentAuth, "parentAuth");

		long ordinal = TcTpmOrdinals.TPM_ORD_CMK_ConvertMigration;

		inAuth1.setNonceOdd(TcCrypto.createTcgNonce());

		TcBlobData[] blob1H = { // 1H
		blobUINT32(ordinal), // 1S
				restrictTicket.getEncoded(), // 2S
				sigTicket.getEncoded(), // 3S
				migratedKey.getEncoded(), // 4S
				blobUINT32(msaList.getEncoded().getLengthAsLong()), // 5S
				msaList.getEncoded(), // 6S
				blobUINT32(random.getLengthAsLong()), // 7S
				random }; // 8S

		TcBlobData authDataH1 = computeAuthData( //
				blob1H, // 1H1
				inAuth1, // 2H1 - 4H1
				parentAuth.getEncoded()); // HMAC key

		inAuth1.setHmac(new TcTpmAuthdata(authDataH1));

		// call to TCS
		TcITcsBinding tcs = context.getTcsBinding();
		Object[] outDataTpm = tcs.TcsipCmkConvertMigration(context.getTcsContextHandle(), parentHandle,
				restrictTicket, sigTicket, migratedKey, msaList, random, inAuth1);

		// get return values
		long resultCode = ((Long) outDataTpm[0]).longValue();
		TcTcsAuth outAuth1 = (TcTcsAuth) outDataTpm[1];
		TcBlobData outData = (TcBlobData) outDataTpm[2];

		// validate output data
		TcBlobData[] blob1Hout = { // 1H
		blobUINT32(resultCode), // 1S
				blobUINT32(ordinal), // 2S
				blobUINT32(outData.getLengthAsLong()), // 3S
				outData }; // 4S

		validateRespAuth(blob1Hout, inAuth1, outAuth1, parentAuth.getEncoded());

		return new Object[] { outAuth1, outData };
	}


	/*************************************************************************************************
	 * This method creates a TPM maintenance archive.
	 *
	 * @param context The context this call is associated with.
	 * @param generateRandom Use RNG or Owner authorization to generate 'random'.
	 * @param inAuth1 The data for the authorization session.
	 * @param ownerAuth HMAC key for the authorization session.
	 *
	 * @return The returned Object[] holds the following elements:
	 *         <ul>
	 *         <li> 0 ... The outgoing authorization data for first session. (TcTpmAuth)
	 *         <li> 1 ... Random data to XOR with result. (TcBlobData)
	 *         <li> 2 ... Encrypted key archive. (TcBlobData)
	 *         </ul>
	 *
	 * @throws {@link TcTssException}
	 */
	public static Object[] TspCreateMaintenanceArchive_Internal(TcContext context,
			boolean generateRandom, TcTcsAuth inAuth1, TcTpmSecret ownerAuth) throws TcTssException
	{
		CheckPrecondition.notNull(context, "context");
		CheckPrecondition.notNull(inAuth1, "inAuth1");
		CheckPrecondition.notNull(ownerAuth, "ownerAuth");

		long ordinal = TcTpmOrdinals.TPM_ORD_CreateMaintenanceArchive;

		inAuth1.setNonceOdd(TcCrypto.createTcgNonce());

		TcBlobData[] blob1H = { // 1H
		blobUINT32(ordinal), // 1S
				blobBOOL(generateRandom) }; // 2S

		TcBlobData authDataH1 = computeAuthData( //
				blob1H, // 1H1
				inAuth1, // 2H1 - 4H1
				ownerAuth.getEncoded()); // HMAC key

		inAuth1.setHmac(new TcTpmAuthdata(authDataH1));

		// call to TCS
		TcITcsBinding tcs = context.getTcsBinding();
		Object[] outDataTpm = tcs.TcsipCreateMaintenanceArchive(context.getTcsContextHandle(),
				generateRandom, inAuth1);

		// get return values
		long resultCode = ((Long) outDataTpm[0]).longValue();
		TcTcsAuth outAuth1 = (TcTcsAuth) outDataTpm[1];
		TcBlobData random = (TcBlobData) outDataTpm[2];
		TcBlobData archive = (TcBlobData) outDataTpm[3];

		// validate output data
		TcBlobData[] blob1Hout = { // 1H
		blobUINT32(resultCode), // 1S
				blobUINT32(ordinal), // 2S
				blobUINT32(random.getLengthAsLong()), // 3S
				random, // 4S
				blobUINT32(archive.getLengthAsLong()), // 5S
				archive }; // 6S

		validateRespAuth(blob1Hout, inAuth1, outAuth1, ownerAuth.getEncoded());

		return new Object[] { outAuth1, random, archive };
	}


	/*************************************************************************************************
	 * This method loads a TPM maintenance archive that has been massaged by the manufacturer to load
	 * into another TPM.
	 *
	 * @param context The context this call is associated with.
	 * @param inData Vendor specific data.
	 * @param inAuth1 The data for the authorization session.
	 * @param ownerAuth HMAC key for the authorization session.
	 *
	 * @return The returned Object[] holds the following elements:
	 *         <ul>
	 *         <li> 0 ... The outgoing authorization data for first session. (TcTpmAuth)
	 *         <li> 1 ... Vendor specific return data. (TcBlobData)
	 *         </ul>
	 *
	 * @throws {@link TcTssException}
	 */
	public static Object[] TspLoadMaintenanceArchive_Internal(TcContext context, TcBlobData inData,
			TcTcsAuth inAuth1, TcTpmSecret ownerAuth) throws TcTssException
	{
		CheckPrecondition.notNull(context, "context");
		CheckPrecondition.notNull(inData, "inData");
		CheckPrecondition.notNull(inAuth1, "inAuth1");
		CheckPrecondition.notNull(ownerAuth, "ownerAuth");

		long ordinal = TcTpmOrdinals.TPM_ORD_LoadMaintenanceArchive;

		inAuth1.setNonceOdd(TcCrypto.createTcgNonce());

		TcBlobData[] blob1H = { // 1H
		blobUINT32(ordinal) }; // 1S

		TcBlobData authDataH1 = computeAuthData( //
				blob1H, // 1H1
				inAuth1, // 2H1 - 4H1
				ownerAuth.getEncoded()); // HMAC key

		inAuth1.setHmac(new TcTpmAuthdata(authDataH1));

		// call to TCS
		TcITcsBinding tcs = context.getTcsBinding();
		Object[] outDataTpm = tcs.TcsipLoadMaintenanceArchive(context.getTcsContextHandle(), inData,
				inAuth1);

		// get return values
		long resultCode = ((Long) outDataTpm[0]).longValue();
		TcBlobData vendorOutData = (TcBlobData) outDataTpm[1];
		TcTcsAuth outAuth1 = (TcTcsAuth) outDataTpm[2];

		// validate output data
		TcBlobData[] blob1Hout = { // 1H
		blobUINT32(resultCode), // 1S
				blobUINT32(ordinal) }; // 2S

		validateRespAuth(blob1Hout, inAuth1, outAuth1, ownerAuth.getEncoded());

		return new Object[] { outAuth1, vendorOutData };
	}


	/*************************************************************************************************
	 * This method triggers a permanent action that prevents ANYONE from creating a TPM maintenance
	 * archive until a new TPM owner is set.
	 *
	 * @param context The context this call is associated with.
	 * @param inAuth1 The data for the authorization session.
	 * @param ownerAuth HMAC key for the authorization session.
	 *
	 * @return The outgoing authorization data for first session.
	 *
	 * @throws {@link TcTssException}
	 */
	public static TcTcsAuth TspKillMaintenanceFeature_Internal(TcContext context, TcTcsAuth inAuth1,
			TcTpmSecret ownerAuth) throws TcTssException
	{
		CheckPrecondition.notNull(context, "context");
		CheckPrecondition.notNull(inAuth1, "inAuth1");
		CheckPrecondition.notNull(ownerAuth, "ownerAuth");

		long ordinal = TcTpmOrdinals.TPM_ORD_KillMaintenanceFeature;

		inAuth1.setNonceOdd(TcCrypto.createTcgNonce());

		TcBlobData[] blob1H = { // 1H
		blobUINT32(ordinal) }; // 1S

		TcBlobData authDataH1 = computeAuthData( //
				blob1H, // 1H1
				inAuth1, // 2H1 - 4H1
				ownerAuth.getEncoded()); // HMAC key

		inAuth1.setHmac(new TcTpmAuthdata(authDataH1));

		// call to TCS
		TcITcsBinding tcs = context.getTcsBinding();
		Object[] outDataTpm = tcs.TcsipKillMaintenanceFeature(context.getTcsContextHandle(), inAuth1);

		// get return values
		long resultCode = ((Long) outDataTpm[0]).longValue();
		TcTcsAuth outAuth1 = (TcTcsAuth) outDataTpm[1];

		// validate output data
		TcBlobData[] blob1Hout = { // 1H
		blobUINT32(resultCode), // 1S
				blobUINT32(ordinal) }; // 2S

		validateRespAuth(blob1Hout, inAuth1, outAuth1, ownerAuth.getEncoded());

		return outAuth1;
	}


	/*************************************************************************************************
	 * This method loads the TPM manufactuerer's public key for use in the maintenance process.
	 *
	 * @param context The context this call is associated with.
	 * @param antiReplay AntiReplay and validation nonce
	 * @param pubKey The public key of the manufacturer to be in use for maintenance
	 *
	 * @return Digest of pubKey and antiReplay
	 *
	 * @throws {@link TcTssException}
	 */
	public static TcTpmDigest TspLoadManuMaintPub_Internal(TcContext context, TcTpmNonce antiReplay,
			TcTpmPubkey pubKey) throws TcTssException
	{
		CheckPrecondition.notNull(context, "context");
		CheckPrecondition.notNull(antiReplay, "antiReplay");
		CheckPrecondition.notNull(pubKey, "pubKey");

		// call to TCS
		TcITcsBinding tcs = context.getTcsBinding();
		Object[] outDataTpm = tcs.TcsipLoadManuMaintPub(context.getTcsContextHandle(), antiReplay,
				pubKey);

		// get return values
		TcTpmDigest checksum = (TcTpmDigest) outDataTpm[1];

		return checksum;
	}


	/*************************************************************************************************
	 * This command is used to check whether the manufactuerer's public maintenance key in a TPM has
	 * the expected value.
	 *
	 * @param context The context this call is associated with.
	 * @param antiReplay AntiReplay and validation nonce
	 *
	 * @return Digest of pubKey and antiReplay
	 *
	 * @throws {@link TcTssException}
	 */
	public static TcTpmDigest TspReadManuMaintPub_Internal(TcContext context, TcTpmNonce antiReplay)
		throws TcTssException
	{
		CheckPrecondition.notNull(context, "context");
		CheckPrecondition.notNull(antiReplay, "antiReplay");

		// call to TCS
		TcITcsBinding tcs = context.getTcsBinding();
		Object[] outDataTpm = tcs.TcsipReadManuMaintPub(context.getTcsContextHandle(), antiReplay);

		// get return values
		TcTpmDigest checksum = (TcTpmDigest) outDataTpm[1];

		return checksum;
	}


	/*************************************************************************************************
	 * This method signs a digest and returns the resulting digital signature. This command uses a
	 * properly authorized signature key.
	 *
	 * @param context The context this call is associated with.
	 * @param keyHandle The keyHandle identifier of a loaded key that can perform digital signatures.
	 * @param areaToSign The value to sign
	 * @param inAuth1 The data for the authorization session.
	 * @param privAuth HMAC key for the authorization session.
	 *
	 * @return The returned Object[] holds the following elements:
	 *         <ul>
	 *         <li> 0 ... The outgoing authorization data for first session. (TcTpmAuth)
	 *         <li> 1 ... The resulting digital signature. (TcBlobData)
	 *         </ul>
	 *
	 * @throws {@link TcTssException}
	 */
	public static Object[] TspSign_Internal(TcContext context, long keyHandle, TcBlobData areaToSign,
			TcTcsAuth inAuth1, TcTpmSecret privAuth) throws TcTssException
	{
		CheckPrecondition.notNull(context, "context");
		CheckPrecondition.notNull(areaToSign, "areaToSign");
		CheckPrecondition.notNull(inAuth1, "inAuth1");
		CheckPrecondition.notNull(privAuth, "privAuth");

		long ordinal = TcTpmOrdinals.TPM_ORD_Sign;

		inAuth1.setNonceOdd(TcCrypto.createTcgNonce());

		TcBlobData[] blob1H = { // 1H
		blobUINT32(ordinal), // 1S
				blobUINT32(areaToSign.getLengthAsLong()), // 2S
				areaToSign }; // 3S

		TcBlobData authDataH1 = computeAuthData( //
				blob1H, // 1H1
				inAuth1, // 2H1 - 4H1
				privAuth.getEncoded()); // HMAC key

		inAuth1.setHmac(new TcTpmAuthdata(authDataH1));

		// call to TCS
		TcITcsBinding tcs = context.getTcsBinding();
		Object[] outDataTpm = tcs.TcsipSign(context.getTcsContextHandle(), keyHandle, areaToSign,
				inAuth1);

		// get return values
		long resultCode = ((Long) outDataTpm[0]).longValue();
		TcTcsAuth outAuth1 = (TcTcsAuth) outDataTpm[1];
		TcBlobData sig = (TcBlobData) outDataTpm[2];

		// validate output data
		TcBlobData[] blob1Hout = { // 1H
		blobUINT32(resultCode), // 1S
				blobUINT32(ordinal), // 2S
				blobUINT32(sig.getLengthAsLong()), // 3S
				sig }; // 4S

		validateRespAuth(blob1Hout, inAuth1, outAuth1, privAuth.getEncoded());

		return new Object[] { outAuth1, sig };
	}


	/*************************************************************************************************
	 * This method returns the next bytesRequested bytes from the random number generator to the
	 * caller.
	 *
	 * @param context The context this call is associated with.
	 * @param bytesRequested Number of bytes to return
	 *
	 * @return The returned bytes
	 *
	 * @throws {@link TcTssException}
	 */
	public static TcBlobData TspGetRandom_Internal(TcContext context, long bytesRequested)
		throws TcTssException
	{
		CheckPrecondition.notNull(context, "context");

		// call to TCS
		TcITcsBinding tcs = context.getTcsBinding();
		Object[] outDataTpm = tcs.TcsipGetRandom(context.getTcsContextHandle(), bytesRequested);

		// get return values
		TcBlobData randomBytes = (TcBlobData) outDataTpm[1];

		return randomBytes;
	}


	/*************************************************************************************************
	 * This method adds entropy to the RNG state.
	 *
	 * @param context The context this call is associated with.
	 * @param inData Data to add entropy to RNG state
	 *
	 *
	 * @throws {@link TcTssException}
	 */
	public static void TspStirRandom_Internal(TcContext context, TcBlobData inData)
		throws TcTssException
	{
		CheckPrecondition.notNull(context, "context");
		CheckPrecondition.notNull(inData, "inData");

		// call to TCS
		TcITcsBinding tcs = context.getTcsBinding();
		tcs.TcsipStirRandom(context.getTcsContextHandle(), inData);
	}


	/*************************************************************************************************
	 * This method allows a key to certify the public portion of certain storage and signing keys.
	 *
	 * @param context The context this call is associated with.
	 * @param certHandle Handle of the key to be used to certify the key.
	 * @param keyHandle Handle of the key to be certified.
	 * @param antiReplay 160 bits of externally supplied data (typically a nonce provided to prevent
	 *          replay-attacks)
	 * @param inAuth1 The data for the first authorization session.
	 * @param inAuth2 The data for the second authorization session.
	 * @param certAuth HMAC key for the first authorization session.
	 * @param keyAuth HMAC key for the second authorization session.
	 *
	 * @return The returned Object[] holds the following elements:
	 *         <ul>
	 *         <li> 0 ... The outgoing authorization data for first session. (TcTpmAuth)
	 *         <li> 1 ... The outgoing authorization data for second session. (TcTpmAuth)
	 *         <li> 2 ... TPM_CERTIFY_INFO or TcTpmCertifyInfo2 structure that provides information
	 *         relative to key handle (TcTpmCertifyInfo)
	 *         <li> 3 ... The signature of certifyInfo (TcBlobData)
	 *         </ul>
	 *
	 * @throws {@link TcTssException}
	 */
	public static Object[] TspCertifyKey_Internal(TcContext context, long certHandle, long keyHandle,
			TcTpmNonce antiReplay, TcTcsAuth inAuth1, TcTcsAuth inAuth2, TcTpmSecret certAuth,
			TcTpmSecret keyAuth) throws TcTssException
	{
		CheckPrecondition.notNull(context, "context");
		CheckPrecondition.notNull(antiReplay, "antiReplay");
		CheckPrecondition.notNull(inAuth1, "inAuth1");
		CheckPrecondition.notNull(inAuth2, "inAuth2");
		CheckPrecondition.notNull(certAuth, "certAuth");
		CheckPrecondition.notNull(keyAuth, "keyAuth");

		long ordinal = TcTpmOrdinals.TPM_ORD_CertifyKey;

		inAuth1.setNonceOdd(TcCrypto.createTcgNonce());
		inAuth2.setNonceOdd(TcCrypto.createTcgNonce());

		TcBlobData[] blob1H = { // 1H
		blobUINT32(ordinal), // 1S
				antiReplay.getEncoded() }; // 2S

		TcBlobData authDataH1 = computeAuthData( //
				blob1H, // 1H1
				inAuth1, // 2H1 - 4H1
				certAuth.getEncoded()); // HMAC key

		inAuth1.setHmac(new TcTpmAuthdata(authDataH1));

		TcBlobData authDataH2 = computeAuthData( //
				blob1H, // 1H2
				inAuth2, // 2H2 - 4H2
				keyAuth.getEncoded()); // HMAC key

		inAuth2.setHmac(new TcTpmAuthdata(authDataH2));

		// call to TCS
		TcITcsBinding tcs = context.getTcsBinding();
		Object[] outDataTpm = tcs.TcsipCertifyKey(context.getTcsContextHandle(), certHandle, keyHandle,
				antiReplay, inAuth1, inAuth2);

		// get return values
		long resultCode = ((Long) outDataTpm[0]).longValue();
		TcTcsAuth outAuth1 = (TcTcsAuth) outDataTpm[1];
		TcTcsAuth outAuth2 = (TcTcsAuth) outDataTpm[2];
		Object certifyInfoObj = outDataTpm[3];
		TcBlobData outData = (TcBlobData) outDataTpm[4];

		// certifyInfoBlob can be either a TPM_CERTIFY_INFO or TPM_CERTIFY_INFO2
		TcBlobData certifyInfoBlob = null;
		if (certifyInfoObj instanceof TcTpmCertifyInfo) {
			certifyInfoBlob = ((TcTpmCertifyInfo) certifyInfoObj).getEncoded();
		} else if (certifyInfoObj instanceof TcTpmCertifyInfo2) {
			certifyInfoBlob = ((TcTpmCertifyInfo2) certifyInfoObj).getEncoded();
		} else {
			throw new TcTspException(TcTssErrors.TSS_E_INTERNAL_ERROR, "Unknown certify info structure.");
		}

		// validate output data
		TcBlobData[] blob1Hout = { // 1H
		blobUINT32(resultCode), // 1S
				blobUINT32(ordinal), // 2S
				certifyInfoBlob, // 3S
				blobUINT32(outData.getLengthAsLong()), // 4S
				outData }; // 5S

		validateRespAuth(blob1Hout, inAuth1, outAuth1, certAuth.getEncoded());
		validateRespAuth(blob1Hout, inAuth2, outAuth2, keyAuth.getEncoded());

		return new Object[] { outAuth1, outAuth2, certifyInfoObj, outData };
	}


	/*************************************************************************************************
	 * This method allows a key to certify the public portion of certifiable migratable storage and
	 * signing keys.
	 *
	 * @param context The context this call is associated with.
	 * @param keyHandle Handle of the key to be certified.
	 * @param certHandle Handle of the key to be used to certify the key.
	 * @param migrationPubDigest The digest of a TcTpmMsaCompositestructure, containing at least one
	 *          public key of a Migration Authority
	 * @param antiReplay 160 bits of externally supplied data (typically a nonce provided to prevent
	 *          replay-attacks)
	 * @param inAuth1 The data for the first authorization session.
	 * @param inAuth2 The data for the second authorization session.
	 * @param keyAuth HMAC key for the first authorization session.
	 * @param certAuth HMAC key for the second authorization session.
	 *
	 * @return The returned Object[] holds the following elements:
	 *         <ul>
	 *         <li> 0 ... The outgoing authorization data for first session. (TcTpmAuth)
	 *         <li> 1 ... The outgoing authorization data for second session. (TcTpmAuth)
	 *         <li> 2 ... TcTpmCertifyInfo2 relative to keyHandle (TcTpmCertifyInfo2)
	 *         <li> 3 ... The signed public key. (TcBlobData)
	 *         </ul>
	 *
	 * @throws {@link TcTssException}
	 */
	public static Object[] TspCertifyKey2_Internal(TcContext context, long certHandle,
			long keyHandle, TcTpmDigest migrationPubDigest, TcTpmNonce antiReplay, TcTcsAuth inAuth1,
			TcTcsAuth inAuth2, TcTpmSecret keyAuth, TcTpmSecret certAuth) throws TcTssException
	{
		CheckPrecondition.notNull(context, "context");
		CheckPrecondition.notNull(migrationPubDigest, "migrationPubDigest");
		CheckPrecondition.notNull(antiReplay, "antiReplay");
		CheckPrecondition.notNull(inAuth1, "inAuth1");
		CheckPrecondition.notNull(inAuth2, "inAuth2");
		CheckPrecondition.notNull(keyAuth, "keyAuth");
		CheckPrecondition.notNull(certAuth, "certAuth");

		long ordinal = TcTpmOrdinals.TPM_ORD_CertifyKey2;

		inAuth1.setNonceOdd(TcCrypto.createTcgNonce());
		inAuth2.setNonceOdd(TcCrypto.createTcgNonce());

		TcBlobData[] blob1H = { // 1H
		blobUINT32(ordinal), // 1S
				migrationPubDigest.getEncoded(), // 2S
				antiReplay.getEncoded() }; // 3S

		TcBlobData authDataH1 = computeAuthData( //
				blob1H, // 1H1
				inAuth1, // 2H1 - 4H1
				keyAuth.getEncoded()); // HMAC key

		inAuth1.setHmac(new TcTpmAuthdata(authDataH1));

		TcBlobData authDataH2 = computeAuthData( //
				blob1H, // 1H2
				inAuth2, // 2H2 - 4H2
				certAuth.getEncoded()); // HMAC key

		inAuth2.setHmac(new TcTpmAuthdata(authDataH2));

		// call to TCS
		TcITcsBinding tcs = context.getTcsBinding();
		Object[] outDataTpm = tcs.TcsipCertifyKey2(context.getTcsContextHandle(), certHandle,
				keyHandle, migrationPubDigest, antiReplay, inAuth1, inAuth2);

		// get return values
		long resultCode = ((Long) outDataTpm[0]).longValue();
		TcTcsAuth outAuth1 = (TcTcsAuth) outDataTpm[1];
		TcTcsAuth outAuth2 = (TcTcsAuth) outDataTpm[2];
		TcTpmCertifyInfo2 certifyInfo = (TcTpmCertifyInfo2) outDataTpm[3];
		TcBlobData outData = (TcBlobData) outDataTpm[4];

		// validate output data
		TcBlobData[] blob1Hout = { // 1H
		blobUINT32(resultCode), // 1S
				blobUINT32(ordinal), // 2S
				certifyInfo.getEncoded(), // 3S
				blobUINT32(outData.getLengthAsLong()), // 4S
				outData }; // 5S

		validateRespAuth(blob1Hout, inAuth1, outAuth1, keyAuth.getEncoded());
		validateRespAuth(blob1Hout, inAuth2, outAuth2, certAuth.getEncoded());

		return new Object[] { outAuth1, outAuth2, certifyInfo, outData };
	}


	/*************************************************************************************************
	 * This method generates the endorsement key pair.
	 *
	 * @param context The context this call is associated with.
	 * @param antiReplay Arbitrary data.
	 * @param keyInfo Information about key to be created, this includes all algorithm parameters.
	 *
	 * @return The returned Object[] holds the following elements:
	 *         <ul>
	 *         <li> 0 ... The public endorsement key (TcTpmPubkey)
	 *         <li> 1 ... Hash of pubEndorsementKey and antiReplay (TcTpmDigest)
	 *         </ul>
	 *
	 * @throws {@link TcTssException}
	 */
	public static Object[] TspCreateEndorsementKeyPair_Internal(TcContext context,
			TcTpmKeyParms keyInfo, TcTpmNonce antiReplay) throws TcTssException
	{
		CheckPrecondition.notNull(context, "context");
		CheckPrecondition.notNull(keyInfo, "keyInfo");
		CheckPrecondition.notNull(antiReplay, "antiReplay");

		// call to TCS
		TcITcsBinding tcs = context.getTcsBinding();
		Object[] outDataTpm = tcs.TcsipCreateEndorsementKeyPair(context.getTcsContextHandle(),
				antiReplay, keyInfo);

		// get return values
		TcTpmPubkey pubEndorsementKey = (TcTpmPubkey) outDataTpm[1];
		TcTpmDigest checksum = (TcTpmDigest) outDataTpm[2];

		return new Object[] { pubEndorsementKey, checksum };
	}


	/*************************************************************************************************
	 * This method generates the revocable endorsement key pair.
	 *
	 * @param context The context this call is associated with.
	 * @param keyInfo Information about key to be created, this includes all algorithm parameters.
	 * @param antiReplay Arbitrary data.
	 * @param generateReset If TRUE use TPM RNG to generate EKreset. If FALSE use the passed value
	 *          inputEKreset,
	 * @param inputEKreset The authorization value to be used with RevokeEndorsementKeyPair if
	 *          generateReset==FALSE, else the parameter is present but ignored.
	 *
	 * @return The returned Object[] holds the following elements:
	 *         <ul>
	 *         <li> 0 ... The public endorsement key (TcTpmPubkey)
	 *         <li> 1 ... Hash of pubEndorsementKey and antiReplay (TcTpmDigest)
	 *         <li> 2 ... The AuthData value to use TPM_RevokeTrust (TcTpmNonce)
	 *         </ul>
	 *
	 * @throws {@link TcTssException}
	 */
	public static Object[] TspCreateRevocableEK_Internal(TcContext context, TcTpmKeyParms keyInfo,
			TcTpmNonce antiReplay, boolean generateReset, TcTpmNonce inputEKreset) throws TcTssException
	{
		CheckPrecondition.notNull(context, "context");
		CheckPrecondition.notNull(keyInfo, "keyInfo");
		CheckPrecondition.notNull(antiReplay, "antiReplay");
		if (!generateReset) {
		    CheckPrecondition.notNull(inputEKreset, "inputEKreset");
		}

		// call to TCS
		TcITcsBinding tcs = context.getTcsBinding();
		Object[] outDataTpm = tcs.TcsipCreateRevocableEK(context.getTcsContextHandle(), antiReplay,
				keyInfo, generateReset, inputEKreset);

		// get return values
		TcTpmPubkey pubEndorsementKey = (TcTpmPubkey) outDataTpm[1];
		TcTpmDigest checksum = (TcTpmDigest) outDataTpm[2];
		TcTpmNonce outputEKreset = (TcTpmNonce) outDataTpm[3];

		// validate checksum
		validateChecksum(pubEndorsementKey.getEncoded(), antiReplay.getEncoded(), checksum);

		return new Object[] { pubEndorsementKey, checksum, outputEKreset };
	}


	/*************************************************************************************************
	 * This method clears the TPM revocable endorsement key pair.
	 *
	 * @param context The context this call is associated with.
	 * @param EKReset The value that will be matched toEK Reset
	 *
	 *
	 * @throws {@link TcTssException}
	 */
	public static void TspRevokeEndorsementKeyPair_Internal(TcContext context, TcTpmNonce EKReset)
		throws TcTssException
	{
		CheckPrecondition.notNull(context, "context");
		CheckPrecondition.notNull(EKReset, "EKReset");

		// call to TCS
		TcITcsBinding tcs = context.getTcsBinding();
		tcs.TcsipRevokeEndorsementKeyPair(context.getTcsContextHandle(), EKReset);
	}


	/*************************************************************************************************
	 * This method returns the public portion of the endorsement key.
	 *
	 * @param context The context this call is associated with.
	 *
	 * @return The returned Object[] holds the following elements:
	 *         <ul>
	 *         <li> 0 ... The public endorsement key (TcTpmPubkey)
	 *         <li> 1 ... Hash of pubEndorsementKey and antiReplay (TcTpmDigest)
	 *         </ul>
	 *
	 * @throws {@link TcTssException}
	 */
	public static Object[] TspReadPubek_Internal(TcContext context, TcTpmNonce antiReplay)
		throws TcTssException
	{
		CheckPrecondition.notNull(context, "context");
		CheckPrecondition.notNull(antiReplay, "antiReplay");

		// call to TCS
		TcITcsBinding tcs = context.getTcsBinding();
		Object[] outDataTpm = tcs.TcsipReadPubek(context.getTcsContextHandle(), antiReplay);

		// get return values
		TcTpmPubkey pubEndorsementKey = (TcTpmPubkey) outDataTpm[1];
		TcTpmDigest checksum = (TcTpmDigest) outDataTpm[2];

		return new Object[] { pubEndorsementKey, checksum };
	}


	/*************************************************************************************************
	 * This method allows to flush a key from the key cache.
	 *
	 * @param context The context this call is associated with.
	 * @param keyHandle TCS key handle of the key to be evicted.
	 *
	 * @throws {@link TcTssException}
	 */
	public static void TcsipEvictKey(TcContext context, long keyHandle) throws TcTssException
	{
		CheckPrecondition.notNull(context, "context");

		// call to TCS
		TcITcsBinding tcs = context.getTcsBinding();
		tcs.TcsipEvictKey(context.getTcsContextHandle(), keyHandle);
	}


	/*************************************************************************************************
	 *
	 *
	 * @param context The context this call is associated with.
	 * @param keyHandle Handle for either PUBEK or SRK
	 * @param inAuth1 The data for the authorization session.
	 * @param ownerAuth HMAC key for the authorization session.
	 *
	 * @return The returned Object[] holds the following elements:
	 *         <ul>
	 *         <li> 0 ... The outgoing authorization data for first session. (TcTpmAuth)
	 *         <li> 1 ... The public portion of the requested key (TcTpmPubkey)
	 *         </ul>
	 *
	 * @throws {@link TcTssException}
	 */
	public static Object[] TspOwnerReadInternalPub_Internal(TcContext context, long keyHandle,
			TcTcsAuth inAuth1, TcTpmSecret ownerAuth) throws TcTssException
	{
		CheckPrecondition.notNull(context, "context");
		CheckPrecondition.notNull(inAuth1, "inAuth1");
		CheckPrecondition.notNull(ownerAuth, "ownerAuth");

		long ordinal = TcTpmOrdinals.TPM_ORD_OwnerReadInternalPub;

		inAuth1.setNonceOdd(TcCrypto.createTcgNonce());

		TcBlobData[] blob1H = { // 1H
		blobUINT32(ordinal), // 1S
				blobUINT32(keyHandle) }; // 2S

		TcBlobData authDataH1 = computeAuthData( //
				blob1H, // 1H1
				inAuth1, // 2H1 - 4H1
				ownerAuth.getEncoded()); // HMAC key

		inAuth1.setHmac(new TcTpmAuthdata(authDataH1));

		// call to TCS
		TcITcsBinding tcs = context.getTcsBinding();
		Object[] outDataTpm = tcs.TcsipOwnerReadInternalPub(context.getTcsContextHandle(), keyHandle,
				inAuth1);

		// get return values
		long resultCode = ((Long) outDataTpm[0]).longValue();
		TcTcsAuth outAuth1 = (TcTcsAuth) outDataTpm[1];
		TcTpmPubkey publicPortion = (TcTpmPubkey) outDataTpm[2];

		// validate output data
		TcBlobData[] blob1Hout = { // 1H
		blobUINT32(resultCode), // 1S
				blobUINT32(ordinal), // 2S
				publicPortion.getEncoded() }; // 3S

		validateRespAuth(blob1Hout, inAuth1, outAuth1, ownerAuth.getEncoded());

		return new Object[] { outAuth1, publicPortion };
	}


	/*************************************************************************************************
	 * The purpose of this method is twofold: The first purpose is to obtain assurance that the
	 * credential in the TPM_SYM_CA_ATTESTATION is for this TPM. The second purpose is to obtain the
	 * session key used to encrypt the TPM_IDENTITY_CREDENTIAL. This function checks that the
	 * symmetric session key corresponds to a TPM-identity before releasing that session key. Only the
	 * owner of the TPM has the privilege of activating a TPM identity. The owner may authorize this
	 * function using either the TPM_OIAP or TPM_OSAP authorization protocols.
	 *
	 * @param context The context this call is associated with.
	 * @param idKeyHandle Identity key to be activated.
	 * @param blob The encrypted ASYM_CA_CONTENTS orTcTpmEkBlob.
	 * @param inAuth1 The data for the first authorization session.
	 * @param inAuth2 The data for the second authorization session.
	 * @param idKeyAuth HMAC key for the first authorization session.
	 * @param ownerAuth HMAC key for the second authorization session.
	 *
	 * @return The returned Object[] holds the following elements:
	 *         <ul>
	 *         <li> 0 ... The outgoing authorization data for first session. (TcTpmAuth)
	 *         <li> 1 ... The outgoing authorization data for second session. (TcTpmAuth)
	 *         <li> 2 ... The decrypted symmetric key. (TcTpmSymmetricKey)
	 *         </ul>
	 *
	 * @throws {@link TcTssException}
	 */
	public static Object[] TspActivateIdentity_Internal(TcContext context, long idKeyHandle,
			TcBlobData blob, TcTcsAuth inAuth1, TcTcsAuth inAuth2, TcTpmSecret idKeyAuth,
			TcTpmSecret ownerAuth) throws TcTssException
	{
		CheckPrecondition.notNull(context, "context");
		CheckPrecondition.notNull(blob, "blob");
		CheckPrecondition.notNull(inAuth1, "inAuth1");
		CheckPrecondition.notNull(inAuth2, "inAuth2");
		CheckPrecondition.notNull(idKeyAuth, "idKeyAuth");
		CheckPrecondition.notNull(ownerAuth, "ownerAuth");

		long ordinal = TcTpmOrdinals.TPM_ORD_ActivateIdentity;

		inAuth1.setNonceOdd(TcCrypto.createTcgNonce());
		inAuth2.setNonceOdd(TcCrypto.createTcgNonce());

		TcBlobData[] blob1H = { // 1H
		blobUINT32(ordinal), // 1S
				blobUINT32(blob.getLengthAsLong()), // 2S
				blob }; // 3S

		TcBlobData authDataH1 = computeAuthData( //
				blob1H, // 1H1
				inAuth1, // 2H1 - 4H1
				idKeyAuth.getEncoded()); // HMAC key

		inAuth1.setHmac(new TcTpmAuthdata(authDataH1));

		TcBlobData authDataH2 = computeAuthData( //
				blob1H, // 1H2
				inAuth2, // 2H2 - 4H2
				ownerAuth.getEncoded()); // HMAC key

		inAuth2.setHmac(new TcTpmAuthdata(authDataH2));

		// call to TCS
		TcITcsBinding tcs = context.getTcsBinding();
		Object[] outDataTpm = tcs.TcsipActivateIdentity(context.getTcsContextHandle(), idKeyHandle,
				blob, inAuth1, inAuth2);

		// get return values
		long resultCode = ((Long) outDataTpm[0]).longValue();
		TcTcsAuth outAuth1 = (TcTcsAuth) outDataTpm[1];
		TcTcsAuth outAuth2 = (TcTcsAuth) outDataTpm[2];
		TcTpmSymmetricKey symmetricKey = (TcTpmSymmetricKey) outDataTpm[3];

		// validate output data
		TcBlobData[] blob1Hout = { // 1H
		blobUINT32(resultCode), // 1S
				blobUINT32(ordinal), // 2S
				symmetricKey.getEncoded() }; // 3S

		validateRespAuth(blob1Hout, inAuth1, outAuth1, idKeyAuth.getEncoded());
		validateRespAuth(blob1Hout, inAuth2, outAuth2, ownerAuth.getEncoded());

		return new Object[] { outAuth1, outAuth2, symmetricKey };
	}


	/*************************************************************************************************
	 * This command causes the modification of a specific PCR register.
	 *
	 * @param context The context this call is associated with.
	 * @param pcrNum The PCR to be updated.
	 * @param inDigest The 160 bit value representing the event to be recorded.
	 *
	 * @return The PCR value after execution of the command.
	 *
	 * @throws {@link TcTssException}
	 */
	public static TcTpmDigest TspExtend_Internal(TcContext context, long pcrNum, TcTpmDigest inDigest)
		throws TcTssException
	{
		CheckPrecondition.notNull(context, "context");
		CheckPrecondition.notNull(inDigest, "inDigest");

		// call to TCS
		TcITcsBinding tcs = context.getTcsBinding();
		Object[] outDataTpm = tcs.TcsipExtend(context.getTcsContextHandle(), pcrNum, inDigest);

		// get return values
		TcTpmDigest outDigest = (TcTpmDigest) outDataTpm[1];

		return outDigest;
	}


	/*************************************************************************************************
	 * This method provides a non-cryptographic reporting of the contents of a named PCR.
	 *
	 * @param context The context this call is associated with.
	 * @param pcrIndex Index of the PCR to be read
	 *
	 * @return The current contents of the named PCR
	 *
	 * @throws {@link TcTssException}
	 */
	public static TcTpmDigest TspPcrRead_Internal(TcContext context, long pcrIndex)
		throws TcTssException
	{
		CheckPrecondition.notNull(context, "context");

		// call to TCS
		TcITcsBinding tcs = context.getTcsBinding();
		Object[] outDataTpm = tcs.TcsipPcrRead(context.getTcsContextHandle(), pcrIndex);

		// get return values
		TcTpmDigest outDigest = (TcTpmDigest) outDataTpm[1];

		return outDigest;
	}


	/*************************************************************************************************
	 * This command provides cryptographic reporting of PCR values. A loaded key is required for
	 * operation. This command uses the key to sign a statement that names the current value of a
	 * chosen PCR and externally supplied data (which may be a nonce supplied by a challenger).
	 *
	 * @param context The context this call is associated with.
	 * @param keyHandle The keyHandle identifier of a loaded key that can sign the PCR values.
	 * @param externalData 160 bits of externally supplied data (typically a nonce provided by a
	 *          server to prevent replay-attacks)
	 * @param targetPCR The indices of the PCRs that are to be reported.
	 * @param inAuth1 The data for the authorization session.
	 * @param privAuth HMAC key for the authorization session.
	 *
	 * @return The returned Object[] holds the following elements:
	 *         <ul>
	 *         <li> 0 ... The outgoing authorization data for first session. (TcTpmAuth)
	 *         <li> 1 ... A structure containing the same indices as targetPCR, plus the corresponding
	 *         current PCR values. (TcTpmPcrComposite)
	 *         <li> 2 ... The signed data blob. (TcBlobData)
	 *         </ul>
	 *
	 * @throws {@link TcTssException}
	 */
	public static Object[] TspQuote_Internal(TcContext context, long keyHandle,
			TcTpmNonce externalData, TcTpmPcrSelection targetPCR, TcTcsAuth inAuth1, TcTpmSecret privAuth)
		throws TcTssException
	{
		CheckPrecondition.notNull(context, "context");
		CheckPrecondition.notNull(externalData, "externalData");
		CheckPrecondition.notNull(targetPCR, "targetPCR");
		CheckPrecondition.notNull(inAuth1, "inAuth1");
		CheckPrecondition.notNull(privAuth, "privAuth");

		long ordinal = TcTpmOrdinals.TPM_ORD_Quote;

		inAuth1.setNonceOdd(TcCrypto.createTcgNonce());

		TcBlobData[] blob1H = { // 1H
		blobUINT32(ordinal), // 1S
				externalData.getEncoded(), // 2S
				targetPCR.getEncoded() }; // 3S

		TcBlobData authDataH1 = computeAuthData( //
				blob1H, // 1H1
				inAuth1, // 2H1 - 4H1
				privAuth.getEncoded()); // HMAC key

		inAuth1.setHmac(new TcTpmAuthdata(authDataH1));

		// call to TCS
		TcITcsBinding tcs = context.getTcsBinding();
		Object[] outDataTpm = tcs.TcsipQuote(context.getTcsContextHandle(), keyHandle, externalData,
				targetPCR, inAuth1);

		// get return values
		long resultCode = ((Long) outDataTpm[0]).longValue();
		TcTcsAuth outAuth1 = (TcTcsAuth) outDataTpm[1];
		TcTpmPcrComposite pcrData = (TcTpmPcrComposite) outDataTpm[2];
		TcBlobData sig = (TcBlobData) outDataTpm[3];

		// validate output data
		TcBlobData[] blob1Hout = { // 1H
		blobUINT32(resultCode), // 1S
				blobUINT32(ordinal), // 2S
				pcrData.getEncoded(), // 3S
				blobUINT32(sig.getLengthAsLong()), // 4S
				sig }; // 5S

		validateRespAuth(blob1Hout, inAuth1, outAuth1, privAuth.getEncoded());

		return new Object[] { outAuth1, pcrData, sig };
	}


	/*************************************************************************************************
	 * This method resets a PCR register. Whether or not it succeeds may depend on the locality
	 * executing the command. PCRs can be defined in a platform specific specification to allow reset
	 * of certain PCRs only for certain localities. The one exception to this is PCR 15, which can
	 * always be reset in a 1.2 implementation (This is to allow software testing). This command will
	 * reset either ALL of the PCRs selected in pcrSelection or NONE of them.
	 *
	 * @param context The context this call is associated with.
	 * @param pcrSelection The PCR's to reset.
	 *
	 *
	 * @throws {@link TcTssException}
	 */
	public static void TspPcrReset_Internal(TcContext context, TcTpmPcrSelection pcrSelection)
		throws TcTssException
	{
		CheckPrecondition.notNull(context, "context");
		CheckPrecondition.notNull(pcrSelection, "pcrSelection");

		// call to TCS
		TcITcsBinding tcs = context.getTcsBinding();
		tcs.TcsipPcrReset(context.getTcsContextHandle(), pcrSelection);
	}


	/*************************************************************************************************
	 * This command provides cryptographic reporting of PCR values. A loaded key is required for
	 * operation. This command uses the key to sign a statement that names the current value of a
	 * chosen PCR and externally supplied data (which may be a nonce supplied by a challenger).
	 *
	 * @param context The context this call is associated with.
	 * @param keyHandle The keyHandle identifier of a loaded key that can sign the PCR values.
	 * @param externalData 160 bits of externally supplied data (typically a nonce provided by a
	 *          server to prevent replay-attacks)
	 * @param targetPCR The indices of the PCRs that are to be reported.
	 * @param addVersion When TRUE add TcTpmCapVersionInfoto the output
	 * @param inAuth1 The data for the authorization session.
	 * @param privAuth HMAC key for the authorization session.
	 *
	 * @return The returned Object[] holds the following elements:
	 *         <ul>
	 *         <li> 0 ... The outgoing authorization data for first session. (TcTpmAuth)
	 *         <li> 1 ... The value created and signed for the quote (TcTpmPcrInfoShort)
	 *         <li> 2 ... The version info (TcTpmCapVersionInfo)
	 *         <li> 3 ... The signed data blob. (TcBlobData)
	 *         </ul>
	 *
	 * @throws {@link TcTssException}
	 */
	public static Object[] TspQuote2_Internal(TcContext context, long keyHandle,
			TcTpmNonce externalData, TcTpmPcrSelection targetPCR, boolean addVersion, TcTcsAuth inAuth1,
			TcTpmSecret privAuth) throws TcTssException
	{
		CheckPrecondition.notNull(context, "context");
		CheckPrecondition.notNull(externalData, "externalData");
		CheckPrecondition.notNull(targetPCR, "targetPCR");
		CheckPrecondition.notNull(inAuth1, "inAuth1");
		CheckPrecondition.notNull(privAuth, "privAuth");

		long ordinal = TcTpmOrdinals.TPM_ORD_Quote2;

		inAuth1.setNonceOdd(TcCrypto.createTcgNonce());

		TcBlobData[] blob1H = { // 1H
		blobUINT32(ordinal), // 1S
				externalData.getEncoded(), // 2S
				targetPCR.getEncoded(), // 3S
				blobBOOL(addVersion) }; // 4S

		TcBlobData authDataH1 = computeAuthData( //
				blob1H, // 1H1
				inAuth1, // 2H1 - 4H1
				privAuth.getEncoded()); // HMAC key

		inAuth1.setHmac(new TcTpmAuthdata(authDataH1));

		// call to TCS
		TcITcsBinding tcs = context.getTcsBinding();
		Object[] outDataTpm = tcs.TcsipQuote2(context.getTcsContextHandle(), keyHandle, externalData,
				targetPCR, addVersion, inAuth1);

		// get return values
		long resultCode = ((Long) outDataTpm[0]).longValue();
		TcTcsAuth outAuth1 = (TcTcsAuth) outDataTpm[1];
		TcTpmPcrInfoShort pcrData = (TcTpmPcrInfoShort) outDataTpm[2];
		TcTpmCapVersionInfo versionInfo = (TcTpmCapVersionInfo) outDataTpm[3];
		TcBlobData sig = (TcBlobData) outDataTpm[4];

		// validate output data
		TcBlobData[] blob1Hout = null;
		if (versionInfo == null) {
			blob1Hout = new TcBlobData[] { // 1H
			blobUINT32(resultCode), // 1S
					blobUINT32(ordinal), // 2S
					pcrData.getEncoded(), // 3S
					blobUINT32(0), // 4S
					blobUINT32(sig.getLengthAsLong()), // 6S
					sig }; // 7S

		} else {
			blob1Hout = new TcBlobData[] { // 1H
			blobUINT32(resultCode), // 1S
					blobUINT32(ordinal), // 2S
					pcrData.getEncoded(), // 3S
					blobUINT32(versionInfo.getEncoded().getLengthAsLong()), // 4S
					versionInfo.getEncoded(), // 5S
					blobUINT32(sig.getLengthAsLong()), // 6S
					sig }; // 7S
		}

		validateRespAuth(blob1Hout, inAuth1, outAuth1, privAuth.getEncoded());

		return new Object[] { outAuth1, pcrData, versionInfo, sig };
	}


	/*************************************************************************************************
	 * This method allows the owner of an entity to change the authorization data for the entity.
	 *
	 * @param context The context this call is associated with.
	 * @param parentHandle Handle of the parent key to the entity.
	 * @param protocolID The protocol in use.
	 * @param newAuth The encrypted new AuthData for the entity.
	 * @param entityType The type of entity to be modified.
	 * @param encData The encrypted entity that is to be modified.
	 * @param inAuth1 The data for the first authorization session.
	 * @param inAuth2 The data for the second authorization session.
	 * @param parentAuth HMAC key for the first authorization session.
	 * @param entityAuth HMAC key for the second authorization session.
	 * @param entityAuthVal HMAC key for validating the output of the second authorization session. On
	 *          1.2 TPMs enityAuth and entityAuthVal typically are the same (namely the new secret of
	 *          the entity). On 1.1 TPMs entityAuth is the new secret while entityAuthVal is the old
	 *          secret of the entity.
	 *
	 * @return The returned Object[] holds the following elements:
	 *         <ul>
	 *         <li> 0 ... The outgoing authorization data for first session. (TcTpmAuth)
	 *         <li> 1 ... The outgoing authorization data for second session. (TcTpmAuth)
	 *         <li> 2 ... The modified, encrypted entity. (TcBlobData)
	 *         </ul>
	 *
	 * @throws {@link TcTssException}
	 */
	public static Object[] TspChangeAuth_Internal(TcContext context, long parentHandle,
			int protocolID, TcTpmEncauth newAuth, int entityType, TcBlobData encData, TcTcsAuth inAuth1,
			TcTcsAuth inAuth2, TcTpmSecret parentAuth, TcTpmSecret entityAuth, TcTpmSecret entityAuthVal)
		throws TcTssException
	{
		CheckPrecondition.notNull(context, "context");
		CheckPrecondition.notNull(newAuth, "newAuth");
		CheckPrecondition.notNull(encData, "encData");
		CheckPrecondition.notNull(inAuth1, "inAuth1");
		CheckPrecondition.notNull(inAuth2, "inAuth2");
		CheckPrecondition.notNull(parentAuth, "parentAuth");
		CheckPrecondition.notNull(entityAuth, "entityAuth");

		long ordinal = TcTpmOrdinals.TPM_ORD_ChangeAuth;

		inAuth1.setNonceOdd(TcCrypto.createTcgNonce());
		inAuth2.setNonceOdd(TcCrypto.createTcgNonce());

		TcBlobData[] blob1H = { // 1H
		blobUINT32(ordinal), // 1S
				blobUINT16(protocolID), // 2S
				newAuth.getEncoded(), // 3S
				blobUINT16(entityType), // 4S
				blobUINT32(encData.getLengthAsLong()), // 5S
				encData }; // 6S

		TcBlobData authDataH1 = computeAuthData( //
				blob1H, // 1H1
				inAuth1, // 2H1 - 4H1
				parentAuth.getEncoded()); // HMAC key

		inAuth1.setHmac(new TcTpmAuthdata(authDataH1));

		TcBlobData authDataH2 = computeAuthData( //
				blob1H, // 1H2
				inAuth2, // 2H2 - 4H2
				entityAuth.getEncoded()); // HMAC key

		inAuth2.setHmac(new TcTpmAuthdata(authDataH2));

		// call to TCS
		TcITcsBinding tcs = context.getTcsBinding();
		Object[] outDataTpm = tcs.TcsipChangeAuth(context.getTcsContextHandle(), parentHandle,
				protocolID, newAuth, entityType, encData, inAuth1, inAuth2);

		// get return values
		long resultCode = ((Long) outDataTpm[0]).longValue();
		TcTcsAuth outAuth1 = (TcTcsAuth) outDataTpm[1];
		TcTcsAuth outAuth2 = (TcTcsAuth) outDataTpm[2];
		TcBlobData outData = (TcBlobData) outDataTpm[3];

		// validate output data
		TcBlobData[] blob1Hout = { // 1H
		blobUINT32(resultCode), // 1S
				blobUINT32(ordinal), // 2S
				blobUINT32(outData.getLengthAsLong()), // 3S
				outData }; // 4S

		validateRespAuth(blob1Hout, inAuth1, outAuth1, parentAuth.getEncoded());
		validateRespAuth(blob1Hout, inAuth2, outAuth2, entityAuthVal.getEncoded());

		return new Object[] { outAuth1, outAuth2, outData };
	}


	/*************************************************************************************************
	 * This method allows the owner of an entity to change the authorization data fro the TPM owner or
	 * the SRK.
	 *
	 * @param context The context this call is associated with.
	 * @param protocolID The protocol in use.
	 * @param newAuth The encrypted new AuthData for the entity
	 * @param entityType The type of entity to be modified
	 * @param inAuth1 The data for the authorization session.
	 * @param ownerAuth HMAC key for the authorization session.
	 *
	 * @return The outgoing authorization data for first session.
	 *
	 * @throws {@link TcTssException}
	 */
	public static TcTcsAuth TspChangeAuthOwner_Internal(TcContext context, int protocolID,
			TcTpmEncauth newAuth, int entityType, TcTcsAuth inAuth1, TcTpmSecret ownerAuth)
		throws TcTssException
	{
		CheckPrecondition.notNull(context, "context");
		CheckPrecondition.notNull(newAuth, "newAuth");
		CheckPrecondition.notNull(inAuth1, "inAuth1");
		CheckPrecondition.notNull(ownerAuth, "ownerAuth");

		long ordinal = TcTpmOrdinals.TPM_ORD_ChangeAuthOwner;

		inAuth1.setNonceOdd(TcCrypto.createTcgNonce());

		TcBlobData[] blob1H = { // 1H
		blobUINT32(ordinal), // 1S
				blobUINT16(protocolID), // 2S
				newAuth.getEncoded(), // 3S
				blobUINT16(entityType) }; // 4S

		TcBlobData authDataH1 = computeAuthData( //
				blob1H, // 1H1
				inAuth1, // 2H1 - 4H1
				ownerAuth.getEncoded()); // HMAC key

		inAuth1.setHmac(new TcTpmAuthdata(authDataH1));

		// call to TCS
		TcITcsBinding tcs = context.getTcsBinding();
		Object[] outDataTpm = tcs.TcsipChangeAuthOwner(context.getTcsContextHandle(), protocolID,
				newAuth, entityType, inAuth1);

		// get return values
		long resultCode = ((Long) outDataTpm[0]).longValue();
		TcTcsAuth outAuth1 = (TcTcsAuth) outDataTpm[1];

		// validate output data
		TcBlobData[] blob1Hout = { // 1H
		blobUINT32(resultCode), // 1S
				blobUINT32(ordinal) }; // 2S

		validateRespAuth(blob1Hout, inAuth1, outAuth1, ownerAuth.getEncoded());

		return outAuth1;
	}


	/*************************************************************************************************
	 * This method allows the creation of an authorization handle and the tracking of the handle by
	 * the TPM. THe TPM generates the handle and nonce.
	 *
	 * @param context The context this call is associated with.
	 *
	 * @return The newly generated authorization session data.
	 *
	 * @throws {@link TcTssException}
	 */
	public static TcTcsAuth TspOIAP_Internal(TcContext context) throws TcTssException
	{
		CheckPrecondition.notNull(context, "context");

		// call to TCS
		TcITcsBinding tcs = context.getTcsBinding();
		Object[] outDataTpm = tcs.TcsipOIAP(context.getTcsContextHandle());

		// get return values
		Long authHandle = (Long) outDataTpm[1];
		TcTpmNonce nonceEven = (TcTpmNonce) outDataTpm[2];

		TcTcsAuth auth = new TcTcsAuth();
		auth.setAuthHandle(authHandle.longValue());
		auth.setNonceEven(nonceEven);

		return auth;
	}


	/*************************************************************************************************
	 * This method creates the authorization handle, the shared secret and generates nonceEven and
	 * nonceEvenOSAP.
	 *
	 * @param context The context this call is associated with.
	 * @param entityType The type of entity in use.
	 * @param entityValue The selection value based on entityType, e.g. a keyHandle.
	 *
	 * @return The returned Object[] holds the following elements:
	 *         <ul>
	 *         <li> 0 ... newly generated authorization session data (TcTpmAuth)
	 *         <li> 1 ... Nonce generated by TPM and associated with shared secret. (TcTpmNonce)
	 *         </ul>
	 *
	 * @throws {@link TcTssException}
	 */
	public static Object[] TspOSAP_Internal(TcContext context, int entityType, long entityValue,
			TcTpmNonce nonceOddOSAP) throws TcTssException
	{
		CheckPrecondition.notNull(context, "context");
		CheckPrecondition.notNull(nonceOddOSAP, "nonceOddOSAP");

		// call to TCS
		TcITcsBinding tcs = context.getTcsBinding();
		Object[] outDataTpm = tcs.TcsipOSAP(context.getTcsContextHandle(), entityType, entityValue,
				nonceOddOSAP);

		// get return values
		Long authHandle = (Long) outDataTpm[1];
		TcTpmNonce nonceEven = (TcTpmNonce) outDataTpm[2];
		TcTpmNonce nonceEvenOSAP = (TcTpmNonce) outDataTpm[3];

		TcTcsAuth auth = new TcTcsAuth();
		auth.setAuthHandle(authHandle.longValue());
		auth.setNonceEven(nonceEven);

		return new Object[] { auth, nonceEvenOSAP };
	}


	/*************************************************************************************************
	 * This method opens a delegated authorization session.
	 *
	 * @param context The context this call is associated with.
	 * @param entityType The type of delegation information to use
	 * @param keyHandle Key for which delegated authority corresponds, or 0 if delegated owner
	 *          activity. Only relevant if entityValue equals TcTpmDelegateKeyBlob
	 * @param entityValue TcTpmDelegateKeyBlob or TcTpmDelegateOwnerBlob or index MUST not be empty If
	 *          entityType is TPM_ET_DEL_ROW thenentityValue is a long
	 *
	 * @return The returned Object[] holds the following elements:
	 *         <ul>
	 *         <li> 0 ... Handle that TPM creates that points to the authorization state. (Long)
	 *         <li> 1 ... Nonce generated by TPM and associated with session. (TcTpmNonce)
	 *         <li> 2 ... Nonce generated by TPM and associated with shared secret. (TcTpmNonce)
	 *         </ul>
	 *
	 * @throws {@link TcTssException}
	 */
	public static Object[] TspDSAP_Internal(TcContext context, int entityType, long keyHandle,
			TcTpmNonce nonceOddDSAP, TcBlobData entityValue) throws TcTssException
	{
		CheckPrecondition.notNull(context, "context");
		CheckPrecondition.notNull(entityValue, "entityValue");

		// call to TCS
		TcITcsBinding tcs = context.getTcsBinding();
		Object[] outDataTpm = tcs.TcsipDSAP(context.getTcsContextHandle(), entityType, keyHandle,
				nonceOddDSAP, entityValue);

		// get return values
		Long authHandle = (Long) outDataTpm[1];
		TcTpmNonce nonceEven = (TcTpmNonce) outDataTpm[2];
		TcTpmNonce nonceEvenDSAP = (TcTpmNonce) outDataTpm[3];

		return new Object[] { authHandle, nonceEven, nonceEvenDSAP };
	}


	/*************************************************************************************************
	 * This command is authorized either by the TPM owner or by physical presence. If no owner is
	 * installed, the command requires no privilege to execute. The command uses the opCode parameter
	 * with values:
	 * <ul>
	 * <li> TPM_FAMILY_CREATE to create a new family
	 * <li> TPM_FAMILY_INVALIDATE to invalidate an existing family
	 * <li> TPM_FAMILY_ENABLE to enable/disable use of a family and all the rows that belong to that
	 * family
	 * <li> TPM_FAMILY_ADMIN to lock or unlock a family against further modification. If a family is
	 * locked while there is no owner it cannot be unlocked until after ownership is established.
	 * </ul>
	 *
	 * @param context The context this call is associated with.
	 * @param familyID The familyID that is to be managed
	 * @param opCode Operation to be performed by this command.
	 * @param opData Data necessary to implement opCode
	 * @param inAuth1 The data for the authorization session.
	 * @param ownerAuth HMAC key for the authorization session.
	 *
	 * @return The returned Object[] holds the following elements:
	 *         <ul>
	 *         <li> 0 ... The outgoing authorization data for first session. (TcTpmAuth)
	 *         <li> 1 ... Returned data (TcBlobData)
	 *         </ul>
	 *
	 * @throws {@link TcTssException}
	 */
	public static Object[] TspDelegateManage_Internal(TcContext context, long familyID, long opCode,
			TcBlobData opData, TcTcsAuth inAuth1, TcTpmSecret ownerAuth) throws TcTssException
	{
		CheckPrecondition.notNull(context, "context");
		CheckPrecondition.notNull(opData, "opData");
		CheckPrecondition.notNull(inAuth1, "inAuth1");
		CheckPrecondition.notNull(ownerAuth, "ownerAuth");

		long ordinal = TcTpmOrdinals.TPM_ORD_Delegate_Manage;

		inAuth1.setNonceOdd(TcCrypto.createTcgNonce());

		TcBlobData[] blob1H = { // 1H
		blobUINT32(ordinal), // 1S
				blobUINT32(familyID) }; // 2S

		TcBlobData authDataH1 = computeAuthData( //
				blob1H, // 1H1
				inAuth1, // 2H1 - 4H1
				ownerAuth.getEncoded()); // HMAC key

		inAuth1.setHmac(new TcTpmAuthdata(authDataH1));

		// call to TCS
		TcITcsBinding tcs = context.getTcsBinding();
		Object[] outDataTpm = tcs.TcsipDelegateManage(context.getTcsContextHandle(), familyID, opCode,
				opData, inAuth1);

		// get return values
		long resultCode = ((Long) outDataTpm[0]).longValue();
		TcTcsAuth outAuth1 = (TcTcsAuth) outDataTpm[1];
		TcBlobData retData = (TcBlobData) outDataTpm[2];

		// validate output data
		TcBlobData[] blob1Hout = { // 1H
		blobUINT32(resultCode), // 1S
				blobUINT32(ordinal), // 2S
				blobUINT32(retData.getLengthAsLong()), // 3S
				retData }; // 4S

		validateRespAuth(blob1Hout, inAuth1, outAuth1, ownerAuth.getEncoded());

		return new Object[] { outAuth1, retData };
	}


	/*************************************************************************************************
	 * This method is used to delegate the privilege to us a key by creating a blob that can be used
	 * TPM_DSAP. THese blob cannot be used as input data for loading owner delegation, because the
	 * internal TPM delegate table is used to store owner delegations only.
	 *
	 * @param context The context this call is associated with.
	 * @param keyHandle The keyHandle identifier of a loaded key.
	 * @param publicInfo The public information necessary to fill in the blob
	 * @param delAuth The encrypted new AuthData for the blob. The encryption key is the shared secret
	 *          from the authorization session protocol.
	 * @param inAuth1 The data for the authorization session.
	 * @param privAuth HMAC key for the authorization session.
	 *
	 * @return The returned Object[] holds the following elements:
	 *         <ul>
	 *         <li> 0 ... The outgoing authorization data for first session. (TcTpmAuth)
	 *         <li> 1 ... The partially encrypted delegation information. (TcTpmDelegateKeyBlob)
	 *         </ul>
	 *
	 * @throws {@link TcTssException}
	 */
	public static Object[] TspDelegateCreateKeyDelegation_Internal(TcContext context, long keyHandle,
			TcTpmDelegatePublic publicInfo, TcTpmEncauth delAuth, TcTcsAuth inAuth1, TcTpmSecret privAuth)
		throws TcTssException
	{
		CheckPrecondition.notNull(context, "context");
		CheckPrecondition.notNull(publicInfo, "publicInfo");
		CheckPrecondition.notNull(delAuth, "delAuth");
		CheckPrecondition.notNull(inAuth1, "inAuth1");
		CheckPrecondition.notNull(privAuth, "privAuth");

		long ordinal = TcTpmOrdinals.TPM_ORD_Delegate_CreateKeyDelegation;

		inAuth1.setNonceOdd(TcCrypto.createTcgNonce());

		TcBlobData[] blob1H = { // 1H
		blobUINT32(ordinal), // 1S
				publicInfo.getEncoded(), // 2S
				delAuth.getEncoded() }; // 3S

		TcBlobData authDataH1 = computeAuthData( //
				blob1H, // 1H1
				inAuth1, // 2H1 - 4H1
				privAuth.getEncoded()); // HMAC key

		inAuth1.setHmac(new TcTpmAuthdata(authDataH1));

		// call to TCS
		TcITcsBinding tcs = context.getTcsBinding();
		Object[] outDataTpm = tcs.TcsipDelegateCreateKeyDelegation(context.getTcsContextHandle(),
				keyHandle, publicInfo, delAuth, inAuth1);

		// get return values
		long resultCode = ((Long) outDataTpm[0]).longValue();
		TcTcsAuth outAuth1 = (TcTcsAuth) outDataTpm[1];
		TcTpmDelegateKeyBlob blob = (TcTpmDelegateKeyBlob) outDataTpm[2];

		// validate output data
		TcBlobData[] blob1Hout = { // 1H
		blobUINT32(resultCode), // 1S
				blobUINT32(ordinal), // 2S
				blobUINT32(blob.getEncoded().getLengthAsLong()), // 3S
				blob.getEncoded() }; // 4S

		validateRespAuth(blob1Hout, inAuth1, outAuth1, privAuth.getEncoded());

		return new Object[] { outAuth1, blob };
	}


	/*************************************************************************************************
	 * This method is used to delegate owner privileges to use a set of command ordinals by creating a
	 * blob. This blob can in turn be used as input data for TPM_DSAP or DelegateLoadOwnerDelegation
	 * to provide proof of privilege. DelegateCreateKeyDelegation must be used to delegate privilege
	 * to use a key.
	 *
	 * @param context The context this call is associated with.
	 * @param increment Flag dictates whether verificationCount will be incremented
	 * @param publicInfo The public parameters for the blob
	 * @param delAuth The encrypted new AuthData for the blob. The encryption key is the shared secret
	 *          from the OSAP protocol.
	 * @param inAuth1 The data for the authorization session.
	 * @param ownerAuth HMAC key for the authorization session.
	 *
	 * @return The returned Object[] holds the following elements:
	 *         <ul>
	 *         <li> 0 ... The outgoing authorization data for first session. (TcTpmAuth)
	 *         <li> 1 ... The partially encrypted delegation information. (TcTpmDelegateOwnerBlob)
	 *         </ul>
	 *
	 * @throws {@link TcTssException}
	 */
	public static Object[] TspDelegateCreateOwnerDelegation_Internal(TcContext context,
			boolean increment, TcTpmDelegatePublic publicInfo, TcTpmEncauth delAuth, TcTcsAuth inAuth1,
			TcTpmSecret ownerAuth) throws TcTssException
	{
		CheckPrecondition.notNull(context, "context");
		CheckPrecondition.notNull(publicInfo, "publicInfo");
		CheckPrecondition.notNull(delAuth, "delAuth");
		CheckPrecondition.notNull(inAuth1, "inAuth1");
		CheckPrecondition.notNull(ownerAuth, "ownerAuth");

		long ordinal = TcTpmOrdinals.TPM_ORD_Delegate_CreateOwnerDelegation;

		inAuth1.setNonceOdd(TcCrypto.createTcgNonce());

		TcBlobData[] blob1H = { // 1H
		blobUINT32(ordinal), // 1S
				blobBOOL(increment), // 2S
				publicInfo.getEncoded(), // 3S
				delAuth.getEncoded() }; // 4S

		TcBlobData authDataH1 = computeAuthData( //
				blob1H, // 1H1
				inAuth1, // 2H1 - 4H1
				ownerAuth.getEncoded()); // HMAC key

		inAuth1.setHmac(new TcTpmAuthdata(authDataH1));

		// call to TCS
		TcITcsBinding tcs = context.getTcsBinding();
		Object[] outDataTpm = tcs.TcsipDelegateCreateOwnerDelegation(context.getTcsContextHandle(),
				increment, publicInfo, delAuth, inAuth1);

		// get return values
		long resultCode = ((Long) outDataTpm[0]).longValue();
		TcTcsAuth outAuth1 = (TcTcsAuth) outDataTpm[1];
		TcTpmDelegateOwnerBlob blob = (TcTpmDelegateOwnerBlob) outDataTpm[2];

		// validate output data
		TcBlobData[] blob1Hout = { // 1H
		blobUINT32(resultCode), // 1S
				blobUINT32(ordinal), // 2S
				blobUINT32(blob.getEncoded().getLengthAsLong()), // 3S
				blob.getEncoded() }; // 4S

		validateRespAuth(blob1Hout, inAuth1, outAuth1, ownerAuth.getEncoded());

		return new Object[] { outAuth1, blob };
	}


	/*************************************************************************************************
	 * This method is used to load an owner delegation blob into the TPM non-volatile delegation
	 * table. If an owner is installed the owner blob must be created with
	 * DelegateCreateOwnerDelegation. If an owner is not installed, the owner blob by be created
	 * outside the TPM and its TPM_DELEGATE_SENSITIVE component must be left un-encrypted.
	 *
	 * @param context The context this call is associated with.
	 * @param index The index of the delegate row to be written
	 * @param blob Delegation information, including encrypted portions as appropriate
	 * @param inAuth1 The data for the authorization session.
	 * @param ownerAuth HMAC key for the authorization session.
	 *
	 * @return The outgoing authorization data for first session.
	 *
	 * @throws {@link TcTssException}
	 */
	public static TcTcsAuth TspDelegateLoadOwnerDelegation_Internal(TcContext context, long index,
			TcTpmDelegateOwnerBlob blob, TcTcsAuth inAuth1, TcTpmSecret ownerAuth) throws TcTssException
	{
		CheckPrecondition.notNull(context, "context");
		CheckPrecondition.notNull(blob, "blob");
		CheckPrecondition.notNull(inAuth1, "inAuth1");
		CheckPrecondition.notNull(ownerAuth, "ownerAuth");

		long ordinal = TcTpmOrdinals.TPM_ORD_Delegate_LoadOwnerDelegation;

		inAuth1.setNonceOdd(TcCrypto.createTcgNonce());

		TcBlobData[] blob1H = { // 1H
		blobUINT32(ordinal), // 1S
				blobUINT32(index), // 3S
				blobUINT32(blob.getEncoded().getLengthAsLong()), // 4S
				blob.getEncoded() }; // 5S

		TcBlobData authDataH1 = computeAuthData( //
				blob1H, // 1H1
				inAuth1, // 2H1 - 4H1
				ownerAuth.getEncoded()); // HMAC key

		inAuth1.setHmac(new TcTpmAuthdata(authDataH1));

		// call to TCS
		TcITcsBinding tcs = context.getTcsBinding();
		Object[] outDataTpm = tcs.TcsipDelegateLoadOwnerDelegation(context.getTcsContextHandle(),
				index, blob, inAuth1);

		// get return values
		long resultCode = ((Long) outDataTpm[0]).longValue();
		TcTcsAuth outAuth1 = (TcTcsAuth) outDataTpm[1];

		// validate output data
		TcBlobData[] blob1Hout = { // 1H
		blobUINT32(resultCode), // 1S
				blobUINT32(ordinal) }; // 2S

		validateRespAuth(blob1Hout, inAuth1, outAuth1, ownerAuth.getEncoded());

		return outAuth1;
	}


	/*************************************************************************************************
	 * This command is used to read from the TPM the public contents of the family and delegate tables
	 * that are stored on the TPM. Such data is required during external verification of tables.
	 *
	 * There are no restrictions on the execution of this command. Anyone can read this information
	 * regardless of the state of the PCRs, regardless of whether they know any specific authorization
	 * value and regardless whether or not the enable and administrator bits are set one way or the
	 * other.
	 *
	 * @param context The context this call is associated with.
	 *
	 * @return The returned Object[] holds the following elements:
	 *         <ul>
	 *         <li> 0 ... Array of TcTpmFamilyTableEntry elements (TcBlobData)
	 *         <li> 1 ... Array of long and TcTpmDelegatePublic elements (TcBlobData)
	 *         </ul>
	 *
	 * @throws {@link TcTssException}
	 */
	public static Object[] TspDelegate_ReadTable_Internal(TcContext context) throws TcTssException
	{
		CheckPrecondition.notNull(context, "context");

		// call to TCS
		TcITcsBinding tcs = context.getTcsBinding();
		Object[] outDataTpm = tcs.TcsipDelegateReadTable(context.getTcsContextHandle());

		// remove outDataTpm[0] (the return code) from the return values
		return new Object[] { outDataTpm[1], outDataTpm[2] };
	}


	/*************************************************************************************************
	 * This method sets the cerificationCount in an entity (a blob or a delegation row) to the current
	 * family value, in order that the delegations represented by that entity will continue to be
	 * accepted by the TPM.
	 *
	 * @param context The context this call is associated with.
	 * @param inputData TcTpmDelegateKeyBlob or TcTpmDelegateOwnerBlob or long
	 * @param inAuth1 The data for the authorization session.
	 * @param ownerAuth HMAC key for the authorization session.
	 *
	 * @return The returned Object[] holds the following elements:
	 *         <ul>
	 *         <li> 0 ... The outgoing authorization data for first session. (TcTpmAuth)
	 *         <li> 1 ... TcTpmDelegateKeyBlob or TcTpmDelegateOwnerBlob (TcBlobData)
	 *         </ul>
	 *
	 * @throws {@link TcTssException}
	 */
	public static Object[] TspDelegate_UpdateVerificationCount_Internal(TcContext context,
			TcBlobData inputData, TcTcsAuth inAuth1, TcTpmSecret ownerAuth) throws TcTssException
	{
		CheckPrecondition.notNull(context, "context");
		CheckPrecondition.notNull(inputData, "inputData");
		CheckPrecondition.notNull(inAuth1, "inAuth1");
		CheckPrecondition.notNull(ownerAuth, "ownerAuth");

		long ordinal = TcTpmOrdinals.TPM_ORD_Delegate_UpdateVerification;

		inAuth1.setNonceOdd(TcCrypto.createTcgNonce());

		TcBlobData[] blob1H = { // 1H
		blobUINT32(ordinal), // 1S
				blobUINT32(inputData.getLengthAsLong()), // 2S
				inputData }; // 3S

		TcBlobData authDataH1 = computeAuthData( //
				blob1H, // 1H1
				inAuth1, // 2H1 - 4H1
				ownerAuth.getEncoded()); // HMAC key

		inAuth1.setHmac(new TcTpmAuthdata(authDataH1));

		// call to TCS
		TcITcsBinding tcs = context.getTcsBinding();
		Object[] outDataTpm = tcs.TcsipDelegateUpdateVerificationCount(context.getTcsContextHandle(),
				inputData, inAuth1);

		// get return values
		long resultCode = ((Long) outDataTpm[0]).longValue();
		TcTcsAuth outAuth1 = (TcTcsAuth) outDataTpm[1];
		TcBlobData outputData = (TcBlobData) outDataTpm[2];

		// validate output data
		TcBlobData[] blob1Hout = { // 1H
		blobUINT32(resultCode), // 1S
				blobUINT32(ordinal), // 2S
				blobUINT32(outputData.getLengthAsLong()), // 3S
				outputData }; // 4S

		validateRespAuth(blob1Hout, inAuth1, outAuth1, ownerAuth.getEncoded());

		return new Object[] { outAuth1, outputData };
	}


	/*************************************************************************************************
	 * This method interprets a delegate blob and returns success or failure, depending on whether the
	 * blob is currently valid.
	 *
	 * @param context The context this call is associated with.
	 * @param delegation TcTpmDelegateKeyBlob or TcTpmDelegateOwnerBlob
	 *
	 *
	 * @throws {@link TcTssException}
	 */
	public static void TspDelegateVerifyDelegation_Internal(TcContext context, TcBlobData delegation)
		throws TcTssException
	{
		CheckPrecondition.notNull(context, "context");
		CheckPrecondition.notNull(delegation, "delegation");

		// call to TCS
		TcITcsBinding tcs = context.getTcsBinding();
		tcs.TcsipDelegateVerifyDelegation(context.getTcsContextHandle(), delegation);
	}


	/*************************************************************************************************
	 * This command sets aside space in the TPM NVRAM and defines the access requirements necessary to
	 * read and write that space. If this function is called twice, the first time it will create the
	 * space and the second time delete it.
	 *
	 * @param context The context this call is associated with.
	 * @param pubInfo The public parameters of the NV area.
	 * @param encAuth The encrypted AuthData, only valid if the attributes require subsequent
	 *          authorization.
	 * @param inAuth1 The data for the authorization session.
	 * @param ownerAuth HMAC key for the authorization session.
	 *
	 * @return The outgoing authorization data for first session.
	 *
	 * @throws {@link TcTssException}
	 */
	public static TcTcsAuth TspNvDefineSpace_Internal(TcContext context, TcTpmNvDataPublic pubInfo,
			TcTpmEncauth encAuth, TcTcsAuth inAuth1, TcTpmSecret ownerAuth) throws TcTssException
	{
		long ordinal = TcTpmOrdinals.TPM_ORD_NV_DefineSpace;
		boolean auth = false;

		if (inAuth1 != null) {
			CheckPrecondition.notNull(context, "context");
			CheckPrecondition.notNull(pubInfo, "pubInfo");
			CheckPrecondition.notNull(encAuth, "encAuth");
			CheckPrecondition.notNull(ownerAuth, "ownerAuth");

			auth = true;

			inAuth1.setNonceOdd(TcCrypto.createTcgNonce());

			TcBlobData[] blob1H = { // 1H
			blobUINT32(ordinal), // 1S
					pubInfo.getEncoded(), // 2S
					encAuth.getEncoded() }; // 3S

			TcBlobData authDataH1 = computeAuthData( //
					blob1H, // 1H1
					inAuth1, // 2H1 - 4H1
					ownerAuth.getEncoded()); // HMAC key

			inAuth1.setHmac(new TcTpmAuthdata(authDataH1));
		}

		// call to TCS
		TcITcsBinding tcs = context.getTcsBinding();
		Object[] outDataTpm = tcs.TcsipNvDefineOrReleaseSpace(context.getTcsContextHandle(),
				pubInfo, encAuth, inAuth1);

		// get return values
		long resultCode = ((Long) outDataTpm[0]).longValue();

		if (auth) {
			TcTcsAuth outAuth1 = (TcTcsAuth) outDataTpm[1];

			// validate output data
			TcBlobData[] blob1Hout = { // 1H
			blobUINT32(resultCode), // 1S
					blobUINT32(ordinal) }; // 2S

			validateRespAuth(blob1Hout, inAuth1, outAuth1, ownerAuth.getEncoded());

			return outAuth1;
		}

		return null;
	}


	/*************************************************************************************************
	 * This command writes the value to a defined area. The write can be TPM owner authorized or
	 * unauthorized and protected by other attributes and will work when no TPM owner is present.
	 *
	 * @param context The context this call is associated with.
	 * @param nvIndex The index of the area to set.
	 * @param offset The offset into the NV Area.
	 * @param data The data to set the area to.
	 * @param inAuth1 The data for the authorization session.
	 * @param ownerAuth HMAC key for the authorization session.
	 *
	 * @return The outgoing authorization data for first session.
	 *
	 * @throws {@link TcTssException}
	 */
	public static TcTcsAuth TspNvWriteValue_Internal(TcContext context, long nvIndex, long offset,
			TcBlobData data, TcTcsAuth inAuth1, TcTpmSecret ownerAuth) throws TcTssException
	{
		CheckPrecondition.notNull(context, "context");
		CheckPrecondition.notNull(data, "data");
		CheckPrecondition.notNull(inAuth1, "inAuth1");
		CheckPrecondition.notNull(ownerAuth, "ownerAuth");

		long ordinal = TcTpmOrdinals.TPM_ORD_NV_WriteValue;

		inAuth1.setNonceOdd(TcCrypto.createTcgNonce());

		TcBlobData[] blob1H = { // 1H
		blobUINT32(ordinal), // 1S
				blobUINT32(nvIndex), // 2S
				blobUINT32(offset), // 3S
				blobUINT32(data.getLengthAsLong()), // 4S
				data }; // 5S

		TcBlobData authDataH1 = computeAuthData( //
				blob1H, // 1H1
				inAuth1, // 2H1 - 4H1
				ownerAuth.getEncoded()); // HMAC key

		inAuth1.setHmac(new TcTpmAuthdata(authDataH1));

		// call to TCS
		TcITcsBinding tcs = context.getTcsBinding();
		Object[] outDataTpm = tcs.TcsipNvWriteValue(context.getTcsContextHandle(), nvIndex, offset,
				data, inAuth1);

		// get return values
		long resultCode = ((Long) outDataTpm[0]).longValue();
		TcTcsAuth outAuth1 = (TcTcsAuth) outDataTpm[1];

		// validate output data
		TcBlobData[] blob1Hout = { // 1H
		blobUINT32(resultCode), // 1S
				blobUINT32(ordinal) }; // 2S

		validateRespAuth(blob1Hout, inAuth1, outAuth1, ownerAuth.getEncoded());

		return outAuth1;
	}


	/*************************************************************************************************
	 * This command writes a previously defined area. The area must require authorization to write.
	 * This command is for using when authorization other than the owner authorization is to be used.
	 *
	 * @param context The context this call is associated with.
	 * @param nvIndex The index of the area to set
	 * @param offset The offset into the chunk
	 * @param data The data to set the area to
	 * @param inAuth1 The data for the authorization session.
	 * @param authValue HMAC key for the authorization session.
	 *
	 * @return The outgoing authorization data for first session.
	 *
	 * @throws {@link TcTssException}
	 */
	public static TcTcsAuth TspNvWriteValueAuth_Internal(TcContext context, long nvIndex,
			long offset, TcBlobData data, TcTcsAuth inAuth1, TcTpmSecret authValue) throws TcTssException
	{
		CheckPrecondition.notNull(context, "context");
		CheckPrecondition.notNull(data, "data");
		CheckPrecondition.notNull(inAuth1, "inAuth1");
		CheckPrecondition.notNull(authValue, "authValue");

		long ordinal = TcTpmOrdinals.TPM_ORD_NV_WriteValueAuth;

		inAuth1.setNonceOdd(TcCrypto.createTcgNonce());

		TcBlobData[] blob1H = { // 1H
		blobUINT32(ordinal), // 1S
				blobUINT32(nvIndex), // 2S
				blobUINT32(offset), // 3S
				blobUINT32(data.getLengthAsLong()), // 4S
				data }; // 5S

		TcBlobData authDataH1 = computeAuthData( //
				blob1H, // 1H1
				inAuth1, // 2H1 - 4H1
				authValue.getEncoded()); // HMAC key

		inAuth1.setHmac(new TcTpmAuthdata(authDataH1));

		// call to TCS
		TcITcsBinding tcs = context.getTcsBinding();
		Object[] outDataTpm = tcs.TcsipNvWriteValueAuth(context.getTcsContextHandle(), nvIndex, offset,
				data, inAuth1);

		// get return values
		long resultCode = ((Long) outDataTpm[0]).longValue();
		TcTcsAuth outAuth1 = (TcTcsAuth) outDataTpm[1];

		// validate output data
		TcBlobData[] blob1Hout = { // 1H
		blobUINT32(resultCode), // 1S
				blobUINT32(ordinal) }; // 2S

		validateRespAuth(blob1Hout, inAuth1, outAuth1, authValue.getEncoded());

		return outAuth1;
	}


	/*************************************************************************************************
	 * This method reads a value from the NV store. THis command uses optional owner authorization.
	 *
	 * @param context The context this call is associated with.
	 * @param nvIndex The index of the area to set
	 * @param offset The offset into the area
	 * @param dataSz The size of the data area
	 * @param inAuth1 The data for the authorization session.
	 * @param ownerAuth HMAC key for the authorization session.
	 *
	 * @return The returned Object[] holds the following elements:
	 *         <ul>
	 *         <li> 0 ... The outgoing authorization data for first session. (TcTpmAuth)
	 *         <li> 1 ... The data to set the area to (TcBlobData)
	 *         </ul>
	 *
	 * @throws {@link TcTssException}
	 */
	public static Object[] TspNvReadValue_Internal(TcContext context, long nvIndex, long offset,
			long dataSz, TcTcsAuth inAuth1, TcTpmSecret ownerAuth) throws TcTssException
	{
		CheckPrecondition.notNull(context, "context");
		// inAuth can be null
		if (inAuth1 != null) {
			CheckPrecondition.notNull(ownerAuth, "ownerAuth");
		}

		long ordinal = TcTpmOrdinals.TPM_ORD_NV_ReadValue;

		if (inAuth1 != null) {
			inAuth1.setNonceOdd(TcCrypto.createTcgNonce());

			TcBlobData[] blob1H = { // 1H
			blobUINT32(ordinal), // 1S
					blobUINT32(nvIndex), // 2S
					blobUINT32(offset), // 3S
					blobUINT32(dataSz) }; // 4S

			TcBlobData authDataH1 = computeAuthData( //
					blob1H, // 1H1
					inAuth1, // 2H1 - 4H1
					ownerAuth.getEncoded()); // HMAC key

			inAuth1.setHmac(new TcTpmAuthdata(authDataH1));
		}
		// call to TCS
		TcITcsBinding tcs = context.getTcsBinding();
		Object[] outDataTpm = tcs.TcsipNvReadValue(context.getTcsContextHandle(), nvIndex, offset,
				dataSz, inAuth1);

		// get return values
		long resultCode = ((Long) outDataTpm[0]).longValue();
		TcTcsAuth outAuth1 = (TcTcsAuth) outDataTpm[1];
		TcBlobData data = (TcBlobData) outDataTpm[2];

		// validate output data
		if (inAuth1 != null) {
			TcBlobData[] blob1Hout = { // 1H
			blobUINT32(resultCode), // 1S
					blobUINT32(ordinal), // 2S
					blobUINT32(data.getLengthAsLong()), // 3S
					data }; // 4S

			validateRespAuth(blob1Hout, inAuth1, outAuth1, ownerAuth.getEncoded());
		}

		return new Object[] { outAuth1, data };
	}


	/*************************************************************************************************
	 * This method reads a value from the NV store. THis command uses optional owner authorization.
	 *
	 * @param context The context this call is associated with.
	 * @param nvIndex The index of the area to set
	 * @param offset The offset from the data area
	 * @param dataSz The size of the data area
	 * @param inAuth1 The data for the authorization session.
	 * @param authHmac HMAC key for the authorization session.
	 *
	 * @return The returned Object[] holds the following elements:
	 *         <ul>
	 *         <li> 0 ... The outgoing authorization data for first session. (TcTpmAuth)
	 *         <li> 1 ... The data (TcBlobData)
	 *         </ul>
	 *
	 * @throws {@link TcTssException}
	 */
	public static Object[] TspNvReadValueAuth_Internal(TcContext context, long nvIndex, long offset,
			long dataSz, TcTcsAuth inAuth1, TcTpmSecret authHmac) throws TcTssException
	{
		CheckPrecondition.notNull(context, "context");
		CheckPrecondition.notNull(inAuth1, "inAuth1");
		CheckPrecondition.notNull(authHmac, "authHmac");

		long ordinal = TcTpmOrdinals.TPM_ORD_NV_ReadValueAuth;

		inAuth1.setNonceOdd(TcCrypto.createTcgNonce());

		TcBlobData[] blob1H = { // 1H
		blobUINT32(ordinal), // 1S
				blobUINT32(nvIndex), // 2S
				blobUINT32(offset), // 3S
				blobUINT32(dataSz) }; // 4S

		TcBlobData authDataH1 = computeAuthData( //
				blob1H, // 1H1
				inAuth1, // 2H1 - 4H1
				authHmac.getEncoded()); // HMAC key

		inAuth1.setHmac(new TcTpmAuthdata(authDataH1));

		// call to TCS
		TcITcsBinding tcs = context.getTcsBinding();
		Object[] outDataTpm = tcs.TcsipNvReadValueAuth(context.getTcsContextHandle(), nvIndex, offset,
				dataSz, inAuth1);

		// get return values
		long resultCode = ((Long) outDataTpm[0]).longValue();
		TcTcsAuth outAuth1 = (TcTcsAuth) outDataTpm[1];
		TcBlobData data = (TcBlobData) outDataTpm[2];

		// validate output data
		TcBlobData[] blob1Hout = { // 1H
		blobUINT32(resultCode), // 1S
				blobUINT32(ordinal), // 2S
				blobUINT32(data.getLengthAsLong()), // 3S
				data }; // 4S

		validateRespAuth(blob1Hout, inAuth1, outAuth1, authHmac.getEncoded());

		return new Object[] { outAuth1, data };
	}


	/*************************************************************************************************
	 * This method reads the current tick out of the TPM.
	 *
	 * @param context The context this call is associated with.
	 *
	 * @return The current time held in the TPM.
	 *
	 * @throws {@link TcTssException}
	 */
	public static TcTpmCurrentTicks TspReadCurrentTicks_Internal(TcContext context)
		throws TcTssException
	{
		CheckPrecondition.notNull(context, "context");

		// call to TCS
		TcITcsBinding tcs = context.getTcsBinding();
		Object[] outDataTpm = tcs.TcsipReadCurrentTicks(context.getTcsContextHandle());

		// get return values
		TcTpmCurrentTicks currentTime = (TcTpmCurrentTicks) outDataTpm[1];

		return currentTime;
	}


	/*************************************************************************************************
	 * This method is similar to a time stamp: it associates a tick value with a blob, indicating that
	 * the blob existed at some point earlier than the time corresponding to the tick value.
	 *
	 * @param context The context this call is associated with.
	 * @param keyHandle The keyHandle identifier of a loaded key that can perform digital signatures.
	 * @param antiReplay Anti replay value added to signature
	 * @param digestToStamp The digest to perform the tick stamp on
	 * @param inAuth1 The data for the authorization session.
	 * @param privAuth HMAC key for the authorization session.
	 *
	 * @return The returned Object[] holds the following elements:
	 *         <ul>
	 *         <li> 0 ... The outgoing authorization data for first session. (TcTpmAuth)
	 *         <li> 1 ... The current time according to the TPM (TcTpmCurrentTicks)
	 *         <li> 2 ... The resulting digital signature. (TcBlobData)
	 *         </ul>
	 *
	 * @throws {@link TcTssException}
	 */
	public static Object[] TspTickStampBlob_Internal(TcContext context, long keyHandle,
			TcTpmNonce antiReplay, TcTpmDigest digestToStamp, TcTcsAuth inAuth1, TcTpmSecret privAuth)
		throws TcTssException
	{
		CheckPrecondition.notNull(context, "context");
		CheckPrecondition.notNull(antiReplay, "antiReplay");
		CheckPrecondition.notNull(digestToStamp, "digestToStamp");
		CheckPrecondition.notNull(inAuth1, "inAuth1");
		CheckPrecondition.notNull(privAuth, "privAuth");

		long ordinal = TcTpmOrdinals.TPM_ORD_TickStampBlob;

		inAuth1.setNonceOdd(TcCrypto.createTcgNonce());

		TcBlobData[] blob1H = { // 1H
		blobUINT32(ordinal), // 1S
				antiReplay.getEncoded(), // 2S
				digestToStamp.getEncoded() }; // 3S

		TcBlobData authDataH1 = computeAuthData( //
				blob1H, // 1H1
				inAuth1, // 2H1 - 4H1
				privAuth.getEncoded()); // HMAC key

		inAuth1.setHmac(new TcTpmAuthdata(authDataH1));

		// call to TCS
		TcITcsBinding tcs = context.getTcsBinding();
		Object[] outDataTpm = tcs.TcsipTickStampBlob(context.getTcsContextHandle(), keyHandle,
				antiReplay, digestToStamp, inAuth1);

		// get return values
		long resultCode = ((Long) outDataTpm[0]).longValue();
		TcTcsAuth outAuth1 = (TcTcsAuth) outDataTpm[1];
		TcTpmCurrentTicks currentTicks = (TcTpmCurrentTicks) outDataTpm[2];
		TcBlobData sig = (TcBlobData) outDataTpm[3];

		// validate output data
		TcBlobData[] blob1Hout = { // 1H
		blobUINT32(resultCode), // 1S
				blobUINT32(ordinal), // 2S
				currentTicks.getEncoded(), // 3S
				blobUINT32(sig.getLengthAsLong()), // 4S
				sig }; // 5S

		validateRespAuth(blob1Hout, inAuth1, outAuth1, privAuth.getEncoded());

		return new Object[] { outAuth1, currentTicks, sig };
	}


	/*************************************************************************************************
	 *
	 *
	 * @param context The context this call is associated with.
	 * @param encHandle The handle to the key that encrypted the blob
	 * @param transPublic The public information describing the transport session
	 * @param secret The encrypted secret area
	 * @param inAuth1 The data for the authorization session.
	 * @param keyAuth HMAC key for the authorization session.
	 *
	 * @return The returned Object[] holds the following elements:
	 *         <ul>
	 *         <li> 0 ... The outgoing authorization data for first session. (TcTpmAuth)
	 *         <li> 1 ... The handle for the transport session (Long)
	 *         <li> 2 ... The locality that called this command (Long)
	 *         <li> 3 ... The current tick count (TcTpmCurrentTicks)
	 *         <li> 4 ... The even nonce in use for subsequent execute transport (TcTpmNonce)
	 *         </ul>
	 *
	 * @throws {@link TcTssException}
	 */
	public static Object[] TspEstablishTransport_Internal(TcContext context, long encHandle,
			TcTpmTransportPublic transPublic, TcBlobData secret, TcTcsAuth inAuth1, TcTpmSecret keyAuth)
		throws TcTssException
	{
		CheckPrecondition.notNull(context, "context");
		CheckPrecondition.notNull(transPublic, "transPublic");
		CheckPrecondition.notNull(secret, "secret");
		if (encHandle != TcTpmConstants.TPM_KH_TRANSPORT) {
			CheckPrecondition.notNull(inAuth1, "inAuth1");
			CheckPrecondition.notNull(keyAuth, "keyAuth");
		}

		long ordinal = TcTpmOrdinals.TPM_ORD_EstablishTransport;

		if (encHandle != TcTpmConstants.TPM_KH_TRANSPORT) {
			inAuth1.setNonceOdd(TcCrypto.createTcgNonce());

			TcBlobData[] blob1H = { // 1H
			blobUINT32(ordinal), // 1S
					transPublic.getEncoded(), // 2S
					blobUINT32(secret.getLengthAsLong()), // 3S
					secret }; // 4S

			TcBlobData authDataH1 = computeAuthData( //
					blob1H, // 1H1
					inAuth1, // 2H1 - 4H1
					keyAuth.getEncoded()); // HMAC key

			inAuth1.setHmac(new TcTpmAuthdata(authDataH1));
		}

		// call to TCS
		TcITcsBinding tcs = context.getTcsBinding();
		Object[] outDataTpm = tcs.TcsEstablishTransport(context.getTcsContextHandle(), encHandle,
				transPublic, secret, inAuth1);

		// get return values
		long resultCode = ((Long) outDataTpm[0]).longValue();
		TcTcsAuth outAuth1 = (TcTcsAuth) outDataTpm[1];
		Long transHandle = (Long) outDataTpm[2];
		Long locality = (Long) outDataTpm[3];
		TcTpmCurrentTicks currentTicks = (TcTpmCurrentTicks) outDataTpm[4];
		TcTpmNonce transNonceEven = (TcTpmNonce) outDataTpm[5];

		// validate output data
		if (encHandle != TcTpmConstants.TPM_KH_TRANSPORT) {
			TcBlobData[] blob1Hout = { // 1H
			blobUINT32(resultCode), // 1S
					blobUINT32(ordinal), // 2S
					blobUINT32(locality.longValue()), // 3S
					currentTicks.getEncoded(), // 4S
					transNonceEven.getEncoded() }; // 5S

			validateRespAuth(blob1Hout, inAuth1, outAuth1, keyAuth.getEncoded());
		}

		return new Object[] { outAuth1, transHandle, locality, currentTicks, transNonceEven };
	}


	/*************************************************************************************************
	 *
	 *
	 * @param context The context this call is associated with.
	 * @param wrappedCmd The wrapped command
	 * @param transHandle The transport session handle
	 * @param inAuth1 The data for the authorization session.
	 * @param transAuth HMAC key for the authorization session.
	 *
	 * @return The returned Object[] holds the following elements:
	 *         <ul>
	 *         <li> 0 ... The outgoing authorization data for first session. (TcTpmAuth)
	 *         <li> 1 ... The current ticks when the command was executed (Long)
	 *         <li> 2 ... The locality that called this command (Long)
	 *         <li> 3 ... The wrapped response (TcBlobData)
	 *         </ul>
	 *
	 * @throws {@link TcTssException}
	 */
	public static Object[] TspExecuteTransport_Internal(TcContext context, TcBlobData wrappedCmd,
			long transHandle, TcTcsAuth inAuth1, TcTpmSecret transAuth) throws TcTssException
	{
		CheckPrecondition.notNull(context, "context");
		CheckPrecondition.notNull(wrappedCmd, "wrappedCmd");
		CheckPrecondition.notNull(inAuth1, "inAuth1");
		CheckPrecondition.notNull(transAuth, "transAuth");

		long ordinal = TcTpmOrdinals.TPM_ORD_ExecuteTransport;

		inAuth1.setNonceOdd(TcCrypto.createTcgNonce());

		TcBlobData[] blob1H = { // 1H
		blobUINT32(ordinal), // 1S
				blobUINT32(wrappedCmd.getLengthAsLong()), // 2S
				wrappedCmd }; // 3S

		TcBlobData authDataH1 = computeAuthData( //
				blob1H, // 1H1
				inAuth1, // 2H1 - 4H1
				transAuth.getEncoded()); // HMAC key

		inAuth1.setHmac(new TcTpmAuthdata(authDataH1));

		// call to TCS
		TcITcsBinding tcs = context.getTcsBinding();
		Object[] outDataTpm = tcs.TcsExecuteTransport(context.getTcsContextHandle(), wrappedCmd,
				transHandle, inAuth1);

		// get return values
		long resultCode = ((Long) outDataTpm[0]).longValue();
		TcTcsAuth outAuth1 = (TcTcsAuth) outDataTpm[1];
		Long currentTicks = (Long) outDataTpm[2];
		Long locality = (Long) outDataTpm[3];
		TcBlobData wrappedRsp = (TcBlobData) outDataTpm[4];

		// validate output data
		TcBlobData[] blob1Hout = { // 1H
		blobUINT32(resultCode), // 1S
				blobUINT32(ordinal), // 2S
				blobUINT32(currentTicks.longValue()), // 3S
				blobUINT32(locality.longValue()), // 4S
				blobUINT32(wrappedRsp.getLengthAsLong()), // 5S
				wrappedRsp }; // 6S

		validateRespAuth(blob1Hout, inAuth1, outAuth1, transAuth.getEncoded());

		return new Object[] { outAuth1, currentTicks, locality, wrappedRsp };
	}


	/*************************************************************************************************
	 *
	 *
	 * @param context The context this call is associated with.
	 * @param keyHandle Handle of a loaded key that will perform the signing
	 * @param antiReplay Value provided by caller for anti-replay protection
	 * @param transHandle The transport session handle
	 * @param inAuth1 The data for the first authorization session.
	 * @param inAuth2 The data for the second authorization session.
	 * @param keyAuth HMAC key for the first authorization session.
	 * @param transAuth HMAC key for the second authorization session.
	 *
	 * @return The returned Object[] holds the following elements:
	 *         <ul>
	 *         <li> 0 ... The outgoing authorization data for first session. (TcTpmAuth)
	 *         <li> 1 ... The outgoing authorization data for second session. (TcTpmAuth)
	 *         <li> 2 ... The locality that called this command (Long)
	 *         <li> 3 ... The current ticks when the command executed (TcTpmCurrentTicks)
	 *         <li> 4 ... The signature of the digest (TcBlobData)
	 *         </ul>
	 *
	 * @throws {@link TcTssException}
	 */
	public static Object[] TspReleaseTransportSigned_Internal(TcContext context, long keyHandle,
			TcTpmNonce antiReplay, long transHandle, TcTcsAuth inAuth1, TcTcsAuth inAuth2,
			TcTpmSecret keyAuth, TcTpmSecret transAuth) throws TcTssException
	{
		CheckPrecondition.notNull(context, "context");
		CheckPrecondition.notNull(antiReplay, "antiReplay");
		CheckPrecondition.notNull(inAuth1, "inAuth1");
		CheckPrecondition.notNull(inAuth2, "inAuth2");
		CheckPrecondition.notNull(keyAuth, "keyAuth");
		CheckPrecondition.notNull(transAuth, "transAuth");

		long ordinal = TcTpmOrdinals.TPM_ORD_ReleaseTransportSigned;

		inAuth1.setNonceOdd(TcCrypto.createTcgNonce());
		inAuth2.setNonceOdd(TcCrypto.createTcgNonce());

		TcBlobData[] blob1H = { // 1H
		blobUINT32(ordinal), // 1S
				antiReplay.getEncoded() }; // 2S

		TcBlobData authDataH1 = computeAuthData( //
				blob1H, // 1H1
				inAuth1, // 2H1 - 4H1
				keyAuth.getEncoded()); // HMAC key

		inAuth1.setHmac(new TcTpmAuthdata(authDataH1));

		TcBlobData authDataH2 = computeAuthData( //
				blob1H, // 1H2
				inAuth2, // 2H2 - 4H2
				transAuth.getEncoded()); // HMAC key

		inAuth2.setHmac(new TcTpmAuthdata(authDataH2));

		// call to TCS
		TcITcsBinding tcs = context.getTcsBinding();
		Object[] outDataTpm = tcs.TcsReleaseTransportSigned(context.getTcsContextHandle(), keyHandle,
				antiReplay, transHandle, inAuth1, inAuth2);

		// get return values
		long resultCode = ((Long) outDataTpm[0]).longValue();
		TcTcsAuth outAuth1 = (TcTcsAuth) outDataTpm[1];
		TcTcsAuth outAuth2 = (TcTcsAuth) outDataTpm[2];
		Long locality = (Long) outDataTpm[3];
		TcTpmCurrentTicks currentTicks = (TcTpmCurrentTicks) outDataTpm[4];
		TcBlobData signature = (TcBlobData) outDataTpm[5];

		// validate output data
		TcBlobData[] blob1Hout = { // 1H
		blobUINT32(resultCode), // 1S
				blobUINT32(ordinal), // 2S
				blobUINT32(locality.longValue()), // 3S
				currentTicks.getEncoded(), // 4S
				blobUINT32(signature.getLengthAsLong()), // 5S
				signature }; // 6S

		validateRespAuth(blob1Hout, inAuth1, outAuth1, keyAuth.getEncoded());
		validateRespAuth(blob1Hout, inAuth2, outAuth2, transAuth.getEncoded());

		return new Object[] { outAuth1, outAuth2, locality, currentTicks, signature };
	}


	/*************************************************************************************************
	 * This method creates a new counter in the TPM. It does NOT select that counter. Counter creation
	 * assigns an authorization value to the counter and sets the counters original start value to be
	 * one more that the internal base counter. The label length has the be 4.
	 *
	 * @param context The context this call is associated with.
	 * @param encAuth The encrypted authorization data for the new counter
	 * @param label Label to associate with counter
	 * @param inAuth1 The data for the authorization session.
	 * @param ownerAuth HMAC key for the authorization session.
	 *
	 * @return The returned Object[] holds the following elements:
	 *         <ul>
	 *         <li> 0 ... The outgoing authorization data for first session. (TcTpmAuth)
	 *         <li> 1 ... The handle for the counter (Long)
	 *         <li> 2 ... The starting counter value (TcTpmCounterValue)
	 *         </ul>
	 *
	 * @throws {@link TcTssException}
	 */
	public static Object[] TspCreateCounter_Internal(TcContext context, TcTpmEncauth encAuth,
			TcBlobData label, TcTcsAuth inAuth1, TcTpmSecret ownerAuth) throws TcTssException
	{
		CheckPrecondition.notNull(context, "context");
		CheckPrecondition.notNull(encAuth, "encAuth");
		CheckPrecondition.notNull(inAuth1, "inAuth1");
		CheckPrecondition.notNull(ownerAuth, "ownerAuth");
		CheckPrecondition.notNull(label, "label");
		CheckPrecondition.equal(label.getLengthAsLong(), 4, "label");

		long ordinal = TcTpmOrdinals.TPM_ORD_CreateCounter;

		inAuth1.setNonceOdd(TcCrypto.createTcgNonce());

		TcBlobData[] blob1H = { // 1H
			blobUINT32(ordinal), // 1S
			encAuth.getEncoded(), // 2S
			label }; // 3S

		TcBlobData authDataH1 = computeAuthData( //
				blob1H, // 1H1
				inAuth1, // 2H1 - 4H1
				ownerAuth.getEncoded()); // HMAC key

		inAuth1.setHmac(new TcTpmAuthdata(authDataH1));

		// call to TCS
		TcITcsBinding tcs = context.getTcsBinding();
		Object[] outDataTpm = tcs.TcsipCreateCounter(context.getTcsContextHandle(), label, encAuth,
				inAuth1);

		// get return values
		long resultCode = ((Long) outDataTpm[0]).longValue();
		TcTcsAuth outAuth1 = (TcTcsAuth) outDataTpm[1];
		Long countID = (Long) outDataTpm[2];
		TcTpmCounterValue counterValue = (TcTpmCounterValue) outDataTpm[3];

		// validate output data
		TcBlobData[] blob1Hout = { // 1H
		blobUINT32(resultCode), // 1S
				blobUINT32(ordinal), // 2S
				blobUINT32(countID.longValue()), // 3S
				counterValue.getEncoded() }; // 4S

		validateRespAuth(blob1Hout, inAuth1, outAuth1, ownerAuth.getEncoded());

		return new Object[] { outAuth1, countID, counterValue };
	}


	/*************************************************************************************************
	 * This method selects a counter if one has not yet been selected, and increments that counter
	 * register. If a counter has already been selected and it is different from the one requested,
	 * the increment counter will fail. To change the selected counter, the TPM must go through a
	 * startup cycle.
	 *
	 * @param context The context this call is associated with.
	 * @param countID The handle of a valid counter
	 * @param inAuth1 The data for the authorization session.
	 * @param counterAuth HMAC key for the authorization session.
	 *
	 * @return The returned Object[] holds the following elements:
	 *         <ul>
	 *         <li> 0 ... The outgoing authorization data for first session. (TcTpmAuth)
	 *         <li> 1 ... The counter value (TcTpmCounterValue)
	 *         </ul>
	 *
	 * @throws {@link TcTssException}
	 */
	public static Object[] TspIncrementCounter_Internal(TcContext context, long countID,
			TcTcsAuth inAuth1, TcTpmSecret counterAuth) throws TcTssException
	{
		CheckPrecondition.notNull(context, "context");
		CheckPrecondition.notNull(inAuth1, "inAuth1");
		CheckPrecondition.notNull(counterAuth, "counterAuth");

		long ordinal = TcTpmOrdinals.TPM_ORD_IncrementCounter;

		inAuth1.setNonceOdd(TcCrypto.createTcgNonce());

		TcBlobData[] blob1H = { // 1H
		blobUINT32(ordinal),  // 1S
		blobUINT32(countID) }; // 2s

		TcBlobData authDataH1 = computeAuthData( //
				blob1H, // 1H1
				inAuth1, // 2H1 - 4H1
				counterAuth.getEncoded()); // HMAC key

		inAuth1.setHmac(new TcTpmAuthdata(authDataH1));

		// call to TCS
		TcITcsBinding tcs = context.getTcsBinding();
		Object[] outDataTpm = tcs
				.TcsipIncrementCounter(context.getTcsContextHandle(), countID, inAuth1);

		// get return values
		long resultCode = ((Long) outDataTpm[0]).longValue();
		TcTcsAuth outAuth1 = (TcTcsAuth) outDataTpm[1];
		TcTpmCounterValue count = (TcTpmCounterValue) outDataTpm[2];

		// validate output data
		TcBlobData[] blob1Hout = { // 1H
		blobUINT32(resultCode), // 1S
				blobUINT32(ordinal), // 2S
				count.getEncoded() }; // 3S

		validateRespAuth(blob1Hout, inAuth1, outAuth1, counterAuth.getEncoded());

		return new Object[] { outAuth1, count };
	}


	/*************************************************************************************************
	 * This method reads the current value of a counter register.
	 *
	 * @param context The context this call is associated with.
	 * @param countID ID value of the counter
	 *
	 * @return The counter value
	 *
	 * @throws {@link TcTssException}
	 */
	public static TcTpmCounterValue TspReadCounter_Internal(TcContext context, long countID)
		throws TcTssException
	{
		CheckPrecondition.notNull(context, "context");
		// call to TCS
		TcITcsBinding tcs = context.getTcsBinding();
		Object[] outDataTpm = tcs.TcsipReadCounter(context.getTcsContextHandle(), countID);

		// get return values
		TcTpmCounterValue count = (TcTpmCounterValue) outDataTpm[1];

		return count;
	}


	/*************************************************************************************************
	 * This method releases a counter so that no reads or increments of the indicated counter will
	 * succeed. It invalidates all information regarding that counter, including the counter handle.
	 *
	 * @param context The context this call is associated with.
	 * @param countID ID value of the counter
	 * @param inAuth1 The data for the authorization session.
	 * @param counterAuth HMAC key for the authorization session.
	 *
	 * @return The outgoing authorization data for first session.
	 *
	 * @throws {@link TcTssException}
	 */
	public static TcTcsAuth TspReleaseCounter_Internal(TcContext context, long countID,
			TcTcsAuth inAuth1, TcTpmSecret counterAuth) throws TcTssException
	{
		CheckPrecondition.notNull(context, "context");
		CheckPrecondition.notNull(inAuth1, "inAuth1");
		CheckPrecondition.notNull(counterAuth, "counterAuth");

		long ordinal = TcTpmOrdinals.TPM_ORD_ReleaseCounter;

		inAuth1.setNonceOdd(TcCrypto.createTcgNonce());

		TcBlobData[] blob1H = { // 1H
		blobUINT32(ordinal),  // 1S
    blobUINT32(countID) }; // 2s

		TcBlobData authDataH1 = computeAuthData( //
				blob1H, // 1H1
				inAuth1, // 2H1 - 4H1
				counterAuth.getEncoded()); // HMAC key

		inAuth1.setHmac(new TcTpmAuthdata(authDataH1));

		// call to TCS
		TcITcsBinding tcs = context.getTcsBinding();
		Object[] outDataTpm = tcs.TcsipReleaseCounter(context.getTcsContextHandle(), countID, inAuth1);

		// get return values
		long resultCode = ((Long) outDataTpm[0]).longValue();
		TcTcsAuth outAuth1 = (TcTcsAuth) outDataTpm[1];

		// validate output data
		TcBlobData[] blob1Hout = { // 1H
		blobUINT32(resultCode), // 1S
				blobUINT32(ordinal) }; // 2S

		validateRespAuth(blob1Hout, inAuth1, outAuth1, counterAuth.getEncoded());

		return outAuth1;
	}


	/*************************************************************************************************
	 * This method releases a counter so that no reads or increments of the indicated counter will
	 * succeed. It invalidates all information regarding that counter, including the counter handle.
	 * It differs from TspReleaseCounter_Internal in that it requires TPM owner authorization instead
	 * of authorization for the counter.
	 *
	 * @param context The context this call is associated with.
	 * @param countID ID value of the counter
	 * @param inAuth1 The data for the authorization session.
	 * @param ownerAuth HMAC key for the authorization session.
	 *
	 * @return The outgoing authorization data for first session.
	 *
	 * @throws {@link TcTssException}
	 */
	public static TcTcsAuth TspReleaseCounterOwner_Internal(TcContext context, long countID,
			TcTcsAuth inAuth1, TcTpmSecret ownerAuth) throws TcTssException
	{
		CheckPrecondition.notNull(context, "context");
		CheckPrecondition.notNull(inAuth1, "inAuth1");
		CheckPrecondition.notNull(ownerAuth, "ownerAuth");

		long ordinal = TcTpmOrdinals.TPM_ORD_ReleaseCounterOwner;

		inAuth1.setNonceOdd(TcCrypto.createTcgNonce());

		TcBlobData[] blob1H = { // 1H
		blobUINT32(ordinal) }; // 1S

		TcBlobData authDataH1 = computeAuthData( //
				blob1H, // 1H1
				inAuth1, // 2H1 - 4H1
				ownerAuth.getEncoded()); // HMAC key

		inAuth1.setHmac(new TcTpmAuthdata(authDataH1));

		// call to TCS
		TcITcsBinding tcs = context.getTcsBinding();
		Object[] outDataTpm = tcs.TcsipReleaseCounterOwner(context.getTcsContextHandle(), countID,
				inAuth1);

		// get return values
		long resultCode = ((Long) outDataTpm[0]).longValue();
		TcTcsAuth outAuth1 = (TcTcsAuth) outDataTpm[1];

		// validate output data
		TcBlobData[] blob1Hout = { // 1H
		blobUINT32(resultCode), // 1S
				blobUINT32(ordinal) }; // 2S

		validateRespAuth(blob1Hout, inAuth1, outAuth1, ownerAuth.getEncoded());

		return outAuth1;
	}


	/*************************************************************************************************
	 * This method executes a TPM DAA join command.
	 *
	 * @param context The context this call is associated with.
	 * @param handle Session handle
	 * @param stage Processing stage of join
	 * @param inputData0 Data to be used by this capability
	 * @param inputData1 Data to be used by this capability
	 * @param inAuth1 The data for the authorization session.
	 * @param ownerAuth HMAC key for the authorization session.
	 *
	 * @return The returned Object[] holds the following elements:
	 *         <ul>
	 *         <li> 0 ... The outgoing authorization data for first session. (TcTpmAuth)
	 *         <li> 1 ... Data produced by this capability (TcBlobData)
	 *         </ul>
	 *
	 * @throws {@link TcTssException}
	 */
	public static Object[] TspDaaJoin_Internal(TcContext context, long handle, short stage,
			TcBlobData inputData0, TcBlobData inputData1, TcTcsAuth inAuth1, TcTpmSecret ownerAuth)
		throws TcTssException
	{
		CheckPrecondition.notNull(context, "context");
		CheckPrecondition.notNull(inputData0, "inputData0");
		CheckPrecondition.notNull(inputData1, "inputData1");
		CheckPrecondition.notNull(inAuth1, "inAuth1");
		CheckPrecondition.notNull(ownerAuth, "ownerAuth");

		long ordinal = TcTpmOrdinals.TPM_ORD_DAA_Join;

		inAuth1.setNonceOdd(TcCrypto.createTcgNonce());

		TcBlobData[] blob1H = { // 1H
		blobUINT32(ordinal), // 1S
				blobBYTE(stage), // 2S
				blobUINT32(inputData0.getLengthAsLong()), // 3S
				inputData0, // 4S
				blobUINT32(inputData1.getLengthAsLong()), // 5S
				inputData1 }; // 6S

		TcBlobData authDataH1 = computeAuthData( //
				blob1H, // 1H1
				inAuth1, // 2H1 - 4H1
				ownerAuth.getEncoded()); // HMAC key

		inAuth1.setHmac(new TcTpmAuthdata(authDataH1));

		// call to TCS
		TcITcsBinding tcs = context.getTcsBinding();
		Object[] outDataTpm = tcs.TcsipDaaJoin(context.getTcsContextHandle(), handle, stage,
				inputData0, inputData1, inAuth1);

		// get return values
		long resultCode = ((Long) outDataTpm[0]).longValue();
		TcTcsAuth outAuth1 = (TcTcsAuth) outDataTpm[1];
		TcBlobData outputData = (TcBlobData) outDataTpm[2];

		// validate output data
		TcBlobData[] blob1Hout = { // 1H
		blobUINT32(resultCode), // 1S
				blobUINT32(ordinal), // 2S
				blobUINT32(outputData.getLengthAsLong()), // 3S
				outputData }; // 4S

		validateRespAuth(blob1Hout, inAuth1, outAuth1, ownerAuth.getEncoded());

		return new Object[] { outAuth1, outputData };
	}


	/*************************************************************************************************
	 * This method executes a TPM DAA sign command.
	 *
	 * @param context The context this call is associated with.
	 * @param handle Handle to the sign session
	 * @param stage Stage of the sign process
	 * @param inputData0 Data to be used by this capability
	 * @param inputData1 Data to be used by this capability
	 * @param inAuth1 The data for the authorization session.
	 * @param ownerAuth HMAC key for the authorization session.
	 *
	 * @return The returned Object[] holds the following elements:
	 *         <ul>
	 *         <li> 0 ... The outgoing authorization data for first session. (TcTpmAuth)
	 *         <li> 1 ... Data produced by this capability (TcBlobData)
	 *         </ul>
	 *
	 * @throws {@link TcTssException}
	 */
	public static Object[] TspDaaSign_Internal(TcContext context, long handle, short stage,
			TcBlobData inputData0, TcBlobData inputData1, TcTcsAuth inAuth1, TcTpmSecret ownerAuth)
		throws TcTssException
	{
		CheckPrecondition.notNull(context, "context");
		CheckPrecondition.notNull(inputData0, "inputData0");
		CheckPrecondition.notNull(inputData1, "inputData1");
		CheckPrecondition.notNull(inAuth1, "inAuth1");
		CheckPrecondition.notNull(ownerAuth, "ownerAuth");

		long ordinal = TcTpmOrdinals.TPM_ORD_DAA_Sign;

		inAuth1.setNonceOdd(TcCrypto.createTcgNonce());

		TcBlobData[] blob1H = { // 1H
		blobUINT32(ordinal), // 1S
				blobBYTE(stage), // 2S
				blobUINT32(inputData0.getLengthAsLong()), // 3S
				inputData0, // 4S
				blobUINT32(inputData1.getLengthAsLong()), // 5S
				inputData1 }; // 6S

		TcBlobData authDataH1 = computeAuthData( //
				blob1H, // 1H1
				inAuth1, // 2H1 - 4H1
				ownerAuth.getEncoded()); // HMAC key

		inAuth1.setHmac(new TcTpmAuthdata(authDataH1));

		// call to TCS
		TcITcsBinding tcs = context.getTcsBinding();
		Object[] outDataTpm = tcs.TcsipDaaSign(context.getTcsContextHandle(), handle, stage,
				inputData0, inputData1, inAuth1);

		// get return values
		long resultCode = ((Long) outDataTpm[0]).longValue();
		TcTcsAuth outAuth1 = (TcTcsAuth) outDataTpm[1];
		TcBlobData outputData = (TcBlobData) outDataTpm[2];

		// validate output data
		TcBlobData[] blob1Hout = { // 1H
		blobUINT32(resultCode), // 1S
				blobUINT32(ordinal), // 2S
				blobUINT32(outputData.getLengthAsLong()), // 3S
				outputData }; // 4S

		validateRespAuth(blob1Hout, inAuth1, outAuth1, ownerAuth.getEncoded());

		return new Object[] { outAuth1, outputData };
	}


	/*************************************************************************************************
	 * This method allows the TPM driver to clear out information in an authorization handle. The TPM
	 * may maintain the authorization session even though a key attached to it has been unloaded or
	 * the authorization session itself has been unloaded in some way.
	 *
	 * @param context The context this call is associated with.
	 * @param handle The handle to terminate
	 *
	 * @throws {@link TcTssException}
	 */
	public static void TspTerminateHandle_Internal(TcContext context, long handle)
		throws TcTssException
	{
		CheckPrecondition.notNull(context, "context");

		// call to TCS
		TcITcsBinding tcs = context.getTcsBinding();
		tcs.TcsipTerminateHandle(context.getTcsContextHandle(), handle);
	}


	/*************************************************************************************************
	 *
	 *
	 * @param context The context this call is associated with.
	 * @param dirIndex Index of the DIR
	 * @param newContents New value to be stored in named DIR
	 * @param inAuth1 The data for the authorization session.
	 * @param ownerAuth HMAC key for the authorization session.
	 *
	 * @return The outgoing authorization data for first session.
	 *
	 * @throws {@link TcTssException}
	 */
	public static TcTcsAuth TspDirWriteAuth_Internal(TcContext context, long dirIndex,
			TcTpmDigest newContents, TcTcsAuth inAuth1, TcTpmSecret ownerAuth) throws TcTssException
	{
		CheckPrecondition.notNull(context, "context");
		CheckPrecondition.notNull(newContents, "newContents");
		CheckPrecondition.notNull(inAuth1, "inAuth1");
		CheckPrecondition.notNull(ownerAuth, "ownerAuth");

		long ordinal = TcTpmOrdinals.TPM_ORD_DirWriteAuth;

		inAuth1.setNonceOdd(TcCrypto.createTcgNonce());

		TcBlobData[] blob1H = { // 1H
		blobUINT32(ordinal), // 1S
				blobUINT32(dirIndex), // 2S
				newContents.getEncoded() }; // 3S

		TcBlobData authDataH1 = computeAuthData( //
				blob1H, // 1H1
				inAuth1, // 2H1 - 4H1
				ownerAuth.getEncoded()); // HMAC key

		inAuth1.setHmac(new TcTpmAuthdata(authDataH1));

		// call to TCS
		TcITcsBinding tcs = context.getTcsBinding();
		Object[] outDataTpm = tcs.TcsipDirWriteAuth(context.getTcsContextHandle(), dirIndex,
				newContents, inAuth1);

		// get return values
		long resultCode = ((Long) outDataTpm[0]).longValue();
		TcTcsAuth outAuth1 = (TcTcsAuth) outDataTpm[1];

		// validate output data
		TcBlobData[] blob1Hout = { // 1H
		blobUINT32(resultCode), // 1S
				blobUINT32(ordinal) }; // 2S

		validateRespAuth(blob1Hout, inAuth1, outAuth1, ownerAuth.getEncoded());

		return outAuth1;
	}


	/*************************************************************************************************
	 * This method provides read access to the Data Integrity Registers.
	 *
	 * @param context The context this call is associated with.
	 * @param dirIndex Index of the DIR to be read
	 *
	 * @return The current contents of the named DIR
	 *
	 * @throws {@link TcTssException}
	 */
	public static TcTpmDigest TspDirRead_Internal(TcContext context, long dirIndex)
		throws TcTssException
	{
		CheckPrecondition.notNull(context, "context");

		// call to TCS
		TcITcsBinding tcs = context.getTcsBinding();
		Object[] outDataTpm = tcs.TcsipDirRead(context.getTcsContextHandle(), dirIndex);

		// get return values
		TcTpmDigest dirContents = (TcTpmDigest) outDataTpm[1];

		return dirContents;
	}


	/*************************************************************************************************
	 * This method starts the process of changing authorization for an entity. It sets the OIAP
	 * session that must be retained for use by its twin TcsipChangeAuthAsymFinish command.
	 *
	 * @param context The context this call is associated with.
	 * @param idHandle The keyHandle identifier of a loaded identity ID key
	 * @param antiReplay The nonce to be inserted into the certifyInfo structure
	 * @param tempKey Structure contains all parameters of ephemeral key.
	 * @param inAuth1 The data for the authorization session.
	 * @param idAuth HMAC key for the authorization session.
	 *
	 * @return The returned Object[] holds the following elements:
	 *         <ul>
	 *         <li> 0 ... The outgoing authorization data for first session. (TcTpmAuth)
	 *         <li> 1 ... The certifyInfo structure that is to be signed. (TcTpmCertifyInfo)
	 *         <li> 2 ... The signature of the certifyInfo parameter. (TcBlobData)
	 *         <li> 3 ... The keyHandle identifier to be used by ChangeAuthAsymFinish for the
	 *         ephemeral key (Long)
	 *         <li> 4 ... Structure containing all parameters and public part of ephemeral key.
	 *         TcTpmKey.encSize is set to 0. (TcTpmKey)
	 *         </ul>
	 *
	 * @throws {@link TcTssException}
	 */
	public static Object[] TspChangeAuthAsymStart_Internal(TcContext context, long idHandle,
			TcTpmNonce antiReplay, TcTpmKeyParms tempKey, TcTcsAuth inAuth1, TcTpmSecret idAuth)
		throws TcTssException
	{
		CheckPrecondition.notNull(context, "context");
		CheckPrecondition.notNull(antiReplay, "antiReplay");
		CheckPrecondition.notNull(tempKey, "tempKey");
		CheckPrecondition.notNull(inAuth1, "inAuth1");
		CheckPrecondition.notNull(idAuth, "idAuth");

		long ordinal = TcTpmOrdinals.TPM_ORD_ChangeAuthAsymStart;

		inAuth1.setNonceOdd(TcCrypto.createTcgNonce());

		TcBlobData[] blob1H = { // 1H
		blobUINT32(ordinal), // 1S
				tempKey.getEncoded() }; // 3S

		TcBlobData authDataH1 = computeAuthData( //
				blob1H, // 1H1
				inAuth1, // 2H1 - 4H1
				idAuth.getEncoded()); // HMAC key

		inAuth1.setHmac(new TcTpmAuthdata(authDataH1));

		// call to TCS
		TcITcsBinding tcs = context.getTcsBinding();
		Object[] outDataTpm = tcs.TcsipChangeAuthAsymStart(context.getTcsContextHandle(), idHandle,
				antiReplay, tempKey, inAuth1);

		// get return values
		long resultCode = ((Long) outDataTpm[0]).longValue();
		TcTcsAuth outAuth1 = (TcTcsAuth) outDataTpm[1];
		TcTpmCertifyInfo certifyInfo = (TcTpmCertifyInfo) outDataTpm[2];
		TcBlobData sig = (TcBlobData) outDataTpm[3];
		Long ephHandle = (Long) outDataTpm[4];
		TcTpmKey tempKeyOut = (TcTpmKey) outDataTpm[5];

		// validate output data
		TcBlobData[] blob1Hout = { // 1H
		blobUINT32(resultCode), // 1S
				blobUINT32(ordinal), // 2S
				certifyInfo.getEncoded(), // 3S
				blobUINT32(sig.getLengthAsLong()), // 4S
				sig, // 5S
				tempKeyOut.getEncoded() }; // 7S

		validateRespAuth(blob1Hout, inAuth1, outAuth1, idAuth.getEncoded());

		return new Object[] { outAuth1, certifyInfo, sig, ephHandle, tempKeyOut };
	}


	/*************************************************************************************************
	 * This method completes the process of changing authorization for an entity.
	 *
	 * @param context The context this call is associated with.
	 * @param parentHandle The keyHandle of the parent key for the input data.
	 * @param ephHandle The keyHandle identifier for the ephemeral key.
	 * @param entityType The type of entity to be modified.
	 * @param newAuthLink HMAC calculation that links the old and new AuthData values together.
	 * @param encNewAuth New AuthData encrypted with ephemeral key.
	 * @param encData The encrypted entity that is to be modified.
	 * @param inAuth1 The data for the authorization session.
	 * @param privAuth HMAC key for the authorization session.
	 *
	 * @return The returned Object[] holds the following elements:
	 *         <ul>
	 *         <li> 0 ... The outgoing authorization data for first session. (TcTpmAuth)
	 *         <li> 1 ... The modified, encrypted entity. (TcBlobData)
	 *         <li> 2 ... A nonce value from the TPM RNG to add entropy to the changeProof value
	 *         (TcTpmNonce)
	 *         <li> 3 ... Proof that AuthData has changed. (TcTpmDigest)
	 *         </ul>
	 *
	 * @throws {@link TcTssException}
	 */
	public static Object[] TspChangeAuthAsymFinish_Internal(TcContext context, long parentHandle,
			long ephHandle, int entityType, TcTpmDigest newAuthLink, TcBlobData encNewAuth,
			TcBlobData encData, TcTcsAuth inAuth1, TcTpmSecret privAuth) throws TcTssException
	{
		CheckPrecondition.notNull(context, "context");
		CheckPrecondition.notNull(newAuthLink, "newAuthLink");
		CheckPrecondition.notNull(encNewAuth, "encNewAuth");
		CheckPrecondition.notNull(encData, "encData");
		CheckPrecondition.notNull(inAuth1, "inAuth1");
		CheckPrecondition.notNull(privAuth, "privAuth");

		long ordinal = TcTpmOrdinals.TPM_ORD_ChangeAuthAsymFinish;

		inAuth1.setNonceOdd(TcCrypto.createTcgNonce());

		TcBlobData[] blob1H = { // 1H
		blobUINT32(ordinal), // 1S
				blobUINT16(entityType), // 3S
				blobUINT32(encNewAuth.getLengthAsLong()), // 5S
				encNewAuth, // 6S
				blobUINT32(encData.getLengthAsLong()), // 7S
				encData }; // 8S

		TcBlobData authDataH1 = computeAuthData( //
				blob1H, // 1H1
				inAuth1, // 2H1 - 4H1
				privAuth.getEncoded()); // HMAC key

		inAuth1.setHmac(new TcTpmAuthdata(authDataH1));

		// call to TCS
		TcITcsBinding tcs = context.getTcsBinding();
		Object[] outDataTpm = tcs.TcsipChangeAuthAsymFinish(context.getTcsContextHandle(),
				parentHandle, ephHandle, entityType, newAuthLink, encNewAuth, encData, inAuth1);

		// get return values
		long resultCode = ((Long) outDataTpm[0]).longValue();
		TcTcsAuth outAuth1 = (TcTcsAuth) outDataTpm[1];
		TcBlobData outData = (TcBlobData) outDataTpm[2];
		TcTpmNonce saltNonce = (TcTpmNonce) outDataTpm[3];
		TcTpmDigest changeProof = (TcTpmDigest) outDataTpm[4];

		// validate output data
		TcBlobData[] blob1Hout = { // 1H
		blobUINT32(resultCode), // 1S
				blobUINT32(ordinal), // 2S
				blobUINT32(outData.getLengthAsLong()), // 3S
				outData, // 4S
				changeProof.getEncoded() }; // 6S

		validateRespAuth(blob1Hout, inAuth1, outAuth1, privAuth.getEncoded());

		return new Object[] { outAuth1, outData, saltNonce, changeProof };
	}


	/*************************************************************************************************
	 * This method allows the TPM owner to read the public endorsement key.
	 *
	 * @param context The context this call is associated with.
	 * @param inAuth1 The data for the authorization session.
	 * @param ownerAuth HMAC key for the authorization session.
	 *
	 * @return The returned Object[] holds the following elements:
	 *         <ul>
	 *         <li> 0 ... The outgoing authorization data for first session. (TcTpmAuth)
	 *         <li> 1 ... The public endorsement key (TcTpmPubkey)
	 *         </ul>
	 *
	 * @throws {@link TcTssException}
	 */
	public static Object[] TspOwnerReadPubek_Internal(TcContext context, TcTcsAuth inAuth1,
			TcTpmSecret ownerAuth) throws TcTssException
	{
		CheckPrecondition.notNull(context, "context");
		CheckPrecondition.notNull(inAuth1, "inAuth1");
		CheckPrecondition.notNull(ownerAuth, "ownerAuth");

		long ordinal = TcTpmOrdinals.TPM_ORD_OwnerReadPubek;

		inAuth1.setNonceOdd(TcCrypto.createTcgNonce());

		TcBlobData[] blob1H = { // 1H
		blobUINT32(ordinal) }; // 1S

		TcBlobData authDataH1 = computeAuthData( //
				blob1H, // 1H1
				inAuth1, // 2H1 - 4H1
				ownerAuth.getEncoded()); // HMAC key

		inAuth1.setHmac(new TcTpmAuthdata(authDataH1));

		// call to TCS
		TcITcsBinding tcs = context.getTcsBinding();
		Object[] outDataTpm = tcs.TcsipOwnerReadPubek(context.getTcsContextHandle(), inAuth1);

		// get return values
		long resultCode = ((Long) outDataTpm[0]).longValue();
		TcTcsAuth outAuth1 = (TcTcsAuth) outDataTpm[1];
		TcTpmPubkey pubEndorsementKey = (TcTpmPubkey) outDataTpm[2];

		// validate output data
		TcBlobData[] blob1Hout = { // 1H
		blobUINT32(resultCode), // 1S
				blobUINT32(ordinal), // 2S
				pubEndorsementKey.getEncoded() }; // 3S

		validateRespAuth(blob1Hout, inAuth1, outAuth1, ownerAuth.getEncoded());

		return new Object[] { outAuth1, pubEndorsementKey };
	}


	/*************************************************************************************************
	 * This method returns the public portion of the endorsement key.
	 *
	 * @param context The context this call is associated with.
	 * @param inAuth1 The data for the authorization session.
	 * @param ownerAuth HMAC key for the authorization session.
	 *
	 * @return The outgoing authorization data for first session.
	 *
	 * @throws {@link TcTssException}
	 */
	public static TcTcsAuth TspDisablePubekRead_Internal(TcContext context, TcTcsAuth inAuth1,
			TcTpmSecret ownerAuth) throws TcTssException
	{
		CheckPrecondition.notNull(context, "context");
		CheckPrecondition.notNull(inAuth1, "inAuth1");
		CheckPrecondition.notNull(ownerAuth, "ownerAuth");

		long ordinal = TcTpmOrdinals.TPM_ORD_DisablePubekRead;

		inAuth1.setNonceOdd(TcCrypto.createTcgNonce());

		TcBlobData[] blob1H = { // 1H
		blobUINT32(ordinal) }; // 1S

		TcBlobData authDataH1 = computeAuthData( //
				blob1H, // 1H1
				inAuth1, // 2H1 - 4H1
				ownerAuth.getEncoded()); // HMAC key

		inAuth1.setHmac(new TcTpmAuthdata(authDataH1));

		// call to TCS
		TcITcsBinding tcs = context.getTcsBinding();
		Object[] outDataTpm = tcs.TcsipDisablePubekRead(context.getTcsContextHandle(), inAuth1);

		// get return values
		long resultCode = ((Long) outDataTpm[0]).longValue();
		TcTcsAuth outAuth1 = (TcTcsAuth) outDataTpm[1];

		// validate output data
		TcBlobData[] blob1Hout = { // 1H
		blobUINT32(resultCode), // 1S
				blobUINT32(ordinal) }; // 2S

		validateRespAuth(blob1Hout, inAuth1, outAuth1, ownerAuth.getEncoded());

		return outAuth1;
	}


	// ===============================================================================================
	// non-official TPM functions

	/*************************************************************************************************
	 *
	 *
	 * @param context The context this call is associated with.
	 *
	 * @return Maximum number of bytes that can be sent to TPM_SHA1Update. Must be a multiple of 64
	 *         bytes.
	 *
	 * @throws {@link TcTssException}
	 */
	public static Long TspSHA1Start_Internal(TcContext context) throws TcTssException
	{
		CheckPrecondition.notNull(context, "context");

		// call to TCS
		TcITcsBinding tcs = context.getTcsBinding();
		Object[] outDataTpm = tcs.TcsSHA1Start(context.getTcsContextHandle());

		// get return values
		Long maxNumBytes = (Long) outDataTpm[1];

		return maxNumBytes;
	}


	/*************************************************************************************************
	 *
	 *
	 * @param context The context this call is associated with.
	 * @param numBytes The number of bytes in hashData. Must be a multiple of 64 bytes.
	 * @param hashData Bytes to be hashed
	 *
	 * @throws {@link TcTssException}
	 */
	public static void TspSHA1Update_Internal(TcContext context, long numBytes, TcBlobData hashData)
		throws TcTssException
	{
		CheckPrecondition.notNull(context, "context");
		CheckPrecondition.notNull(hashData, "hashData");

		// call to TCS
		TcITcsBinding tcs = context.getTcsBinding();
		tcs.TcsSHA1Update(context.getTcsContextHandle(), numBytes, hashData);
	}


	/*************************************************************************************************
	 *
	 *
	 * @param context The context this call is associated with.
	 * @param hashData Final bytes to be hashed
	 *
	 * @return The output of the SHA-1 hash.
	 *
	 * @throws {@link TcTssException}
	 */
	public static TcTpmDigest TspSHA1Complete_Internal(TcContext context, TcBlobData hashData)
		throws TcTssException
	{
		CheckPrecondition.notNull(context, "context");
		CheckPrecondition.notNull(hashData, "hashData");

		// call to TCS
		TcITcsBinding tcs = context.getTcsBinding();
		Object[] outDataTpm = tcs.TcsSHA1Complete(context.getTcsContextHandle(), hashData);

		// get return values
		TcTpmDigest hashValue = (TcTpmDigest) outDataTpm[1];

		return hashValue;
	}


	/*************************************************************************************************
	 *
	 *
	 * @param context The context this call is associated with.
	 * @param pcrNum Index of the PCR to be modified
	 * @param hashData Final bytes to be hashed
	 *
	 * @return The returned Object[] holds the following elements:
	 *         <ul>
	 *         <li> 0 ... The output of the SHA-1 hash. (TcTpmDigest)
	 *         <li> 1 ... The PCR value after execution of the command. (TcTpmDigest)
	 *         </ul>
	 *
	 * @throws {@link TcTssException}
	 */
	public static Object[] TspSHA1CompleteExtend_Internal(TcContext context, long pcrNum,
			TcBlobData hashData) throws TcTssException
	{
		CheckPrecondition.notNull(context, "context");
		CheckPrecondition.notNull(hashData, "hashData");

		// call to TCS
		TcITcsBinding tcs = context.getTcsBinding();
		Object[] outDataTpm = tcs
				.TcsSHA1CompleteExtend(context.getTcsContextHandle(), pcrNum, hashData);

		// remove outDataTpm[0] (the return code) from the return values
		return new Object[] { outDataTpm[1], outDataTpm[2] };
	}


	// ===============================================================================================
	// vendor specific functions

	/*************************************************************************************************
	 * This method reads the EK certificate embedded in 1.1b Infineon chips. The certificate is not
	 * read in one piece but it is split into several parts which have to be read one by one and then
	 * put together. Note that this functionality is vendor specific for Infineon 1.1b TPMs!
	 *
	 * @param context The context this call is associated with.
	 *
	 * @return Binary blob containing the EK certificate read from the TPM.
	 */
	public static TcBlobData TspIfxReadTpm11Ek(TcContext context) throws TcTssException
	{
		CheckPrecondition.notNull(context, "context");
		TcITcsBinding tcs = context.getTcsBinding();

		// read part 0
		TcBlobData antiReplay = TcCrypto.createTcgNonce().getNonce();
		Object[] outDataTpm = tcs.TcsipIfxReadTpm11EkCert(context.getTcsContextHandle(), (byte) 0,
				antiReplay);
		short maxIndex = ((Short) outDataTpm[0]).shortValue();
		TcTpmDigest checksum = (TcTpmDigest) outDataTpm[1];
		TcBlobData ekCertPart = (TcBlobData) outDataTpm[2];
		validateChecksum(ekCertPart, antiReplay, checksum);

		TcBlobData ekCert = ekCertPart;

		// read parts 1 ... n
		for (byte i = 1; i <= maxIndex; i++) {
			antiReplay = TcCrypto.createTcgNonce().getNonce();
			outDataTpm = tcs.TcsipIfxReadTpm11EkCert(context.getTcsContextHandle(), i, antiReplay);
			checksum = (TcTpmDigest) outDataTpm[1];
			ekCertPart = (TcBlobData) outDataTpm[2];
			validateChecksum(ekCertPart, antiReplay, checksum);
			ekCert.append(ekCertPart);
		}

		return ekCert;
	}



}
