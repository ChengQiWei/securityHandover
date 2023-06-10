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
import iaik.tc.tss.api.structs.tcs.TcTcsAuth;
import iaik.tc.tss.api.structs.tpm.TcITpmPcrInfo;
import iaik.tc.tss.api.structs.tpm.TcITpmStoredData;
import iaik.tc.tss.api.structs.tpm.TcTpmBoundData;
import iaik.tc.tss.api.structs.tpm.TcTpmEncauth;
import iaik.tc.tss.api.structs.tpm.TcTpmPcrInfo;
import iaik.tc.tss.api.structs.tpm.TcTpmPcrInfoLong;
import iaik.tc.tss.api.structs.tpm.TcTpmPubkey;
import iaik.tc.tss.api.structs.tpm.TcTpmSecret;
import iaik.tc.tss.api.structs.tpm.TcTpmStoredData;
import iaik.tc.tss.api.structs.tpm.TcTpmStoredData12;
import iaik.tc.tss.api.structs.tpm.TcTpmStructVer;
import iaik.tc.tss.api.structs.tpm.TcTpmStructsHelpers;
import iaik.tc.tss.api.tspi.TcIAttributes;
import iaik.tc.tss.api.tspi.TcIAuthObject;
import iaik.tc.tss.api.tspi.TcIContext;
import iaik.tc.tss.api.tspi.TcIEncData;
import iaik.tc.tss.api.tspi.TcIPcrComposite;
import iaik.tc.tss.api.tspi.TcIPolicy;
import iaik.tc.tss.api.tspi.TcIRsaKey;
import iaik.tc.tss.impl.csp.TcCrypto;
import iaik.tc.tss.impl.java.tsp.internal.TcTspInternal;
import iaik.tc.utils.misc.CheckPrecondition;

public class TcEncData extends TcAuthObject implements TcIEncData {

	/**
	 * This field determines if the SealX operation is used instead of the normal Seal operation. This
	 * flag can be toggled using the {@link TcTssConstants#TSS_TSPATTRIB_ENCDATASEAL_PROTECT}
	 * attribute.
	 */
	protected boolean useSealX_ = false;

	/**
	 * This field determines the usage mode of the data object. Usage modes are either binding or
	 * sealing. The usage mode is defined in the object's init flags.
	 */
	protected long usageMode_ = TcTssConstants.TSS_ENCDATA_LEGACY;

	/**
	 * This field holds the encrypted blob resulting from the bind or seal operations. Alternatively,
	 * the encrypted blob can also be set using setAttribData before calling unbind or unseal.
	 */
	protected TcBlobData encBlob_ = null;


	/*************************************************************************************************
	 * Hidden constructor (factory pattern).
	 */
	protected TcEncData(TcIContext context) throws TcTssException
	{
		super(context);
	}


	/*************************************************************************************************
	 * This method is used to decode a set of init flags.
	 * 
	 * @TSS_1_1_EA 54
	 * 
	 * @param flags The init flags.
	 */
	protected void setInitFlags(long flags) throws TcTspException
	{
		if (flags == TcTssConstants.TSS_ENCDATA_BIND) {
			usageMode_ = TcTssConstants.TSS_ENCDATA_BIND;
		} else if (flags == TcTssConstants.TSS_ENCDATA_SEAL) {
			usageMode_ = TcTssConstants.TSS_ENCDATA_SEAL;
		} else if (flags == TcTssConstants.TSS_ENCDATA_LEGACY) {
			usageMode_ = TcTssConstants.TSS_ENCDATA_LEGACY;
		} else {
			throw new TcTspException(TcTssErrors.TSS_E_ENC_INVALID_TYPE,
					"Unknown or unsupported init flags.");
		}
	}


	/*
	 * (non-Javadoc)
	 * 
	 * @see iaik.tss.api.tspi.TcIEncData#bind(iaik.tss.api.tspi.TcIRsaKey,
	 *      iaik.tss.api.structs.TcBlobData)
	 */
	public synchronized void bind(TcIRsaKey encKey, TcBlobData data) throws TcTssException
	{
		checkContextOpen();
		CheckPrecondition.notNullAndInstanceOf(encKey, "encKey", TcRsaKey.class);
		context_.checkAssociation(encKey, "encKey");
		CheckPrecondition.notNull(data, "data");

		if (usageMode_ == TcTssConstants.TSS_ENCDATA_SEAL) {
			throw new TcTspException(TcTssErrors.TSS_E_ENC_INVALID_TYPE,
					"This object is can not be used for binding.");
		}
		
		
		TcRsaKey encKeyInternal = (TcRsaKey) encKey;
		TcTpmPubkey pubKey = new TcTpmPubkey(encKeyInternal
				.getAttribKeyBlob(TcTssConstants.TSS_TSPATTRIB_KEYBLOB_PUBLIC_KEY));
		long encScheme = encKeyInternal
				.getAttribKeyInfoUINT32(TcTssConstants.TSS_TSPATTRIB_KEYINFO_ENCSCHEME);

		
		TcBlobData boundBlobData;
        //add TPM_BOUND_DATA structure
		TcTpmBoundData boundData = new TcTpmBoundData();
		boundData.setPayload(TcTpmConstants.TPM_PT_BIND);
		boundData.setPayloadData(data);
		boundData.setVer(TcTpmStructVer.TPM_V1_1);
		
		boundBlobData = boundData.getEncoded();
		
		if (usageMode_ == TcTssConstants.TSS_ENCDATA_LEGACY 
				&& encScheme == TcTssConstants.TSS_ES_RSAESPKCSV15 ) { 
			
			//checking if data doesn't exceed the maximum input size
			if ((pubKey.getPubKey().getKeyLength()-11) < data.getLength() ) {
				throw new TcTspException(TcTssErrors.TSS_E_ENC_INVALID_LENGTH,
				"Data size exceeded maximum data input size for bind (maximum data input size: s-11).");	
			}
			//if a legacy key with TSS_ES_RSAESPKCSV15 is used, don't use the TPM_BOUND_DATA structure
			boundBlobData = data;			

		}
		//TSS spec seems to be wrong with maximum data input size: s-11-(4-1) 
		else if (usageMode_ == TcTssConstants.TSS_ENCDATA_BIND 
				&& encScheme == TcTssConstants.TSS_ES_RSAESPKCSV15
				&& (pubKey.getPubKey().getKeyLength()-11-(4+1)) < data.getLength() ) {
			throw new TcTspException(TcTssErrors.TSS_E_ENC_INVALID_LENGTH,
					"Data size exceeded maximum data input size for bind (maximum data input size: s-11-(4+1)).");
		}
		//TSS spec defines maximum data input size: s-(40-2)-(4-1)
		//But it needs to be s-(2*20)-2-(4+1)
		else if (encScheme == TcTssConstants.TSS_ES_RSAESOAEP_SHA1_MGF1
				&& (pubKey.getPubKey().getKeyLength()-(2*20)-2-(4+1)) < data.getLength()) {
			throw new TcTspException(TcTssErrors.TSS_E_ENC_INVALID_LENGTH,
					"Data size exceeded maximum data input size for bind (maximum data input size: s-(2*20)-2-(4+1)).");
		}

		//encrypting
		if (encScheme == TcTssConstants.TSS_ES_RSAESOAEP_SHA1_MGF1) {
			encBlob_ = TcCrypto.pubEncryptRsaOaepSha1Mgf1(pubKey, boundBlobData);
		} else if (encScheme == TcTssConstants.TSS_ES_RSAESPKCSV15) {
			encBlob_ = TcCrypto.pubEncryptRsaEcbPkcs1Padding(pubKey, boundBlobData);
		} else {
			throw new TcTspException(TcTssErrors.TSS_E_INVALID_ENCSCHEME,
					"The specified encryption scheme can not be used for bind operations.");
		}
	}


	/*
	 * (non-Javadoc)
	 * 
	 * @see iaik.tss.api.tspi.TcIEncData#seal(iaik.tss.api.tspi.TcIRsaKey,
	 *      iaik.tss.api.structs.TcBlobData, iaik.tss.api.tspi.TcIPcrComposite)
	 */
	public synchronized void seal(TcIRsaKey encKey, TcBlobData data, TcIPcrComposite pcrComposite)
		throws TcTssException
	{
		checkContextOpenAndConnected();
		CheckPrecondition.notNullAndInstanceOf(encKey, "encKey", TcRsaKey.class);
		context_.checkAssociation(encKey, "encKey");
		CheckPrecondition.notNull(data, "data");
		checkKeyHandleNotNull(((TcRsaKey) encKey).getTcsKeyHandle(), "encKey");

		// pcrComposite can be null

		if (usageMode_ != TcTssConstants.TSS_ENCDATA_SEAL) {
			throw new TcTspException(TcTssErrors.TSS_E_ENC_INVALID_TYPE,
					"This object is can not be used for sealing.");
		}

		// get pcrInfo structure in correct form
		TcITpmPcrInfo pcrInfo = null;
		if (pcrComposite != null) {
			if (pcrComposite instanceof TcPcrCompositeInfoLong) {
				pcrInfo = new TcTpmPcrInfoLong(((TcPcrCompositeBase) pcrComposite).getPcrStructEncoded());
			} else if (pcrComposite instanceof TcPcrCompositeInfo) {
				pcrInfo = new TcTpmPcrInfo(((TcPcrCompositeBase) pcrComposite).getPcrStructEncoded());
			} else {
				throw new TcTspException(TcTssErrors.TSS_E_BAD_PARAMETER,
						"PCR structure has to be of type PcrInfo or PcrInfoLong.");
			}
		}

		// get tcs key handle of sealing key
		long keyHandle = ((TcRsaKey) encKey).getTcsKeyHandle();

		// start OSAP session
		Object[] osapData = createOsapSession(TcTpmConstants.TPM_ET_KEYHANDLE, keyHandle, encKey
				.getUsagePolicyObject(), getUsagePolicyObject());
		TcTcsAuth osapSession = (TcTcsAuth) osapData[0];
		TcTpmEncauth encAuth = (TcTpmEncauth) osapData[1];
		TcTpmSecret osapSecret = (TcTpmSecret) osapData[2];

		// call to TPM
		Object[] tpmOutData = null;
		if (useSealX_) {
			// TODO: implement SealX, note: SealX is not supported on STM and IFX TPMs
			throw new TcTspException(TcTssErrors.TSS_E_NOTIMPL, "SealX is not implemented");
		} else {
			tpmOutData = TcTspInternal.TspSeal_Internal(context_, keyHandle, encAuth, pcrInfo, data,
					osapSession, osapSecret);
		}

		// decode TPM output
		encBlob_ = ((TcITpmStoredData) tpmOutData[1]).getEncoded();
	}


	/*
	 * (non-Javadoc)
	 * 
	 * @see iaik.tss.api.tspi.TcIEncData#unbind(iaik.tss.api.tspi.TcIRsaKey)
	 */
	public synchronized TcBlobData unbind(TcIRsaKey key) throws TcTssException
	{
		checkContextOpenAndConnected();
		CheckPrecondition.notNullAndInstanceOf(key, "key", TcRsaKey.class);
		context_.checkAssociation(key, "key");
		checkKeyHandleNotNull(((TcRsaKey) key).getTcsKeyHandle(), "key");

		if (usageMode_ == TcTssConstants.TSS_ENCDATA_SEAL) {
			throw new TcTspException(TcTssErrors.TSS_E_ENC_INVALID_TYPE,
					"This object is can not be used for (un)binding.");
		}

		if (encBlob_ == null) {
			throw new TcTspException(TcTssErrors.TSS_E_ENC_NO_DATA,
					"Bound data has to be set before calling unbind.");
		}

		long keyHandle = ((TcRsaKey) key).getTcsKeyHandle();
		TcTpmSecret privAuth = ((TcPolicy) key.getUsagePolicyObject()).getTpmSecret();

		// start OIAP session
		TcTcsAuth inAuth1 = TcTspInternal.TspOIAP_Internal(context_);

		// call down to TPM
		Object[] tpmOutData = TcTspInternal.TspUnBind_Internal(context_, keyHandle, encBlob_, inAuth1,
				privAuth);

		return (TcBlobData) tpmOutData[1];
	}


	/*
	 * (non-Javadoc)
	 * 
	 * @see iaik.tss.api.tspi.TcIEncData#unseal(iaik.tss.api.tspi.TcIRsaKey)
	 */
	public synchronized TcBlobData unseal(TcIRsaKey key) throws TcTssException
	{
		checkContextOpenAndConnected();
		CheckPrecondition.notNullAndInstanceOf(key, "key", TcRsaKey.class);
		context_.checkAssociation(key, "key");
		checkKeyHandleNotNull(((TcRsaKey) key).getTcsKeyHandle(), "key");

		if (usageMode_ != TcTssConstants.TSS_ENCDATA_SEAL) {
			throw new TcTspException(TcTssErrors.TSS_E_INVALID_OBJ_ACCESS,
					"This object is can not be used for (un)sealing.");
		}

		TcTpmSecret parentAuth = ((TcPolicy) key.getUsagePolicyObject()).getTpmSecret();
		TcTpmSecret dataAuth = ((TcPolicy) getUsagePolicyObject()).getTpmSecret();
		long parentHandle = ((TcRsaKey) key).getTcsKeyHandle();

		TcITpmStoredData storedData = null;
		if (TcTpmStructsHelpers.isTpm11Struct(encBlob_)) {
			storedData = new TcTpmStoredData(encBlob_);
		} else {
			storedData = new TcTpmStoredData12(encBlob_);
		}

		// start OIAP session
		TcTcsAuth inAuth1 = TcTspInternal.TspOIAP_Internal(context_);

		// start OIAP session
		TcTcsAuth inAuth2 = TcTspInternal.TspOIAP_Internal(context_);

		// call down to TPMs
		Object[] tpmOutData = TcTspInternal.TspUnseal_Internal(context_, parentHandle, storedData,
				inAuth1, inAuth2, parentAuth, dataAuth);

		return (TcBlobData) tpmOutData[2];
	}


	/*
	 * (non-Javadoc)
	 * 
	 * @see iaik.tc.tss.api.tspi.TcIAuthObject#changeAuth(iaik.tc.tss.api.tspi.TcIAuthObject,
	 *      iaik.tc.tss.api.tspi.TcIPolicy)
	 */
	public synchronized void changeAuth(TcIAuthObject parentObject, TcIPolicy newPolicy)
		throws TcTssException
	{
		checkContextOpenAndConnected();
		CheckPrecondition.notNullAndInstanceOf(parentObject, "parentObject", TcRsaKey.class);
		checkKeyHandleNotNull(((TcRsaKey) parentObject).getTcsKeyHandle(), "parentObject");
		CheckPrecondition.notNullAndInstanceOf(newPolicy, "newPolicy", TcPolicy.class);
		context_.checkAssociation(newPolicy, "newPolicy");

		if (usageMode_ != TcTssConstants.TSS_ENCDATA_SEAL) {
			throw new TcTspException(TcTssErrors.TSS_E_ENC_INVALID_TYPE,
					"ChangeAuth only supported for sealed data.");
		}

		if (encBlob_ == null) {
			throw new TcTspException(TcTssErrors.TSS_E_ENC_NO_DATA,
					"There is not bound or sealed data to change the auth for.");
		}

		long parentHandle = ((TcRsaKey) parentObject).getTcsKeyHandle();

		TcITpmStoredData storedData = null;
		if (TcTpmStructsHelpers.isTpm11Struct(encBlob_)) {
			storedData = new TcTpmStoredData(encBlob_);
		} else {
			storedData = new TcTpmStoredData12(encBlob_);
		}

		// do the actual change
		TcBlobData newEncData = genericChangeAuth(TcTpmConstants.TPM_ET_KEYHANDLE, parentHandle,
				TcTpmConstants.TPM_ET_DATA, storedData.getEncData(), parentHandle, parentObject
						.getUsagePolicyObject(), (TcPolicy) newPolicy, (TcPolicy) getUsagePolicyObject());

		storedData.setEncData(newEncData);
		encBlob_ = storedData.getEncoded();

		// assign key to new policy
		newPolicy.assignToObject(this);
	}


	// ----------------------------------------------------------------------------------------------
	// TSS attribute getters and setter
	// ----------------------------------------------------------------------------------------------

	/*************************************************************************************************
	 * This method defines the mapping of attribute flags to getter methods.
	 */
	protected void initAttribGetters()
	{
		addGetterUINT32(TcTssConstants.TSS_TSPATTRIB_ENCDATA_SEAL, "getAttribSeal");
		addGetterUINT32(TcTssConstants.TSS_TSPATTRIB_ENCDATA_PCR_LONG, "getAttribPcrLongUINT32");

		addGetterData(TcTssConstants.TSS_TSPATTRIB_ENCDATA_BLOB, "getAttribBlob");
		addGetterData(TcTssConstants.TSS_TSPATTRIB_ENCDATA_PCR_LONG, "getAttribPcrLongBlob");
		addGetterData(TcTssConstants.TSS_TSPATTRIB_ENCDATA_PCR, "getAttribPcr");
	}


	/*************************************************************************************************
	 * This method defines the mapping of attribute flags to setter methods.
	 */
	protected void initAttribSetters()
	{
		addSetterUINT32(TcTssConstants.TSS_TSPATTRIB_ENCDATA_SEAL, "setAttribSeal");

		addSetterData(TcTssConstants.TSS_TSPATTRIB_ENCDATA_BLOB, "setAttribBlob");
	}


	/*************************************************************************************************
	 * This method sets toggles the usage of the SealX command as specified for the
	 * {@link TcTssConstants#TSS_TSPATTRIB_ENCDATA_SEAL} attribute. This method is an alternative to
	 * using {@link TcIAttributes#setAttribUint32(long, long, long)} with
	 * {@link TcTssConstants#TSS_TSPATTRIB_ENCDATA_SEAL} as flag.
	 * 
	 * @param subFlag Valid subFlags are:
	 *          {@link TcTssConstants#TSS_TSPATTRIB_ENCDATASEAL_PROTECT_MODE}.
	 * @param attrib Valid attributes are:
	 *          <ul>
	 *          <li>{@link TcTssConstants#TSS_TSPATTRIB_ENCDATASEAL_PROTECT} (use SealX)
	 *          <li>{@link TcTssConstants#TSS_TSPATTRIB_ENCDATASEAL_NO_PROTECT} (do not use SealX)
	 *          </ul>
	 * 
	 * 
	 */
	public synchronized void setAttribSeal(long subFlag, long attrib) throws TcTspException
	{
		if (subFlag != TcTssConstants.TSS_TSPATTRIB_ENCDATASEAL_PROTECT_MODE) {
			throw new TcTspException(TcTssErrors.TSS_E_INVALID_ATTRIB_SUBFLAG);
		}

		if (attrib == TcTssConstants.TSS_TSPATTRIB_ENCDATASEAL_PROTECT) {
			useSealX_ = true;
		} else if (attrib == TcTssConstants.TSS_TSPATTRIB_ENCDATASEAL_NO_PROTECT) {
			useSealX_ = false;
		} else {
			throw new TcTspException(TcTssErrors.TSS_E_INVALID_ATTRIB_DATA);
		}
	}


	/*************************************************************************************************
	 * This method returns the current setting of the
	 * {@link TcTssConstants#TSS_TSPATTRIB_ENCDATA_SEAL} attribute which defines if the SealX command
	 * is used or not. This method is an alternative to using
	 * {@link TcIAttributes#getAttribUint32(long, long)} with
	 * {@link TcTssConstants#TSS_TSPATTRIB_ENCDATA_SEAL} as flag.
	 * 
	 * @param subFlag Valid subFlags are:
	 *          {@link TcTssConstants#TSS_TSPATTRIB_ENCDATASEAL_PROTECT_MODE}.
	 * 
	 * @return
	 * <ul>
	 * <li>{@link TcTssConstants#TSS_TSPATTRIB_ENCDATASEAL_PROTECT} (uses SealX)
	 * <li>{@link TcTssConstants#TSS_TSPATTRIB_ENCDATASEAL_NO_PROTECT} (does not use SealX)
	 * </ul>
	 * 
	 * 
	 * 
	 */
	public synchronized long getAttribSeal(long subFlag) throws TcTspException
	{
		if (subFlag != TcTssConstants.TSS_TSPATTRIB_ENCDATASEAL_PROTECT_MODE) {
			throw new TcTspException(TcTssErrors.TSS_E_INVALID_ATTRIB_SUBFLAG);
		}

		if (useSealX_) {
			return TcTssConstants.TSS_TSPATTRIB_ENCDATASEAL_PROTECT;
		} else {
			return TcTssConstants.TSS_TSPATTRIB_ENCDATASEAL_NO_PROTECT;
		}
	}


	/*************************************************************************************************
	 * This method returns the locality at creation/release of the previously sealed data. Not that
	 * localities are only supported on 1.2 TPMs and are used only if 1.2 structures are used. This
	 * method is an alternative to using {@link TcIAttributes#getAttribUint32(long, long)} with
	 * {@link TcTssConstants#TSS_TSPATTRIB_ENCDATA_PCR_LONG} as flag.
	 * 
	 * @param subFlag Valid subFlags are:
	 *          <ul>
	 *          <li>{@link TcTssConstants#TSS_TSPATTRIB_ENCDATAPCRLONG_LOCALITY_ATCREATION}
	 *          <li>{@link TcTssConstants#TSS_TSPATTRIB_ENCDATAPCRLONG_LOCALITY_ATRELEASE}
	 *          </ul>
	 * @return The requested locality value.
	 * 
	 * 
	 */
	public synchronized long getAttribPcrLongUINT32(long subFlag) throws TcTspException
	{
		if (usageMode_ != TcTssConstants.TSS_ENCDATA_SEAL) {
			throw new TcTspException(TcTssErrors.TSS_E_ENC_INVALID_TYPE,
					"This object is not a sealed data object.");
		}
		if (encBlob_ == null) {
			throw new TcTspException(TcTssErrors.TSS_E_ENC_NO_DATA, "No data sealed yet.");
		}
		if (TcTpmStructsHelpers.isTpm11Struct(encBlob_)) {
			throw new TcTspException(TcTssErrors.TSS_E_INVALID_OBJ_ACCESS,
					"The sealed data is not an 1.2 TPM structure and therefore has no locality.");
		}

		TcTpmStoredData12 storedData = new TcTpmStoredData12(encBlob_);

		if (subFlag == TcTssConstants.TSS_TSPATTRIB_ENCDATAPCRLONG_LOCALITY_ATCREATION) {
			return (new TcTpmPcrInfoLong(((TcTpmStoredData12) storedData).getSealInfo()))
					.getLocalityAtCreation();
		} else if (subFlag == TcTssConstants.TSS_TSPATTRIB_ENCDATAPCRLONG_LOCALITY_ATRELEASE) {
			return (new TcTpmPcrInfoLong(((TcTpmStoredData12) storedData).getSealInfo()))
					.getLocalityAtRelease();
		} else {
			throw new TcTspException(TcTssErrors.TSS_E_INVALID_ATTRIB_SUBFLAG);
		}
	}


	/*************************************************************************************************
	 * This method allows to set the blob to be bound or encrypted. This method is an alternative to
	 * using {@link TcIAttributes#setAttribData(long, long, TcBlobData)} with
	 * {@link TcTssConstants#TSS_TSPATTRIB_ENCDATA_BLOB} as flag.
	 * 
	 * @param subFlag Valid subFlags are {@link TcTssConstants#TSS_TSPATTRIB_ENCDATA_BLOB}.
	 * @param data The data to set.
	 */
	public synchronized void setAttribBlob(long subFlag, TcBlobData data) throws TcTspException
	{
		CheckPrecondition.notNull(data, "data");

		if (subFlag != TcTssConstants.TSS_TSPATTRIB_ENCDATABLOB_BLOB) {
			throw new TcTspException(TcTssErrors.TSS_E_INVALID_ATTRIB_SUBFLAG);
		}

		encBlob_ = data;
	}


	/*************************************************************************************************
	 * This method returns a reference to the data blob represented by this object. This method is an
	 * alternative to using {@link TcIAttributes#getAttribData(long, long)} with
	 * {@link TcTssConstants#TSS_TSPATTRIB_ENCDATA_BLOB} as flag.
	 * 
	 * @param subFlag Valid subFlags are {@link TcTssConstants#TSS_TSPATTRIB_ENCDATA_BLOB}.
	 * 
	 * @return Reference to the blob associated with the object.
	 */
	public synchronized TcBlobData getAttribBlob(long subFlag) throws TcTspException
	{
		if (subFlag != TcTssConstants.TSS_TSPATTRIB_ENCDATABLOB_BLOB) {
			throw new TcTspException(TcTssErrors.TSS_E_INVALID_ATTRIB_SUBFLAG);
		}
		if (encBlob_ == null) {
			throw new TcTspException(TcTssErrors.TSS_E_ENC_NO_DATA, "No blob has been set yet.");
		}

		return encBlob_;
	}


	/*************************************************************************************************
	 * This method is used to retrieve PcrInfoLong information about sealed data. Not that this method
	 * can only be used on 1.2 TPMs and if 1.2 PCR structures are used. This method is an alternative
	 * to using {@link TcIAttributes#getAttribData(long, long)} with
	 * {@link TcTssConstants#TSS_TSPATTRIB_ENCDATA_PCR_LONG} as flag.
	 * 
	 * @param subFlag Valid subFlags are:
	 *          <ul>
	 *          <li> {@link TcTssConstants#TSS_TSPATTRIB_ENCDATAPCRLONG_CREATION_SELECTION}
	 *          <li> {@link TcTssConstants#TSS_TSPATTRIB_ENCDATAPCRLONG_RELEASE_SELECTION}
	 *          <li> {@link TcTssConstants#TSS_TSPATTRIB_ENCDATAPCRLONG_DIGEST_ATCREATION}
	 *          <li> {@link TcTssConstants#TSS_TSPATTRIB_ENCDATAPCRLONG_DIGEST_ATRELEASE}
	 *          </ul>
	 * 
	 * @return The request information.
	 */
	public synchronized TcBlobData getAttribPcrLongBlob(long subFlag) throws TcTspException
	{
		if (usageMode_ != TcTssConstants.TSS_ENCDATA_SEAL) {
			throw new TcTspException(TcTssErrors.TSS_E_INVALID_OBJECT_TYPE,
					"This object is not a sealed data object.");
		}
		if (encBlob_ == null) {
			throw new TcTspException(TcTssErrors.TSS_E_ENC_NO_DATA, "No data sealed yet.");
		}
		if (TcTpmStructsHelpers.isTpm11Struct(encBlob_)) {
			throw new TcTspException(TcTssErrors.TSS_E_INVALID_OBJ_ACCESS,
					"The sealed data is not an 1.2 TPM structure and therefore the requested "
							+ "information can not be provided.");
		}

		TcTpmStoredData12 storedData = new TcTpmStoredData12(encBlob_);
		TcTpmPcrInfoLong pcrLong = new TcTpmPcrInfoLong(storedData.getSealInfo());

		TcBlobData retVal = null;
		if (subFlag == TcTssConstants.TSS_TSPATTRIB_ENCDATAPCRLONG_CREATION_SELECTION) {
			retVal = pcrLong.getCreationPCRSelection().getEncoded();
		} else if (subFlag == TcTssConstants.TSS_TSPATTRIB_ENCDATAPCRLONG_RELEASE_SELECTION) {
			retVal = pcrLong.getReleasePcrSelection().getEncoded();
		} else if (subFlag == TcTssConstants.TSS_TSPATTRIB_ENCDATAPCRLONG_DIGEST_ATCREATION) {
			retVal = pcrLong.getDigestAtCreation().getEncoded();
		} else if (subFlag == TcTssConstants.TSS_TSPATTRIB_ENCDATAPCRLONG_DIGEST_ATRELEASE) {
			retVal = pcrLong.getDigestAtRelease().getEncoded();
		} else {
			throw new TcTspException(TcTssErrors.TSS_E_INVALID_ATTRIB_SUBFLAG);
		}

		return retVal;
	}


	/*************************************************************************************************
	 * This method is used to retrieve PcrInfo information about sealed data. Not that this method can
	 * only be used if 1.1 PCR structures are used. This method is an alternative to using
	 * {@link TcIAttributes#getAttribData(long, long)} with
	 * {@link TcTssConstants#TSS_TSPATTRIB_ENCDATA_PCR} as flag.
	 * 
	 * @param subFlag Valid subFlags are:
	 *          <ul>
	 *          <li> {@link TcTssConstants#TSS_TSPATTRIB_ENCDATAPCR_DIGEST_ATCREATION}
	 *          <li> {@link TcTssConstants#TSS_TSPATTRIB_ENCDATAPCR_DIGEST_ATRELEASE}
	 *          <li> {@link TcTssConstants#TSS_TSPATTRIB_ENCDATAPCR_SELECTION}
	 *          </ul>
	 * 
	 * @return The request information.
	 * 
	 * 
	 */
	public synchronized TcBlobData getAttribPcr(long subFlag) throws TcTspException
	{
		if (usageMode_ != TcTssConstants.TSS_ENCDATA_SEAL) {
			throw new TcTspException(TcTssErrors.TSS_E_INVALID_OBJECT_TYPE,
					"This object is not a sealed data object.");
		}
		if (encBlob_ == null) {
			throw new TcTspException(TcTssErrors.TSS_E_ENC_NO_DATA, "No data sealed yet.");
		}
		if (!TcTpmStructsHelpers.isTpm11Struct(encBlob_)) {
			throw new TcTspException(TcTssErrors.TSS_E_INVALID_OBJ_ACCESS,
					"The sealed data is not an 1.1 TPM structure and therefore the requested "
							+ "information can not be provided.");
		}

		TcTpmStoredData storedData = new TcTpmStoredData(encBlob_);
		TcTpmPcrInfo pcrInfo = new TcTpmPcrInfo(storedData.getSealInfo());

		TcBlobData retVal = null;
		if (subFlag == TcTssConstants.TSS_TSPATTRIB_ENCDATAPCR_DIGEST_ATCREATION) {
			retVal = pcrInfo.getDigestAtCreation().getEncoded();
		} else if (subFlag == TcTssConstants.TSS_TSPATTRIB_ENCDATAPCR_DIGEST_ATRELEASE) {
			retVal = pcrInfo.getDigestAtRelease().getEncoded();
		} else if (subFlag == TcTssConstants.TSS_TSPATTRIB_ENCDATAPCR_SELECTION) {
			retVal = pcrInfo.getPcrSelection().getEncoded();
		} else {
			throw new TcTspException(TcTssErrors.TSS_E_INVALID_ATTRIB_SUBFLAG);
		}

		return retVal;
	}

}
