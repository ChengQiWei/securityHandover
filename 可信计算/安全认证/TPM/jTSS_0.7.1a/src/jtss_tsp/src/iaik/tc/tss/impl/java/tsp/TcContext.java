/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler, Ronald Toegl
 */

package iaik.tc.tss.impl.java.tsp;


import iaik.tc.tss.api.constants.tpm.TcTpmConstants;
import iaik.tc.tss.api.constants.tsp.TcTssConstants;
import iaik.tc.tss.api.constants.tsp.TcTssErrors;
import iaik.tc.tss.api.exceptions.common.TcTssException;
import iaik.tc.tss.api.exceptions.tcs.TcTpmException;
import iaik.tc.tss.api.exceptions.tsp.TcTspException;
import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.tss.api.structs.tpm.TcTpmStructVer;
import iaik.tc.tss.api.structs.tpm.TcTpmVersion;
import iaik.tc.tss.api.structs.tsp.TcTssKmKeyinfo;
import iaik.tc.tss.api.structs.tsp.TcTssUuid;
import iaik.tc.tss.api.structs.tsp.TcTssVersion;
import iaik.tc.tss.api.structs.tsp.TcUuidFactory;
import iaik.tc.tss.api.tspi.TcIAttributes;
import iaik.tc.tss.api.tspi.TcIContext;
import iaik.tc.tss.api.tspi.TcIEncData;
import iaik.tc.tss.api.tspi.TcIHash;
import iaik.tc.tss.api.tspi.TcIMigData;
import iaik.tc.tss.api.tspi.TcIMonotonicCtr;
import iaik.tc.tss.api.tspi.TcINvRam;
import iaik.tc.tss.api.tspi.TcIPcrComposite;
import iaik.tc.tss.api.tspi.TcIPolicy;
import iaik.tc.tss.api.tspi.TcIRsaKey;
import iaik.tc.tss.api.tspi.TcITpm;
import iaik.tc.tss.api.tspi.TcIWorkingObject;
import iaik.tc.tss.impl.java.tsp.internal.TcTspInternal;
import iaik.tc.tss.impl.java.tsp.internal.TcTspProperties;
import iaik.tc.tss.impl.java.tsp.tcsbinding.TcITcsBinding;
import iaik.tc.tss.impl.ps.TcITssPersistentStorage;
import iaik.tc.utils.logging.Log;
import iaik.tc.utils.misc.CheckPrecondition;
import iaik.tc.utils.misc.Utils;
import iaik.tc.utils.properties.Properties;

import java.lang.reflect.Constructor;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Iterator;
import java.util.Vector;

public class TcContext extends TcWorkingObject implements TcIContext {

	/**
	 * This field holds the binding that is used when interacting with the TCS.
	 */
	protected TcITcsBinding tcsBinding_;

	/**
	 * This field holds the handle of the TCS context that is associated with this TSP context.
	 */
	protected long tcsContextHandle_;

	/**
	 * This field holds the connection status of the context.
	 */
	protected boolean connected_ = false;

	/**
	 * This flag holds the status if dialog popups (e.g. for entering user passwords should be
	 * displayed or not.
	 */
	protected long silentMode_ = TcTssConstants.TSS_TSPATTRIB_CONTEXT_NOT_SILENT;

	/**
	 * This field is used to determine if 1.1 or 1.2 structs should be used.
	 */
	protected long versionMode_ = TcTssConstants.TSS_TSPATTRIB_CONTEXT_VERSION_V1_1;

	/**
	 * This field defines if passwords originating from a popup window are hashed with or without null
	 * termination.
	 */
	protected long popupHashMode_ = TcTssConstants.TSS_TSPATTRIB_HASH_MODE_NOT_NULL;

	/**
	 * This field holds the connection version. It determines if the underlying TCS and TPM support
	 * 1.1 or 1.2 features.
	 */
	protected long connectionVersion_ = TcTssConstants.TSS_CONNECTION_VERSION_1_1;

	/**
	 * There only is on TPM object per context. This field holds this TPM instance that is returned
	 * upon getTpm.
	 */
	protected TcTpm tpmInstance_ = null;

	/**
	 * This field holds all working objects that have been created by this context.
	 */
	protected Vector workingObjects_ = new Vector();

	/**
	 * This field holds the default usage policy. This policy object is created upon context creation
	 * and is assigned to every auth object that is created by this context.
	 */
	protected TcPolicy defaultUsagePolicy_ = null;

	/**
	 * This field indicates the version of the TSP. Shouldn't be set manually,
	 * as it will be set when built with ant.
	 */
	//DOT NOT CHANGE MANUALLY
	private final String tspVersion_ = "0.7.1a"; //THIS IS SET AUTOMATICALLY BY THE ANT BUILD FILE
	//DOT NOT CHANGE MANUALLY



	protected static TcITssPersistentStorage psUser_ = null;

	// This static block is used to instantiate TSP components such as the binding to the TCS the key cache or the system
	// persistent storage.
	static {


		// instantiate persistent storage
		String psClassName = "";

		try {
			psClassName = TcTspProperties.getInstance().getProperty(TcTspProperties.TSP_INI_SEC_PS,
					TcTspProperties.TSP_INI_KEY_PS_TYPE);
			Class cls = Class.forName(psClassName);
			Class[] constParams = new Class[] { Properties.class };
			Constructor constr = cls.getConstructor(constParams);

			psUser_ = (TcITssPersistentStorage) constr.newInstance(new Object[] { TcTspProperties
					.getInstance() });

		} catch (TcTspException e) {
			Log.info("Unable to open TSP configuration file for system persistent "
					+ "storage information. Disabling user persistent storage.");
		} catch (Exception e) {
			Log.info("Unable to instantiate user persistent storage (" + psClassName
					+ "). Disabling user persistent storage.");
		}
	}



	/*************************************************************************************************
	 * Hidden constructor (factory pattern).
	 */
	protected TcContext(final TcITcsBinding tcsBinding) throws TcTssException
	{
		context_ = this;
		CheckPrecondition.notNull(tcsBinding, "tcsBinding");
		tcsBinding_ = tcsBinding;

		// create default usage policy object
		defaultUsagePolicy_ = (TcPolicy) createPolicyObject(TcTssConstants.TSS_POLICY_USAGE);
	}


	/*
	 * (non-Javadoc)
	 *
	 * @see iaik.tss.api.tspi.TcIContext#connect(java.lang.String)
	 */
	public synchronized void connect(String hostname) throws TcTssException
	{
		if (isConnected()) {
			return;
		}

		// hostname can be null

		TcTspInternal.TspContextConnect_Internal(this, hostname);

		connected_ = true;
		tcsContextHandle_ = TcTspInternal.TspContextOpen_Internal(this);
		// TODO: remove direct call to TCSI binding

		// detect the Version of the TPM we are connected to and set the connectionVersion accordingly.

		TcTssVersion tpmVersion = null;
		try {
			tpmVersion = getTpmObject().getCapabilityVersion(TcTssConstants.TSS_TPMCAP_VERSION_VAL, null);
		} catch (TcTpmException e) {
			tpmVersion = getTpmObject().getCapabilityVersion(TcTssConstants.TSS_TPMCAP_VERSION, null);
		}

		if (tpmVersion.equalsMinMaj(TcTssVersion.TPM_V1_2)) {
			connectionVersion_ = TcTssConstants.TSS_CONNECTION_VERSION_1_2;
			versionMode_ = TcTssConstants.TSS_TSPATTRIB_CONTEXT_VERSION_V1_2;



		} else {
			connectionVersion_ = TcTssConstants.TSS_CONNECTION_VERSION_1_1;
			versionMode_ = TcTssConstants.TSS_TSPATTRIB_CONTEXT_VERSION_V1_1;
		}
	}


	/*
	 * (non-Javadoc)
	 *
	 * @see iaik.tss.api.tspi.TcIContext#connect()
	 */
	public synchronized void connect() throws TcTssException
	{
		connect("");
	}


	/*
	 * (non-Javadoc)
	 *
	 * @see iaik.tss.api.tspi.TcIContext#closeContext()
	 */
	public synchronized void closeContext() throws TcTssException
	{
		checkContextOpen();

		// TSS spec: This method destroys a context and releases all assigned resources.
		// Consequently, all working objects are invalidated.
		Iterator it = workingObjects_.iterator();
		while (it.hasNext()) {
			TcIWorkingObject obj = (TcIWorkingObject) it.next();
			synchronized (obj) {
				it.remove();
				((TcWorkingObject) obj).context_ = null;
			}
		}

		tpmInstance_ = null;

		try {
			if (connected_) {
				TcTspInternal.TspContextClose_Internal(this);
				connected_ = false;
			}
			context_ = null;

		} catch (TcTpmException e) {
			context_ = null;
			throw new TcTspException(TcTssErrors.TSS_E_COMM_FAILURE);

		} catch (TcTssException e) {
			context_ = null;
			throw new TcTspException(TcTssErrors.TSS_E_COMM_FAILURE);
		}
	}


	/*************************************************************************************************
	 * In case a context is garbage collected make sure that its TCS connection is shut down.
	 */
	protected void finalize() throws Throwable
	{
		closeContext();
	}


	/*
	 * (non-Javadoc)
	 *
	 * @see iaik.tss.api.tspi.TcIContext#closeObject(iaik.tss.api.tspi.TcIBaseObject)
	 */
	public synchronized void closeObject(TcIWorkingObject obj) throws TcTssException
	{
		checkContextOpen();
		CheckPrecondition.notNullAndInstanceOf(obj, "obj", TcWorkingObject.class);
		context_.checkAssociation(obj, "obj");

		// Ensure that closing an object does not interfere with other operations currently
		// executed on that object (note: working-object access methods are synchronized).
		synchronized (obj) {

			// The TPM object is a singleton that is not closed.
			if (obj instanceof TcTpm) {
				return;
			}

			// object specific cleanup
			((TcWorkingObject) obj).closeObject();

			// Finally remove the object from the list of working objects.
			workingObjects_.remove(obj);
		}
	}


	/*************************************************************************************************
	 * This method returns the underlying TCS binding. This method is used by internal methods only to
	 * get access to the TCS.
	 */
	public synchronized TcITcsBinding getTcsBinding()
	{
		return tcsBinding_;
	}


	/*************************************************************************************************
	 * This method returns the handle of the corresponding TCS context.
	 */
	public synchronized long getTcsContextHandle() throws TcTssException
	{
		return tcsContextHandle_;
	};


	/*
	 * (non-Javadoc)
	 *
	 * @see iaik.tss.api.tspi.TcIContext#isConnected()
	 */
	public synchronized boolean isConnected()
	{
		return connected_;
	}


	/*************************************************************************************************
	 * This method is not required in a pure Java TSS implementation and therefore not supported.
	 *
	 * @deprecated
	 */
	public void freeMemory(long cPtr) throws TcTssException
	{
		throw new TcTspException(TcTssErrors.TSS_E_NOTIMPL,
				"The freeMemory method is not required in a pure Java implementation "
						+ "and therefore not supported.");
	}


	/*
	 * (non-Javadoc)
	 *
	 * @see iaik.tss.api.tspi.TcIContext#getCapability(long, iaik.tss.api.structs.TcBlobData)
	 */
	public synchronized TcBlobData getCapability(long capArea, TcBlobData subCap)
		throws TcTssException
	{
		return TcTspInternal.TspContextGetCapability_Internal(context_, capArea, subCap);
	}


	/*
	 * (non-Javadoc)
	 *
	 * @see iaik.tss.api.tspi.TcIContext#getCapabilityBoolean(long, iaik.tss.api.structs.TcBlobData)
	 */
	public synchronized boolean getCapabilityBoolean(long capArea, TcBlobData subCap)
		throws TcTssException
	{
		byte retByte;
		boolean retVal = false;

		switch ((int) capArea) {

//			case (int) TcTssConstants.TSS_TSPCAP_ALG :
//				break;

			case ((int) TcTssConstants.TSS_TSPCAP_PERSSTORAGE) :
				retVal = true;
				break;

			case ((int) TcTssConstants.TSS_TCSCAP_ALG) :
				retByte = TcTspInternal.TspContextGetCapability_Internal(
						context_, capArea, subCap).asByteArray()[0];
				retVal = Utils.byteToBoolean(retByte);
				break;

			case ((int) TcTssConstants.TSS_TCSCAP_CACHING) :
				retByte = TcTspInternal.TspContextGetCapability_Internal(
						context_, capArea, subCap).asByteArray()[0];
				retVal = Utils.byteToBoolean(retByte);
				break;

			case ((int) TcTssConstants.TSS_TCSCAP_PERSSTORAGE) :
				retByte = TcTspInternal.TspContextGetCapability_Internal(
						context_, capArea, subCap).asByteArray()[0];
				retVal = Utils.byteToBoolean(retByte);
				break;

			default :
				throw new TcTspException(TcTssErrors.TSS_E_BAD_PARAMETER,
						"Unknown/unsupported capability. (" + Utils.longToHex(capArea) + ")");
		}

		return retVal;
	}


	/*
	 * (non-Javadoc)
	 *
	 * @see iaik.tss.api.tspi.TcIContext#getCapabilityVersion(long, iaik.tss.api.structs.TcBlobData)
	 */
	public synchronized TcTssVersion getCapabilityVersion(long capArea, TcBlobData subCap)
		throws TcTssException
	{
		TcTssVersion retVal = new TcTssVersion();
		switch ((int) capArea) {

			case (int) TcTssConstants.TSS_TCSCAP_VERSION :
				TcBlobData tcsVersionBlob = getCapability(capArea, subCap);
				TcTpmVersion tcsVersion = new TcTpmVersion(tcsVersionBlob);
				retVal.init(tcsVersion.getMajor(), tcsVersion.getMinor(),
						tcsVersion.getRevMajor(), tcsVersion.getRevMinor());
				break;

			case (int) TcTssConstants.TSS_TSPCAP_VERSION :
				int revIndex = tspVersion_.indexOf(".");
				retVal.init((short)1, (short)2,
						Short.parseShort(tspVersion_.substring(0, revIndex)),
						//only take the first digit after the "." of the TSP Version
						Short.parseShort(tspVersion_.substring(revIndex+1, revIndex+2)));
				break;

			default:
				throw new TcTspException(TcTssErrors.TSS_E_BAD_PARAMETER,
						"Unknown/unsupported capability. (" + Utils.longToHex(capArea) + ")");
		}

		return retVal;
	}


	/*
	 * (non-Javadoc)
	 *
	 * @see iaik.tss.api.tspi.TcIContext#createEncDataObject(long)
	 */
	public synchronized TcIEncData createEncDataObject(long initFlags) throws TcTssException
	{
		checkContextOpen();
		TcEncData encData = new TcEncData(this);
		encData.setInitFlags(initFlags);
		defaultUsagePolicy_.assignToObject(encData);
		workingObjects_.add(encData);
		return encData;
	}


	/*
	 * (non-Javadoc)
	 *
	 * @see iaik.tss.api.tspi.TcIContext#createHashObject(long)
	 */
	public synchronized TcIHash createHashObject(long initFlags) throws TcTssException
	{
		checkContextOpen();
		TcHash hash = new TcHash(this);
		hash.setInitFlags(initFlags);
		workingObjects_.add(hash);
		return hash;
	}


	/*
	 * (non-Javadoc)
	 *
	 * @see iaik.tss.api.tspi.TcIContext#createMigDataObject(long)
	 */
	public TcIMigData createMigDataObject(long initFlags) throws TcTssException
	{
		checkContextOpen();
		TcMigData migData = new TcMigData(this);
		workingObjects_.add(migData);
		return migData;
	}


	/*
	 * (non-Javadoc)
	 *
	 * @see iaik.tss.api.tspi.TcIContext#createPcrCompositeObject(long)
	 */
	public synchronized TcIPcrComposite createPcrCompositeObject(long initFlags)
		throws TcTssException
	{
		checkContextOpen();
		TcIPcrComposite retVal = null;

		if (initFlags == TcTssConstants.TSS_PCRS_STRUCT_INFO_SHORT) {
			retVal = new TcPcrCompositeInfoShort(this);

		} else if (initFlags == TcTssConstants.TSS_PCRS_STRUCT_INFO_LONG) {
			retVal = new TcPcrCompositeInfoLong(this);

		} else if (initFlags == TcTssConstants.TSS_PCRS_STRUCT_INFO) {
			retVal = new TcPcrCompositeInfo(this);

		} else {
			// TcTssConstants.TSS_PCRS_STRUCT_DEFAULT or unspecified struct version

			if (getAttribVersionMode(0) == TcTssConstants.TSS_TSPATTRIB_CONTEXT_VERSION_V1_2) {
				retVal = new TcPcrCompositeInfoLong(this); // DEFAULT on 1.2 TPMs
			} else {
				retVal = new TcPcrCompositeInfo(this); // DEFAULT on 1.1 or if unspecified
				// initFlags
			}
		}

		workingObjects_.add(retVal);
		return retVal;
	}


	/*
	 * (non-Javadoc)
	 *
	 * @see iaik.tss.api.tspi.TcIContext#createPolicyObject(long)
	 */
	public synchronized TcIPolicy createPolicyObject(long initFlags) throws TcTssException
	{
		checkContextOpen();
		TcPolicy policy = new TcPolicy(this);
		policy.setInitFlags(initFlags);
		workingObjects_.add(policy);
		return policy;
	}


	/*************************************************************************************************
	 * For general details on this method please refer to {@link TcIContext#createRsaKeyObject(long)}.
	 * <br>
	 * <b>Implementation specific note:</b> The TSS specification states that upon creation of new
	 * working objects, these objects are assigned to the default policy of the TSS. The specification
	 * however leaves room for interpretation if new working objects get a copy of the default policy
	 * of the context or if all working objects share the same policy object. For this implementation
	 * it has been opted to go with the first variant, namely that working objects are assigned a real
	 * copy of the current default policy of the context.
	 */
	public synchronized TcIRsaKey createRsaKeyObject(long initFlags) throws TcTssException
	{
		TcRsaKey key = new TcRsaKey(this);
		key.setInitFlags(initFlags);
		defaultUsagePolicy_.assignToObject(key);
		TcIPolicy defaultMigrationPolicyClone = createPolicyObject(TcTssConstants.TSS_POLICY_MIGRATION);
		defaultMigrationPolicyClone.assignToObject(key);
		workingObjects_.add(key);
		return key;
	}


	/*************************************************************************************************
	 * Note: The default policy object is returned by reference.
	 *
	 * For general documentation of this method refer to {@link TcIContext#getDefaultPolicy()}.
	 */
	public synchronized TcIPolicy getDefaultPolicy() throws TcTssException
	{
		return defaultUsagePolicy_;
	}


	/*
	 * (non-Javadoc)
	 *
	 * @see iaik.tss.api.tspi.TcIContext#getKeyByPublicInfo(long, long,
	 *      iaik.tss.api.structs.TcBlobData)
	 */
	public synchronized TcIRsaKey getKeyByPublicInfo(long stypeKey, long algId, TcBlobData publicInfo)
		throws TcTssException
	{

		if (stypeKey != TcTssConstants.TSS_PS_TYPE_USER && stypeKey != TcTssConstants.TSS_PS_TYPE_SYSTEM)
		{
			throw new TcTspException(TcTssErrors.TSS_E_BAD_PARAMETER);
		}



		long TpmAlgorithmId=TcConstantsMappings.algMap.getTpmForTssVal(algId);
		TcBlobData keyBlob=null;

		if (stypeKey == TcTssConstants.TSS_PS_TYPE_USER)
		{
			keyBlob=psUser_.getRegisteredKeyByPublicInfo(TpmAlgorithmId, publicInfo);
		}

		if (stypeKey == TcTssConstants.TSS_PS_TYPE_SYSTEM)
		{
			//get the key blob from storage
			TcITcsBinding tcs = context_.getTcsBinding();
			keyBlob= tcs.TcsiGetRegisteredKeyByPublicInfo(context_.tcsContextHandle_, TpmAlgorithmId, publicInfo);
		}


		//Make shore the correct (TPM1.1 or 1.2) key blog type is chosen for key object creation.

		long keyStruct = 0;
		// there are two legal values blob can have: TPM_KEY and TPM_KEY12
		TcBlobData tagKey12 = TcBlobData.newByteArray(new byte[] { 0x00, TcTpmConstants.TPM_TAG_KEY12 });
		TcBlobData tag = TcBlobData.newByteArray(keyBlob.getRange(0, 2));

		if (tag.equals(tagKey12))
		{
			keyStruct = TcTssConstants.TSS_KEY_STRUCT_KEY12;

		} else {
			TcBlobData ver = TcBlobData.newByteArray(keyBlob.getRange(0, 4));
			if (new TcTpmStructVer(ver).equalsMinMaj(TcTpmStructVer.TPM_V1_1)) {
				keyStruct = TcTssConstants.TSS_KEY_STRUCT_KEY;
			} else {
				throw new TcTspException(TcTssErrors.TSS_E_BAD_PARAMETER,
						"The given blob seems to be neither a 1.1 nor a 1.2 TPM key blob.");
			}
		}


		//Create the new key object from storage.
		TcIRsaKey key = context_.createRsaKeyObject(TcTssConstants.TSS_KEY_EMPTY_KEY | keyStruct);
		((TcRsaKey) key).setAttribKeyBlob(TcTssConstants.TSS_TSPATTRIB_KEYBLOB_BLOB, keyBlob);

		return key;


	}


	/*
	 * (non-Javadoc)
	 *
	 * @see iaik.tss.api.tspi.TcIContext#getKeyByUuid(long, iaik.tss.api.structs.tsp.TcTssUuid)
	 */
	public synchronized TcIRsaKey getKeyByUuid(long stypeKey, TcTssUuid uuidKey)
	throws TcTssException
	{


		//Test for special case SRK

		if (uuidKey.equals(TcUuidFactory.getInstance().getUuidSRK())) {

			//TODO: This is a special treatment for the SRK for testing purposes, should be removed, when the no authentication needed mode is supported

			TcIRsaKey srk = context_.createRsaKeyObject(TcTssConstants.TSS_KEY_TSP_SRK);

			return srk;
		}



		if (stypeKey != TcTssConstants.TSS_PS_TYPE_USER && stypeKey != TcTssConstants.TSS_PS_TYPE_SYSTEM)
		{
			throw new TcTspException(TcTssErrors.TSS_E_BAD_PARAMETER);
		}


		//Get the key blob
		TcBlobData keyBlob=null;

		if (stypeKey == TcTssConstants.TSS_PS_TYPE_USER)
		{
			keyBlob=psUser_.getRegisteredKeyBlob(uuidKey);
		}

		if (stypeKey == TcTssConstants.TSS_PS_TYPE_SYSTEM)
		{
			//get the key blob from storage
			TcITcsBinding tcs = context_.getTcsBinding();
			keyBlob= tcs.TcsiGetRegisteredKeyBlob(context_.tcsContextHandle_, uuidKey);

		}


		//Create a TcRsaKey object

		//Make shore the correct (TPM1.1 or 1.2) key blog type is chosen for key object creation.

		long keyStruct = 0;
		// there are two legal values blob can have: TPM_KEY and TPM_KEY12
		TcBlobData tagKey12 = TcBlobData.newByteArray(new byte[] { 0x00, TcTpmConstants.TPM_TAG_KEY12 });
		TcBlobData tag = TcBlobData.newByteArray(keyBlob.getRange(0, 2));

		if (tag.equals(tagKey12))
		{
			keyStruct = TcTssConstants.TSS_KEY_STRUCT_KEY12;

		} else {
			TcBlobData ver = TcBlobData.newByteArray(keyBlob.getRange(0, 4));
			if (new TcTpmStructVer(ver).equalsMinMaj(TcTpmStructVer.TPM_V1_1)) {
				keyStruct = TcTssConstants.TSS_KEY_STRUCT_KEY;
			} else {
				throw new TcTspException(TcTssErrors.TSS_E_BAD_PARAMETER,
						"The given blob seems to be neither a 1.1 nor a 1.2 TPM key blob.");
			}
		}


		//Create the new key object from storage.
		TcIRsaKey key = context_.createRsaKeyObject(TcTssConstants.TSS_KEY_EMPTY_KEY | keyStruct);
		((TcRsaKey) key).setAttribKeyBlob(TcTssConstants.TSS_TSPATTRIB_KEYBLOB_BLOB, keyBlob);

		key.setAttribUuid(uuidKey);

		return key;

	}


	/*
	 * (non-Javadoc)
	 *
	 * @see iaik.tss.api.tspi.TcIContext#getRegisteredKeysByUuid(iaik.tss.api.structs.tsp.TcTssUuid,
	 *      long)
	 */
	public synchronized TcTssKmKeyinfo[] getRegisteredKeysByUuid(TcTssUuid uuid, long storage)
		throws TcTssException
	{


		if (storage==TcTssConstants.TSS_PS_TYPE_USER)
			return getRegisteredKeysByUuidUser(uuid);

		if (storage==TcTssConstants.TSS_PS_TYPE_SYSTEM)
			return getRegisteredKeysByUuidSystem(uuid);

		//all other cases
		throw new TcTspException(TcTssErrors.TSS_E_BAD_PARAMETER);


	}


	/*
	 * (non-Javadoc)
	 *
	 * @see iaik.tss.api.tspi.TcIContext#getRegisteredKeysByUuidSystem(iaik.tss.api.structs.tsp.TcTssUuid)
	 */
	public synchronized TcTssKmKeyinfo[] getRegisteredKeysByUuidSystem(TcTssUuid uuid)
		throws TcTssException
	{
		TcITcsBinding tcs = context_.getTcsBinding();

		TcTssKmKeyinfo[] keyInfos =  tcs.TcsiEnumRegisteredKeys(context_.tcsContextHandle_, uuid);

		return keyInfos;
	}


	/*
	 * (non-Javadoc)
	 *
	 * @see iaik.tss.api.tspi.TcIContext#getRegisteredKeysByUuidUser(iaik.tss.api.structs.tsp.TcTssUuid)
	 */
	public synchronized TcTssKmKeyinfo[] getRegisteredKeysByUuidUser(TcTssUuid uuid)
		throws TcTssException
	{

		TcTssKmKeyinfo[] userKeys =  psUser_.enumRegisteredKeys(uuid);

		if (userKeys==null || userKeys.length==0) {	//No keys are registered
			return null;
		}

		TcTssUuid systemPSLeafElement=userKeys[userKeys.length-1].getParentKeyUuid();

		TcITcsBinding tcs = context_.getTcsBinding();

		TcTssKmKeyinfo[] systemKeys =  tcs.TcsiEnumRegisteredKeys(context_.tcsContextHandle_, systemPSLeafElement);

		int systemKeyLength=0;

		if (systemKeys!=null)
		{
			systemKeyLength=systemKeys.length;
		}


		TcTssKmKeyinfo[] keyHierarchy = new TcTssKmKeyinfo[userKeys.length+systemKeyLength];

		int i,j;
		for (i=0; i!=userKeys.length;i++) //Note: no SRK here
		{
			keyHierarchy[i]=userKeys[i];
		}

		for (j=0; j!=systemKeyLength;j++)	//By spec, the last one must be the SRK
		{
			keyHierarchy[i+j]=systemKeys[j];
		}

		return keyHierarchy;

	}


	/*
	 * (non-Javadoc)
	 *
	 * @see iaik.tss.api.tspi.TcIContext#getTpmObject()
	 */
	public synchronized TcITpm getTpmObject() throws TcTssException
	{
		checkContextOpenAndConnected();
		if (tpmInstance_ == null) {
			tpmInstance_ = new TcTpm(this);
			// the TPM does not use the default policy but gets an own policy (TSS_1_2_EA 163)
			createPolicyObject(TcTssConstants.TSS_POLICY_USAGE).assignToObject(tpmInstance_);
		}

		return tpmInstance_;
	}


	/*
	 * (non-Javadoc)
	 *
	 * @see iaik.tss.api.tspi.TcIContext#loadKeyByBlob(iaik.tss.api.tspi.TcIRsaKey,
	 *      iaik.tss.api.structs.TcBlobData)
	 */
	public synchronized TcIRsaKey loadKeyByBlob(TcIRsaKey unwrappingKey, TcBlobData blob)
		throws TcTssException
	{
		checkContextOpen();
		CheckPrecondition.notNullAndInstanceOf(unwrappingKey, "unwrappingKey", TcRsaKey.class);
		context_.checkAssociation(unwrappingKey, "unwrappingKey");
		CheckPrecondition.notNull(blob, "blob");

		long keyStruct = 0;

		// there are two legal values blob can have: TPM_KEY and TPM_KEY12
		TcBlobData tagKey12 = TcBlobData
				.newByteArray(new byte[] { 0x00, TcTpmConstants.TPM_TAG_KEY12 });
		TcBlobData tag = TcBlobData.newByteArray(blob.getRange(0, 2));

		if (tag.equals(tagKey12)) {
			keyStruct = TcTssConstants.TSS_KEY_STRUCT_KEY12;

		} else {
			TcBlobData ver = TcBlobData.newByteArray(blob.getRange(0, 4));
			if (new TcTpmStructVer(ver).equalsMinMaj(TcTpmStructVer.TPM_V1_1)) {
				keyStruct = TcTssConstants.TSS_KEY_STRUCT_KEY;
			} else {
				throw new TcTspException(TcTssErrors.TSS_E_BAD_PARAMETER,
						"The given blob seems to be neither a 1.1 nor a 1.2 TPM key blob.");
			}
		}

		TcIRsaKey retKey = createRsaKeyObject(TcTssConstants.TSS_KEY_EMPTY_KEY | keyStruct);
		((TcRsaKey) retKey).setAttribKeyBlob(TcTssConstants.TSS_TSPATTRIB_KEYBLOB_BLOB, blob);
		retKey.loadKey(unwrappingKey);


		return retKey;
	}


	/*
	 * (non-Javadoc)
	 *
	 * @see iaik.tss.api.tspi.TcIContext#loadKeyByUuidFromSystem(iaik.tss.api.structs.tsp.TcTssUuid)
	 */
	public synchronized TcIRsaKey loadKeyByUuidFromSystem(TcTssUuid uuid) throws TcTssException
	{
		// Original comment by tw: compatibility workaround for TrouSerS until we have PS

		if (uuid.equals(TcUuidFactory.getInstance().getUuidSRK())) {
			TcIRsaKey srk = context_.createRsaKeyObject(TcTssConstants.TSS_KEY_TSP_SRK);

			return srk;
		}

		throw new TcTspException(TcTssErrors.TSS_E_NOTIMPL);

		//TODO: activate the code as soon as the no authentication mode is supported
//
//		TcTssKmKeyinfo[] keyInfos= getRegisteredKeysByUuidSystem(uuid);
//
//		TcIRsaKey[] keys=new TcIRsaKey[keyInfos.length];
//
//		for (int i=0; i!=keyInfos.length;i++)
//		{
//			TcIRsaKey key = getKeyByUuid(TcTssConstants.TSS_PS_TYPE_SYSTEM, keyInfos[i].getKeyUuid());
//			keys[i] = key;
//		}
//
//
//		for (int i=keys.length-1; i!=-1;i--) //We need to walk down the key hierarchy..
//		{
//
//			// Assumes that the isLoaded flag works!
//			// Else no key that needs authorisation must be within the hierarchy
//			if (keyInfos[i].getAuthDataUsage()!= (short)0 && !keyInfos[i].isLoaded() )
//			{
//				throw new TcTspException(TcTssErrors.TSS_E_KEY_NOT_LOADED);
//
//			}
//
//
//			if (keyInfos[i].isLoaded()) //skip loaded keys. Note: the SRK is always loaded
//			{
//				continue;
//			}
//
//			assert(i<keys.length-1); //since the SRK is always loaded, it will be skipped. Then this statement will hold.
//
//			TcIRsaKey currentKey = keys[i];
//			TcIRsaKey parentKey = keys[i+1];
//
//			currentKey.loadKey(parentKey);
//
//		}
//
//		return keys[0];

	}


	/*
	 * (non-Javadoc)
	 *
	 * @see iaik.tss.api.tspi.TcIContext#loadKeyByUuidFromUser(iaik.tss.api.structs.tsp.TcTssUuid)
	 */
	public synchronized TcIRsaKey loadKeyByUuidFromUser(TcTssUuid uuid) throws TcTssException
	{

		//TODO: activate the code as soon as the no authentication mode is supported

		// This only works for keys that do not require authorisation (by spec). However, our implementation does not support these
		// non-authorized keys yet

		throw new TcTspException(TcTssErrors.TSS_E_NOTIMPL);

//		//Merge key hierarchies, and retrieve all individual keys from PS
//
//
//
//		TcTssKmKeyinfo[] userKeys =  psUser_.enumRegisteredKeys(uuid);
//
//		if (userKeys==null | userKeys.length==0)
//		{
//			throw new TcTspException(TcTssErrors.TSS_E_PS_KEY_NOTFOUND,"Could not load key from user persistent storage." +
//					" Key or key hierarachy not found for "+ uuid.toString());
//		}
//
//
//		TcTssUuid lastUserKeyParent=userKeys[userKeys.length-1].getParentKeyUuid();
//
//		TcITcsBinding tcs = context_.getTcsBinding();
//		TcTssKmKeyinfo[] systemKeys =  tcs.TcsiEnumRegisteredKeys(context_.tcsContextHandle_, lastUserKeyParent);
//
//		TcTssKmKeyinfo[] keyHierarchy = new TcTssKmKeyinfo[userKeys.length+systemKeys.length];
//		TcIRsaKey[] keys=new TcIRsaKey[keyHierarchy.length];
//
//		int i,j;
//
//		for (i=0; i!=userKeys.length;i++) //Note: no SRK here
//		{
//			keyHierarchy[i]=userKeys[i];
//			TcIRsaKey key = getKeyByUuid(TcTssConstants.TSS_PS_TYPE_USER, userKeys[i].getKeyUuid());
//			keys[i] = key;
//		}
//
//		for (j=0; j!=systemKeys.length;j++)	//By spec, the last one must be the SRK
//		{
//			keyHierarchy[i+j]=systemKeys[j];
//			TcIRsaKey key = getKeyByUuid(TcTssConstants.TSS_PS_TYPE_SYSTEM, systemKeys[j].getKeyUuid());
//			keys[i+j] = key;
//		}
//
//
//		//Now load all the keys in reverse order
//
//		for (int k=keys.length-1; k!=-1;k--) //We need to walk down the key hierarchy..
//		{
//			// Assumes that the isLoaded flag works!
//			// Else no key that needs authorisation must be within the hierarchy
//			if (keyHierarchy[i].getAuthDataUsage()!= (short)0 && !keyHierarchy[i].isLoaded() )
//			{
//				throw new TcTspException(TcTssErrors.TSS_E_KEY_NOT_LOADED);
//
//			}
//
//			if (keyHierarchy[k].isLoaded()) //skip loaded keys. Note: the SRK is always loaded
//			{
//				continue;
//			}
//
//			assert(k<keys.length-1); //since the SRK is always loaded, it will be skipped. Then this statement will hold.
//
//			TcIRsaKey currentKey = keys[k];
//			TcIRsaKey parentKey = keys[k+1];
//
//			currentKey.loadKey(parentKey);
//
//		}
//
//		return keys[0];
	}


	/*
	 * (non-Javadoc)
	 *
	 * @see iaik.tss.api.tspi.TcIContext#registerKey(iaik.tss.api.tspi.TcIRsaKey, long,
	 *      iaik.tss.api.structs.tsp.TcTssUuid, long, iaik.tss.api.structs.tsp.TcTssUuid)
	 */
	public synchronized void registerKey(TcIRsaKey key, long stypeKey, TcTssUuid uuidKey,
			long stypeParentKey, TcTssUuid uuidParent) throws TcTssException
	{

		if (stypeKey != TcTssConstants.TSS_PS_TYPE_USER &&  stypeKey != TcTssConstants.TSS_PS_TYPE_SYSTEM)
		{
			throw new TcTspException(TcTssErrors.TSS_E_BAD_PARAMETER, "Neither user nor system persistent storage was selected.");
		}

		TcBlobData keyBlob= key.getAttribData(TcTssConstants.TSS_TSPATTRIB_KEY_BLOB, TcTssConstants.TSS_TSPATTRIB_KEYBLOB_BLOB);

		if (stypeKey == TcTssConstants.TSS_PS_TYPE_USER)
		{
			psUser_.registerKey(uuidParent, uuidKey, keyBlob);

		}

		if (stypeKey == TcTssConstants.TSS_PS_TYPE_SYSTEM)
		{
			TcITcsBinding tcs = context_.getTcsBinding();
			tcs.TcsiRegisterKey(context_.tcsContextHandle_, uuidParent, uuidKey, keyBlob, null); 	//Vendor Data set to null for now..

		}

	}


	/*
	 * (non-Javadoc)
	 *
	 * @see iaik.tss.api.tspi.TcIContext#unregisterKey(long, iaik.tss.api.structs.tsp.TcTssUuid)
	 */
	public synchronized TcIRsaKey unregisterKey(long stypeKey, TcTssUuid uuidKey)
		throws TcTssException
	{

		TcIRsaKey key = context_.getKeyByUuid(stypeKey, uuidKey);

		if (stypeKey == TcTssConstants.TSS_PS_TYPE_USER)
		{
			psUser_.unregisterKey(uuidKey);

		}

		if (stypeKey == TcTssConstants.TSS_PS_TYPE_SYSTEM)
		{

		TcITcsBinding tcs = context_.getTcsBinding();
		tcs.TcsiUnregisterKey(context_.tcsContextHandle_, uuidKey);

		}

		return key;
	}


	/*************************************************************************************************
	 * This internal method checks if the given working object is associated with the context. If not,
	 * an exception is thrown.
	 */
	protected synchronized void checkAssociation(TcIWorkingObject obj, String objName)
		throws TcTspException
	{
		CheckPrecondition.notNull(obj, "obj");
		CheckPrecondition.notNull(objName, "objName");

		if (!workingObjects_.contains(obj)) {
			throw new TcTspException(TcTssErrors.TSS_E_BAD_PARAMETER, "The given working object ("
					+ objName + ") does not belong to this context.");
		}
	}


	// ----------------------------------------------------------------------------------------------
	// TSS attribute getters and setter
	// ----------------------------------------------------------------------------------------------

	/*
	 * (non-Javadoc)
	 *
	 * @see iaik.tss.impl.java.tsp.TcAttributes#initAttribGetters()
	 */
	protected void initAttribGetters()
	{
		// UINT32
		addGetterUINT32(TcTssConstants.TSS_TSPATTRIB_CONTEXT_SILENT_MODE, "getAttribSilentMode");
		addGetterUINT32(TcTssConstants.TSS_TSPATTRIB_CONTEXT_VERSION_MODE, "getAttribVersionMode");
		addGetterUINT32(TcTssConstants.TSS_TSPATTRIB_SECRET_HASH_MODE, "getAttribHashMode");
		addGetterUINT32(TcTssConstants.TSS_TSPATTRIB_CONTEXT_CONNECTION_VERSION,
				"getAttribConnectionVersion");

		// Data
		addGetterData(TcTssConstants.TSS_TSPATTRIB_CONTEXT_MACHINE_NAME, "getAttribMachineName");
	}


	/*
	 * (non-Javadoc)
	 *
	 * @see iaik.tss.impl.java.tsp.TcAttributes#initAttribSetters()
	 */
	protected void initAttribSetters()
	{
		// UINT32
		addSetterUINT32(TcTssConstants.TSS_TSPATTRIB_CONTEXT_SILENT_MODE, "setAttribSilentMode");
		addSetterUINT32(TcTssConstants.TSS_TSPATTRIB_CONTEXT_VERSION_MODE, "setAttribVersionMode");
		addSetterUINT32(TcTssConstants.TSS_TSPATTRIB_SECRET_HASH_MODE, "setAttribHashMode");

		// Data: none
	}


	/*************************************************************************************************
	 * This method is used to specify if GUI popups for entering passwords should be displayed or not.
	 * By default, popups will be displayed. This method is an alternative to using
	 * {@link TcIAttributes#setAttribUint32(long, long, long)}. Note that this method is not
	 * standardized as part of the TSP Interface (TSPI).
	 *
	 * @param subflag Ignored (set to 0).
	 * @param attrib Either {@link TcTssConstants#TSS_TSPATTRIB_CONTEXT_SILENT} or
	 *          {@link TcTssConstants#TSS_TSPATTRIB_CONTEXT_NOT_SILENT}.
	 *
	 * @throws TcTssException
	 */
	public synchronized void setAttribSilentMode(long subflag, long attrib) throws TcTssException
	{
		if (attrib != TcTssConstants.TSS_TSPATTRIB_CONTEXT_SILENT
				&& attrib != TcTssConstants.TSS_TSPATTRIB_CONTEXT_NOT_SILENT) {
			throw new TcTspException(TcTssErrors.TSS_E_BAD_PARAMETER, "Unknown context mode value.");
		} else {
			silentMode_ = attrib;
		}
	}


	/*************************************************************************************************
	 * This method returns the silent mode setting of the context. This method is an alternative to
	 * using {@link TcIAttributes#getAttribUint32(long, long)}.
	 *
	 * @param subFlag Ignored (set to 0).
	 *
	 * @return Either {@link TcTssConstants#TSS_TSPATTRIB_CONTEXT_SILENT} or
	 *         {@link TcTssConstants#TSS_TSPATTRIB_CONTEXT_NOT_SILENT}.
	 *
	 * @throws TcTssException
	 */
	public synchronized long getAttribSilentMode(long subFlag) throws TcTssException
	{
		return silentMode_;
	}


	/*************************************************************************************************
	 * This method is used to specify if 1.1 or 1.2. data structures should be created. The default
	 * setting are 1.1 data structures. This method is an alternative to using
	 * {@link TcIAttributes#setAttribUint32(long, long, long)}.
	 *
	 * @param subflag Ignored (set to 0).
	 * @param attrib Either {@link TcTssConstants#TSS_TSPATTRIB_CONTEXT_VERSION_V1_1} or
	 *          {@link TcTssConstants#TSS_TSPATTRIB_CONTEXT_VERSION_V1_2} or
	 *          {@link TcTssConstants#TSS_TSPATTRIB_CONTEXT_VERSION_AUTO}.
	 *
	 * @throws TcTssException
	 */
	public synchronized void setAttribVersionMode(long subflag, long attrib) throws TcTssException
	{
		if (attrib != TcTssConstants.TSS_TSPATTRIB_CONTEXT_VERSION_V1_1
				&& attrib != TcTssConstants.TSS_TSPATTRIB_CONTEXT_VERSION_V1_2
				&& attrib != TcTssConstants.TSS_TSPATTRIB_CONTEXT_VERSION_AUTO) {
			throw new TcTspException(TcTssErrors.TSS_E_BAD_PARAMETER, "Unknown context mode value.");
		} else {
			versionMode_ = attrib;
		}
	}


	/*************************************************************************************************
	 * This method returns the version mode setting of the context. The version mode determines if 1.1
	 * or 1.2 data structures are created. This method is an alternative to using
	 * {@link TcIAttributes#getAttribUint32(long, long)}.
	 *
	 * @param subFlag Ignored (set to 0).
	 *
	 * @return Either {@link TcTssConstants#TSS_TSPATTRIB_CONTEXT_VERSION_V1_1} or
	 *         {@link TcTssConstants#TSS_TSPATTRIB_CONTEXT_VERSION_V1_2} or
	 *         {@link TcTssConstants#TSS_TSPATTRIB_CONTEXT_VERSION_AUTO}.
	 *
	 * @throws TcTssException
	 */
	public synchronized long getAttribVersionMode(long subFlag) throws TcTssException
	{
		return versionMode_;
	}


	/*************************************************************************************************
	 * This method is used to specify if passwords obtained via popups should be hashed with or
	 * without null termination. This method is an alternative to using
	 * {@link TcIAttributes#setAttribUint32(long, long, long)}.
	 *
	 * @param subflag {@link TcTssConstants#TSS_TSPATTRIB_SECRET_HASH_MODE_POPUP}
	 * @param attrib Either {@link TcTssConstants#TSS_TSPATTRIB_HASH_MODE_NOT_NULL} or
	 *          {@link TcTssConstants#TSS_TSPATTRIB_HASH_MODE_NULL}.
	 *
	 * @throws TcTssException
	 */
	public synchronized void setAttribHashMode(long subflag, long attrib) throws TcTssException
	{
		if (attrib != TcTssConstants.TSS_TSPATTRIB_HASH_MODE_NULL
				&& attrib != TcTssConstants.TSS_TSPATTRIB_HASH_MODE_NOT_NULL) {
			throw new TcTspException(TcTssErrors.TSS_E_BAD_PARAMETER, "Unknown context mode value.");
		} else {
			popupHashMode_ = attrib;
		}
	}


	/*************************************************************************************************
	 * This method returns if secrets obtained via popups are hashed with or without null termination.
	 * This method is an alternative to using {@link TcIAttributes#getAttribUint32(long, long)}.
	 *
	 * @param subFlag {@link TcTssConstants#TSS_TSPATTRIB_SECRET_HASH_MODE_POPUP}
	 *
	 * @return Either {@link TcTssConstants#TSS_TSPATTRIB_HASH_MODE_NOT_NULL} or
	 *         {@link TcTssConstants#TSS_TSPATTRIB_HASH_MODE_NULL}.
	 */
	public synchronized long getAttribHashMode(long subFlag) throws TcTssException
	{
		return popupHashMode_;
	}


	/*************************************************************************************************
	 * This method returns the connection version. The version indicates if 1.1 or 1.2 features are
	 * supported by the underlying TCS and TPM. This method is an alternative to using
	 * {@link TcIAttributes#getAttribUint32(long, long)}.
	 *
	 * @param subFlag Ignored (set to 0).
	 *
	 * @return Either {@link TcTssConstants#TSS_CONNECTION_VERSION_1_1} or
	 *         {@link TcTssConstants#TSS_CONNECTION_VERSION_1_2}.
	 *
	 * @throws {@link TcTssException}
	 */
	public synchronized long getAttribConnectionVersion(long subFlag) throws TcTssException
	{
		return connectionVersion_;
	}


	/*************************************************************************************************
	 * This method returns the machines host name. This method is an alternative to using
	 * {@link TcIAttributes#getAttribUint32(long, long)}.
	 *
	 * @param subFlag Ignored (set to 0).
	 *
	 * @return The host name of the machine.
	 *
	 * @throws {@link TcTssException}
	 */
	// no synchronization required: not touching any internal data
	public TcBlobData getAttribMachineName(long subFlag) throws TcTssException
	{
		String hostName;
		try {
			InetAddress addr = InetAddress.getLocalHost();
			hostName = addr.getHostName();
			return TcBlobData.newString(hostName);
		} catch (UnknownHostException e) {
			hostName = "unknown";
		}
		return TcBlobData.newString(hostName);
	}

	public TcIMonotonicCtr getMonotonicCounters(long handle) throws TcTssException {

		return new TcMonotonicCtr(this, handle);

	}


	public TcINvRam getNvRamObject(long nvIndex) throws TcTssException {

		return new TcNvRam(this, nvIndex);

	}
}
