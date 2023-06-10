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
import iaik.tc.tss.api.structs.tpm.TcTpmEncauth;
import iaik.tc.tss.api.structs.tpm.TcTpmSecret;
import iaik.tc.tss.api.structs.tsp.TcTssVersion;
import iaik.tc.tss.api.tspi.TcIAuthObject;
import iaik.tc.tss.api.tspi.TcIContext;
import iaik.tc.tss.api.tspi.TcIPolicy;
import iaik.tc.tss.api.tspi.TcIRsaKey;
import iaik.tc.tss.impl.java.tsp.internal.TcTspInternal;
import iaik.tc.utils.misc.CheckPrecondition;

/**
 * This class implements common methods for all auth objects. That are all those working objects
 * that require authorization to be used. Amon those objects are e.g. the TPM, key or EncData
 * objects.
 */
public abstract class TcAuthObject extends TcWorkingObject implements TcIAuthObject {

	/**
	 * The usage policy currently assigned to the object.
	 */
	protected TcPolicy usagePolicy_ = null;


	/*************************************************************************************************
	 * Constructor.
	 */
	protected TcAuthObject(TcIContext context) throws TcTssException
	{
		super(context);
	}


	/*************************************************************************************************
	 * This internal method changes the authorization data of an entity that requires owner
	 * authorization (i.e. the SRK key and the TPM).
	 */
	protected synchronized void genericChangeAuthOwner(int entityType, TcIPolicy parentPolicy,
			TcIPolicy newPolicy) throws TcTssException
	{
		checkContextOpenAndConnected();
		CheckPrecondition.notNull(parentPolicy, "parentPolicy");
		context_.checkAssociation(parentPolicy, "parentPolicy");
		CheckPrecondition.notNull(newPolicy, "newPolicy");
		context_.checkAssociation(newPolicy, "newPolicy");

		if (entityType != TcTpmConstants.TPM_ET_SRK && entityType != TcTpmConstants.TPM_ET_OWNER) {
			throw new TcTspException(TcTssErrors.TSS_E_BAD_PARAMETER,
					"entity type must be ET_SRK or ET_OWNER");
		}

		// start OSAP session
		Object[] osapData = createOsapSession(TcTpmConstants.TPM_ET_OWNER, 0, parentPolicy, newPolicy);
		TcTcsAuth osapSession = (TcTcsAuth) osapData[0];
		TcTpmEncauth newEncAuth = (TcTpmEncauth) osapData[1];
		TcTpmSecret osapSecret = (TcTpmSecret) osapData[2];

		// call to TPM
		TcTspInternal.TspChangeAuthOwner_Internal(context_, TcTpmConstants.TPM_PID_ADCP, newEncAuth,
				entityType, osapSession, osapSecret);

		// assign TPM to new policy object
		newPolicy.assignToObject(this);
	}


	/*************************************************************************************************
	 * This internal method can be used to change the auth of RsaKey and EncData objects. 
	 */
	protected synchronized TcBlobData genericChangeAuth(int entityTypeOsap, long entityValueOsap,
			int entityTypeToChange, TcBlobData encData, long parentHandle, TcIPolicy parentPolicy,
			TcIPolicy newPolicy, TcIPolicy currentPolicy) throws TcTssException
	{
		checkContextOpenAndConnected();
		CheckPrecondition.notNull(encData, "encData");
		CheckPrecondition.notNullAndInstanceOf(parentPolicy, "parentPolicy", TcPolicy.class);
		CheckPrecondition.notNull(newPolicy, "newPolicy");
		CheckPrecondition.notNullAndInstanceOf(currentPolicy, "currentPolicy", TcPolicy.class);

		// start OIAP session
		TcTcsAuth oiapSession = TcTspInternal.TspOIAP_Internal(context_);

		// start OSAP session
		Object[] osapData = createOsapSession(entityTypeOsap, entityValueOsap, parentPolicy, newPolicy);
		TcTcsAuth osapSession = (TcTcsAuth) osapData[0];
		TcTpmEncauth encNewAuth = (TcTpmEncauth) osapData[1];
		TcTpmSecret osapSecret = (TcTpmSecret) osapData[2];

		// Note: TPM spec 1.1. and 1.2 differ for this command regarding the computation of the
		// validation data.
		// On 1.1 TPMs the HMAC key for the second auth session has to be the new entity secret while on
		// 1.2 TPMs the second HMAC key has to be the entity old secret.
		TcTssVersion tpmVer = ((TcTpm) context_.getTpmObject()).getRealTpmVersion();
		TcTpmSecret entityAuthVal = null;
		if (tpmVer.equalsMinMaj(TcTssVersion.TPM_V1_1)) {
			entityAuthVal = ((TcPolicy) newPolicy).getTpmSecret();
		} else {
			entityAuthVal = ((TcPolicy) currentPolicy).getTpmSecret();
		}

		// call down to TPM
		Object[] tpmOutData = TcTspInternal.TspChangeAuth_Internal(context_, parentHandle,
				TcTpmConstants.TPM_PID_ADCP, encNewAuth, entityTypeToChange, encData, osapSession,
				oiapSession, osapSecret, ((TcPolicy) currentPolicy).getTpmSecret(), entityAuthVal);

		return (TcBlobData) tpmOutData[2];
	}


	/*
	 * (non-Javadoc)
	 * 
	 * @see iaik.tss.api.tspi.TcIAuthObject#changeAuthAsym(iaik.tss.api.tspi.TcIWorkingObject,
	 *      iaik.tss.api.tspi.TcIRsaKey, iaik.tss.api.tspi.TcIPolicy)
	 */
	public synchronized void changeAuthAsym(final TcIAuthObject parentObject,
			final TcIRsaKey identKey, final TcIPolicy newPolicy) throws TcTssException
	{
		throw new TcTspException(TcTssErrors.TSS_E_NOTIMPL);
	}


	/*************************************************************************************************
	 * Note: Policy objects are returned by reference. Keep that in mind when modifying a policy.
	 * 
	 * For general documentation of this method refer to {@link TcIAuthObject#getPolicyObject(long)}.
	 */
	public synchronized TcIPolicy getPolicyObject(long policyType) throws TcTssException
	{
		if (policyType == TcTssConstants.TSS_POLICY_USAGE) {
			return usagePolicy_;
		} else {
			throw new TcTspException(TcTssErrors.TSS_E_BAD_PARAMETER,
					"The requested policy type is not supported.");
		}
	}


	/*************************************************************************************************
	 * Note: Policy objects are returned by reference. Keep that in mind when modifying a policy.
	 * 
	 * For general documentation of this method refer to {@link TcIAuthObject#getUsagePolicyObject()}.
	 */
	public synchronized TcIPolicy getUsagePolicyObject() throws TcTssException
	{
		return getPolicyObject(TcTssConstants.TSS_POLICY_USAGE);
	}


	/*************************************************************************************************
	 * This method sets the usage policy object that is assigned to this auth object. This
	 * functionality is used internally only and is therefore package protected.
	 * 
	 * @param policy The policy object to be set.
	 */
	protected synchronized void setUsagePolicy(TcIPolicy policy) throws TcTssException
	{
		CheckPrecondition.notNullAndInstanceOf(policy, "policy", TcPolicy.class);
		usagePolicy_ = (TcPolicy) policy;
	}
	
	
	/*
	 * (non-Javadoc)
	 * @see iaik.tc.tss.impl.java.tsp.TcWorkingObject#closeObject()
	 */
	protected synchronized void closeObject() throws TcTssException
	{
		// remove usage policy association
		((TcPolicy)getUsagePolicyObject()).removeAssignedAuthObj(this);
			
		super.closeObject();
	}
	
	@Override
	protected void finalize() throws Throwable {
		
		if (usagePolicy_!=null)
			usagePolicy_.flushSecret();
		
		usagePolicy_=null;
		
		// TODO Auto-generated method stub
		super.finalize();
		
		
	}
	
}
