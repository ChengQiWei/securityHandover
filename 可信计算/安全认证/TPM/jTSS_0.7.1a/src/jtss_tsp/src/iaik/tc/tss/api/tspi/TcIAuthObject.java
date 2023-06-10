/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.api.tspi;


import iaik.tc.tss.api.exceptions.common.TcTssException;

/**
 * This class implements common methods for all auth objects. That are all those working objects
 * that require authorization to be used. Amon those objects are e.g. the TPM, key or EncData
 * objects.
 */
public interface TcIAuthObject {

	/*************************************************************************************************
	 * This method changes the authorization data (secret) of an entity (object) and assigns the
	 * object to the newPolicy object. All classes using secrets provide this method for changing
	 * their authorization data.
	 * 
	 * To change the TPM owner authorization, this method has to be called on the TPM object. The
	 * parent has to be set to null. To change the SRK authorization, this method has to be called on
	 * the SRK key object and the parent has to be set to the TPM object.
	 * 
	 * @TSS_V1 71
	 * 
	 * @TSS_1_2_EA 179
	 * 
	 * @param parentObject The parent object wrapping this object.
	 * @param newPolicy Policy object providing the new authorization data.
	 * 
	 * 
	 */
	public void changeAuth(final TcIAuthObject parentObject, final TcIPolicy newPolicy)
		throws TcTssException;


	/*************************************************************************************************
	 * This method changes the authorization data (secret) of an entity (object) utilizing the
	 * asymmetric change protocol and assigns the object to the newPolicy object. All classes using
	 * secrets provide this method for changing their authorization data. This method changes the
	 * authorization data of an object ensuring that the parent of the object does not get knowledge
	 * of the new secret.
	 * 
	 * @TSS_V1 72
	 * 
	 * @TSS_1_2_EA 180
	 * 
	 * @param parentObject The parent object wrapping this object
	 * @param identKey The identity key object required to proof the internally created temporary key.
	 * @param newPolicy The policy object providing the new authorization data.
	 * 
	 * 
	 */
	public void changeAuthAsym(final TcIAuthObject parentObject, final TcIRsaKey identKey,
			final TcIPolicy newPolicy) throws TcTssException;


	/*************************************************************************************************
	 * This method returns the policy object currently assigned to a working object. If an application
	 * does not create a policy object and does not create a policy object and does not assign it to
	 * the working object prior to this call, this function returns the default context policy.
	 * Setting a new secret to the default policy will affect all future objects associated with this
	 * policy.
	 * 
	 * 
	 * @TSS_V1 73
	 * 
	 * @TSS_1_2_EA 182
	 * 
	 * @param policyType The policy type to be returned (TSS_POLICY_*)
	 * 
	 * @return Policy object currently assigned to the object.
	 * 
	 * 
	 */
	public TcIPolicy getPolicyObject(long policyType) throws TcTssException;


	/*************************************************************************************************
	 * This method returns a policy object representing the usage policy currently assigned to the
	 * object. It is based on the getPolicy method of the TSS with TSS_POLICY_USAGE as parameter.
	 * 
	 * @TSS_V1 73
	 * 
	 * @TSS_1_2_EA 182
	 * 
	 * @return Usage policy object.
	 * 
	 * 
	 */
	public TcIPolicy getUsagePolicyObject() throws TcTssException;

}
