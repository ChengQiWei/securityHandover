/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.api.tspi;


import iaik.tc.tss.api.constants.tsp.TcTssConstants;
import iaik.tc.tss.api.exceptions.common.TcTssException;
import iaik.tc.tss.api.structs.common.TcBlobData;

/**
 * The Policy class represents information authorization data (secrets), authorization data handling
 * and the assigned authorized objects like key objects or encrypted data objects.<br />
 * 
 * <b>Secret Lifetime:</b> If an application uses the mode TSS_SECRET_LIFETIME_COUNTER or
 * TSS_SECRET_LIFETIME_TIMER, the application has to be aware that during a command processing the
 * secret may be invalidated because of a time out or because the counter runs out. <br/>
 * 
 * <b>TSPI Default Policy:</b> Each context has its own default policy object that is automatically
 * assigned to a new key or encrypted data object after its creation. If this policy object is not
 * appropriate, a different policy object can be assigned with
 * {@link TcIPolicy#assignToObject(TcIAuthObject)}.
 * 
 * When a working object is added to a policy, the reference to the working object is added to the
 * list of assigned objects stored in that policy object and the reference to the policy object is
 * stored on the working object.
 * 
 * @TSS_1_2_EA 221
 */
public interface TcIPolicy extends TcIWorkingObject, TcIAttributes {

	/*************************************************************************************************
	 * This method sets the authorization data of a policy object and defines the handling of its
	 * retrieval.
	 * 
	 * @TSS_V1 101
	 * 
	 * @TSS_1_2_EA 233
	 * 
	 * @param secretMode Flag indicating the policy secret mode to set. Secret mode values are
	 *          prefixed with TSS_SECRET_MODE_ and are defined in {@link TcTssConstants}. <br>
	 *          Valid secretModes are:
	 *          <ul>
	 *          <li>{@link TcTssConstants#TSS_SECRET_MODE_NONE}
	 *          <li>{@link TcTssConstants#TSS_SECRET_MODE_PLAIN}
	 *          <li>{@link TcTssConstants#TSS_SECRET_MODE_POPUP}
	 *          <li>{@link TcTssConstants#TSS_SECRET_MODE_SHA1}
	 *          </ul>
	 *          Note that there is another secret mode ({@link TcTssConstants#TSS_SECRET_MODE_CALLBACK}).
	 *          To actually use the callback functionality to obtain the secret, the setAttribData
	 *          method has to be used to set the callback. If this is done, the setSecret method must
	 *          not be called.
	 * @param secret The secret data blob.
	 */
	public void setSecret(final long secretMode, final TcBlobData secret) throws TcTssException;


	/*************************************************************************************************
	 * This method flushes a cached secret.
	 * 
	 * @TSS_V1 102
	 * 
	 * @TSS_1_2_EA 235
	 */
	public void flushSecret() throws TcTssException;


	/*************************************************************************************************
	 * This method assigns an object (working object) like TPM object, key object, encrypted data
	 * object to a certain policy. Each of these working objects will utilize its assigned policy
	 * object to process an authorized TPM command.
	 * 
	 * Note that there are two different policies that can be assigned to a working object, usage
	 * policy and migration policy. The type of a policy object is determined upon creation of the
	 * policy object or later using the {@link TcIAttributes#setAttribData(long, long, TcBlobData)}.
	 * 
	 * @TSS_V1 103
	 * 
	 * @TSS_1_2_EA 236
	 * 
	 * @param obj The object to be assigned.
	 */
	public void assignToObject(final TcIAuthObject obj) throws TcTssException;
}