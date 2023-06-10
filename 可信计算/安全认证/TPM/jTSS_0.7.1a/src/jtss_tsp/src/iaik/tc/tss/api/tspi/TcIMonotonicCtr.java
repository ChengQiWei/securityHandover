/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.api.tspi;

import iaik.tc.tss.api.exceptions.common.TcTssException;
import iaik.tc.tss.api.structs.common.TcBlobData;

/**
 * This class is used to store information about a monotonic counter 
 * inside the TPM, for use when defining, releasing, reading or incrementing such a
 * counter. 
 */
public interface TcIMonotonicCtr extends TcIAttributes, TcIAuthObject {

	/** Sets the handle referred to by this counter 
	public void setHandle(final long handle);
	*/

	/*************************************************************************************************
	 * This method creates the counter with the label provided. Note that
	 * this command requires owner authorization which can be set via the usage
	 * policy of the TPM object.
	 *
	 * @TSS_1_2_EA 381
	 *
	 * @param label 
   *          The label value used to identify this counter
	* @return
     *     0 ... The handle for the counter (Long)
     *     1 ... The starting counter value (TcTpmCounterValue)
	 */
	public Object[] createCtr(final TcBlobData label) throws TcTssException;

	/*************************************************************************************************
	 * This method releases the counter. 
	 * Note that this command requires owner authorization which can be set via
	 * the usage policy of the TPM object.
	 *
	 * @TSS_1_2_EA 383
	 *
	 *
	 */
	public void releaseCtr() throws TcTssException;

	/*************************************************************************************************
	 * This method increments a previously defined counter. 
	 * A policy object must be assigned to this object; the authData within the policy
	 * object will be used to authorize this operation. 
	 * @TSS_1_2_EA 384
	 *
	 * @return The new TcTpmCounterValue post increment
	 */
	public Object incrementCtr()
			throws TcTssException;

	/*************************************************************************************************
	 * This method reads the counter value. 
	 *
	 * @return The current value of the counter 
	 *
	 *
	 */
	public long readCtr()
			throws TcTssException;

}
