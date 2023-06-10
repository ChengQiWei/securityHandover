/*
 * Copyright (C) 2009 IAIK, Graz University of Technology
 */
package iaik.tc.tss.impl.java.tsp;

import iaik.tc.tss.api.constants.tpm.TcTpmConstants;
import iaik.tc.tss.api.constants.tsp.TcTssErrors;
import iaik.tc.tss.api.exceptions.common.TcTssException;
import iaik.tc.tss.api.exceptions.tsp.TcTspException;
import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.tss.api.structs.tcs.TcTcsAuth;
import iaik.tc.tss.api.structs.tpm.TcTpmEncauth;
import iaik.tc.tss.api.structs.tpm.TcTpmSecret;
import iaik.tc.tss.api.structs.tpm.TcTpmCounterValue;
import iaik.tc.tss.api.tspi.TcIAuthObject;
import iaik.tc.tss.api.tspi.TcIContext;
import iaik.tc.tss.api.tspi.TcIPolicy;
import iaik.tc.tss.api.tspi.TcIMonotonicCtr;
import iaik.tc.tss.impl.java.tsp.internal.TcTspInternal;

/**
 * @author tpm
 */
public class TcMonotonicCtr extends TcAuthObject implements TcIMonotonicCtr {

	long ctrHandle_;

	/*
	 * (non-Javadoc)
	 * 
	 * @see iaik.tc.tss.impl.java.tsp.TcAttributes#initAttribGetters()
	 */
	protected TcMonotonicCtr(TcIContext context, long handle)
			throws TcTssException {
		super(context);
		ctrHandle_ = handle;

	}

	@Override
	protected void initAttribGetters() {
		// TODO Auto-generated method stub

	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see iaik.tc.tss.impl.java.tsp.TcAttributes#initAttribSetters()
	 */

	@Override
	protected void initAttribSetters() {
		// TODO Auto-generated method stub

	}

	/*************************************************************************************************
	 * This method releases the counter. Note that this command requires owner
	 * authorization which can be set via the usage policy of the TPM object.
	 * 
	 * @TSS_1_2_EA 383
	 * 
	 * 
	 */
	public void releaseCtr() throws TcTssException {
		TcTpmSecret ownerAuth = null;
		TcTcsAuth inAuth1 = null;
		TcTcsAuth outAuth1 = null;

		if (((TcPolicy) getUsagePolicyObject()) != null) {
			ownerAuth = ((TcPolicy) getUsagePolicyObject()).getTpmSecret();
			inAuth1 = TcTspInternal.TspOIAP_Internal(context_);

			outAuth1 = TcTspInternal.TspReleaseCounter_Internal(context_,
					ctrHandle_, inAuth1, ownerAuth);
		} else {
			throw new TcTspException(TcTssErrors.TSS_E_TSP_AUTHREQUIRED);
		}
	}

	/*************************************************************************************************
	 * This method increments a previously defined counter. A policy object must
	 * be assigned to this object; the authData within the policy object will be
	 * used to authorize this operation.
	 * 
	 * @TSS_1_2_EA 384
	 * 
	 */
	public Object incrementCtr() throws TcTssException {
		TcTpmSecret ownerAuth = null;
		TcTcsAuth inAuth1 = null;
		Object[] returnVals = null;
		
		if (((TcPolicy) getUsagePolicyObject()) != null) {
			ownerAuth = ((TcPolicy) getUsagePolicyObject()).getTpmSecret();
			inAuth1 = TcTspInternal.TspOIAP_Internal(context_);
		
		
			returnVals = TcTspInternal.TspIncrementCounter_Internal(context_,
					ctrHandle_, inAuth1, ownerAuth);
		} else {
			throw new TcTspException(TcTssErrors.TSS_E_TSP_AUTHREQUIRED);
		}

		if (returnVals != null && returnVals.length >= 2) {
			return returnVals[1];
		} else {
			return null;
		}

	}

	/*************************************************************************************************
	 * This method reads the counter value.
	 * 
	 * @return The current value of the counter
	 * 
	 */
	public long readCtr() throws TcTssException {
		TcTpmCounterValue counterValue = TcTspInternal.TspReadCounter_Internal(
				context_, ctrHandle_);

		return counterValue.getCounter();
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see iaik.tc.tss.api.tspi.TcITpm#createCtr()
	 */
	public Object[] createCtr(TcBlobData label) throws TcTssException {
		checkContextOpenAndConnected();

		if (((TcPolicy) this.getUsagePolicyObject()) == null) {
			// the policy which holds the usage secret for this ctr is not
			// assigned to "this"
			throw new TcTspException(TcTssErrors.TSS_E_TSP_AUTHREQUIRED,
					"Usage policy for entity not set");
		}

		if (((TcPolicy) context_.getTpmObject().getUsagePolicyObject()) == null) {
			// the policy holding the owner secret is not assigned to the tpm
			// object
			throw new TcTspException(TcTssErrors.TSS_E_TSP_AUTHREQUIRED,
					"policy with owner secret not set");
		}

		// start OSAP session
		// (when using TPM_ET_OWNER, the 2nd arg (value) is ignored -- see Line
		// 3080 of TPM Spec, Part 3)
		Object[] osapData = createOsapSession(TcTpmConstants.TPM_ET_OWNER, 0,
				context_.getTpmObject().getUsagePolicyObject(), this
						.getUsagePolicyObject());

		TcTcsAuth inAuth1 = (TcTcsAuth) osapData[0];
		TcTpmEncauth encAuth = (TcTpmEncauth) osapData[1];
		TcTpmSecret ownerAuth = (TcTpmSecret) osapData[2];

		Object[] returnVals = TcTspInternal.TspCreateCounter_Internal(context_,
				encAuth, label, inAuth1, ownerAuth);

		/*
		 * Parse out the return values The returned Object[] holds the following
		 * elements: 0 ... The outgoing authorization data for first session.
		 * (TcTpmAuth) 1 ... The handle for the counter (Long) 2 ... The
		 * starting counter value (TcTpmCounterValue)
		 */
		Long handle = null;
		TcTpmCounterValue startingValue = null;

		if (returnVals != null && returnVals.length >= 3) {

			handle = (Long) returnVals[1];
			ctrHandle_ = handle.longValue();

			startingValue = (TcTpmCounterValue) returnVals[2];
			
		}

		return new Object[] { handle, startingValue };
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @seeiaik.tc.tss.api.tspi.TcIAuthObject#changeAuth(iaik.tc.tss.api.tspi.
	 * TcIAuthObject, iaik.tc.tss.api.tspi.TcIPolicy)
	 */

	public void changeAuth(TcIAuthObject parentObject, TcIPolicy newPolicy)
			throws TcTssException {

		throw new TcTspException(TcTssErrors.TSS_E_NOTIMPL, "Not implemented");

	}

}
