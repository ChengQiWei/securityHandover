/*
 * authors: Thomas Winkler
 */

package iaik.tc.tss.impl.java.tsp;


import iaik.tc.tss.api.constants.tpm.TcTpmConstants;
import iaik.tc.tss.api.constants.tsp.TcTssConstants;
import iaik.tc.tss.api.constants.tsp.TcTssErrors;
import iaik.tc.tss.api.exceptions.common.TcTssException;
import iaik.tc.tss.api.exceptions.tsp.TcTspException;
import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.tss.api.structs.tpm.TcTpmSecret;
import iaik.tc.tss.api.structs.tsp.TcTssCallback;
import iaik.tc.tss.api.tspi.TcIAttributes;
import iaik.tc.tss.api.tspi.TcIAuthObject;
import iaik.tc.tss.api.tspi.TcIContext;
import iaik.tc.tss.api.tspi.TcIPolicy;
import iaik.tc.utils.misc.CheckPrecondition;
import iaik.tc.utils.misc.Utils;

import java.util.Vector;

public class TcPolicy extends TcWorkingObject implements TcIPolicy {

	/**
	 * This field determines the type of the policy object. This can either be
	 * {@link TcTssConstants#TSS_POLICY_USAGE}, {@link TcTssConstants#TSS_POLICY_USAGE} or
	 * {@link TcTssConstants#TSS_POLICY_OPERATOR}.
	 */
	private long policyType_;

	/**
	 * This field specifies is a null termination at the and of a password is included when computing
	 * the password hash. The default behavior is not to include the null termination.
	 */
	private long hashModePopup_ = 0;

	/**
	 * This filed specifies the lifetime of a secret. The default value is
	 * {@see TcTssConstants#TSS_TSPATTRIB_POLICYSECRET_LIFETIME_ALWAYS}.
	 */
	private long secretLifetime_ = TcTssConstants.TSS_TSPATTRIB_POLICYSECRET_LIFETIME_ALWAYS;

	/**
	 * This filed holds the point in time (in milliseconds) when the timer (LIFTIME_TIMER) was
	 * started.
	 */
	private long timerStart_ = 0;

	/**
	 * This filed holds the total number of seconds the secret is valid. Note that this value is not
	 * modified but remains at the value set using setAttribUint32. Together with the timerStart_
	 * value, this value is used to determine if the secret still is valid.
	 */
	private long timerDuration_ = 0;

	/**
	 * This filed holds number of times the secret can be used (in case of LIFTIME_COUNTER).
	 */
	private long secretCounter_ = 0;

	/**
	 * This field holds the string to be displayed on a popup window asking for a password.
	 */
	private TcBlobData popupString_ = TcBlobData.newString("Please enter the password:");

	/**
	 * This field holds the actual secret represented by this policy object. The secret is not the
	 * plaintext password but the SHA1 hash of the password.
	 */
	private TcBlobData secret_ = null;

	/**
	 * For TSS_SECRET_MODE_NONE, the secret is set to null. Therefore a check (secret_ == null) is not
	 * sufficient to determine if the secret has already been set. This flag allows to check that.
	 */
	private boolean secretSet_ = false;

	/**
	 * This field holds a callback object that was registered to be called to get the secret.
	 */
	private TcTssCallback callback_ = null;

	/**
	 * This field holds all working objects that have been assigned to this policy.
	 */
	private Vector assignedWorkingObjects_ = new Vector();


	/*************************************************************************************************
	 * Hidden constructor (factory pattern).
	 */
	protected TcPolicy(TcIContext context) throws TcTssException
	{
		super(context);
	}


	/*************************************************************************************************
	 * This method sets the policyType_ field. It checks if the provided policy is legal and if the
	 * list of working objects is empty. If there already are working objects assigned to this policy,
	 * an exception is thrown.
	 *
	 * @param policyType The policy type to set.
	 *
	 * @throws TcTssException
	 */
	protected synchronized void setInitFlags(long policyType) throws TcTssException
	{
		if (policyType != TcTssConstants.TSS_POLICY_USAGE
				&& policyType != TcTssConstants.TSS_POLICY_MIGRATION
				&& policyType != TcTssConstants.TSS_POLICY_OPERATOR) {
			throw new TcTspException(TcTssErrors.TSS_E_INVALID_OBJECT_INIT_FLAG,
					"Invalid policy object type.");
		}

		// only allow changing the policy type if there are no assigned working objects yet
		if (!assignedWorkingObjects_.isEmpty()) {
			throw new TcTspException(TcTssErrors.TSS_E_BAD_PARAMETER,
					"Can not change object type for policies that already have working objects assigned.");
		}

		policyType_ = policyType;
	}


	/*
	 * (non-Javadoc)
	 *
	 * @see iaik.tss.api.tspi.TcIPolicy#assignToObject(iaik.tss.api.tspi.TcIWorkingObject)
	 */
	public synchronized void assignToObject(TcIAuthObject obj) throws TcTssException
	{
		CheckPrecondition.notNullAndInstanceOf(obj, "obj", TcAuthObject.class);

		if (policyType_ == TcTssConstants.TSS_POLICY_USAGE) {
			TcAuthObject authObj = (TcAuthObject) obj;
			// remove references from previous policies to obj
			if (authObj.getUsagePolicyObject() != null) {
				((TcPolicy) authObj.getUsagePolicyObject()).assignedWorkingObjects_.remove(obj);
			}

			// set new policy
			authObj.setUsagePolicy(this);

			// add object to list of assigned working objects
			assignedWorkingObjects_.add((TcAuthObject) obj);

		} else if (policyType_ == TcTssConstants.TSS_POLICY_MIGRATION && obj instanceof TcRsaKey) {
			TcRsaKey authObj = (TcRsaKey) obj;
			// remove references from previous policies to obj
			if (authObj.getMigrationPolicyObject() != null) {
				((TcPolicy) authObj.getMigrationPolicyObject()).assignedWorkingObjects_.remove(obj);
			}

			// set new policy
			authObj.setMigrationPolicy(this);

			// add object to list of assigned working objects
			assignedWorkingObjects_.add((TcAuthObject) obj);
		}  else if (policyType_ == TcTssConstants.TSS_POLICY_OPERATOR && obj instanceof TcTpm) {
			TcTpm authObj = (TcTpm) obj;
			// remove references from previous policies to obj
			if (authObj.getOperatorPolicyObject() != null) {
				((TcPolicy) authObj.getOperatorPolicyObject()).assignedWorkingObjects_.remove(obj);
			}

			// set new policy
			authObj.setOperatorPolicy(this);

			// add object to list of assigned working objects
			assignedWorkingObjects_.add((TcAuthObject) obj);
		} else {
			throw new TcTspException(TcTssErrors.TSS_E_INTERNAL_ERROR, "Unknown policy type");
		}
	}


	/*
	 * (non-Javadoc)
	 *
	 * @see iaik.tss.api.tspi.TcIPolicy#flushSecret()
	 */
	public synchronized void flushSecret() throws TcTssException
	{
		if (secretSet_ == true && secret_ != null) {
			secretSet_ = false;
			secret_.invalidateContent();
			secret_ = null;
		}
	}


	/*
	 * (non-Javadoc)
	 *
	 * @see iaik.tss.api.tspi.TcIPolicy#setSecret(long, iaik.tss.api.structs.TcBlobData)
	 */
	public synchronized void setSecret(long secretMode, TcBlobData secret) throws TcTssException
	{
		// the callback secret mode has to be set using setAttribData
		if (secretMode == TcTssConstants.TSS_SECRET_MODE_CALLBACK) {
			throw new TcTspException(TcTssErrors.TSS_E_BAD_PARAMETER,
					"Secret mode callback has to be configured using setAttribData.");
		}

		// check if the requested secret mode is a known one
		if (secretMode != TcTssConstants.TSS_SECRET_MODE_NONE
				&& secretMode != TcTssConstants.TSS_SECRET_MODE_SHA1
				&& secretMode != TcTssConstants.TSS_SECRET_MODE_PLAIN
				&& secretMode != TcTssConstants.TSS_SECRET_MODE_POPUP) {
			throw new TcTspException(TcTssErrors.TSS_E_BAD_PARAMETER,
					"The given secret mode is not supported.");
		}

		// for mode none and mode popup, the secret can be null
		if (secretMode != TcTssConstants.TSS_SECRET_MODE_POPUP
				&& secretMode != TcTssConstants.TSS_SECRET_MODE_NONE) {
			CheckPrecondition.notNull(secret, "secret");
		}

		// set the secret_ field depending on the used secret mode
		if (secretMode == TcTssConstants.TSS_SECRET_MODE_PLAIN) {
			setSecret(secret.sha1());

		} else if (secretMode == TcTssConstants.TSS_SECRET_MODE_SHA1) {
			if (secret.getLength() != TcTpmConstants.TPM_SHA1_160_HASH_LEN) {
				throw new TcTspException(TcTssErrors.TSS_E_BAD_PARAMETER, "Illegal secret length.");
			}
			setSecret((TcBlobData) secret.clone());

		} else if (secretMode == TcTssConstants.TSS_SECRET_MODE_POPUP) {
			setSecret(displayPasswordPopup());

		} else if (secretMode == TcTssConstants.TSS_SECRET_MODE_NONE) {
			setSecret(null);
		}
	}


	/*************************************************************************************************
	 * This method should be used to set the secret_ field. It ensures that secret_ and secretSet_ are
	 * in sync.
	 */
	protected synchronized void setSecret(TcBlobData secret)
	{
		secret_ = secret;
		secretSet_ = true;
	}


	/*************************************************************************************************
	 * This method returns the cached secret held by this object. If there is no cached secret (i.e.
	 * secretSet == false) there are two options:<br>
	 * <ul>
	 * <li> If a callback was registered, this callback is invoked to obtain a secret.
	 * <li> If no callback was registered, a POPUP-window is displayed asking for the password.
	 * </ul>
	 * In both cases the hashed secret is cached before it is returned.
	 *
	 * This method also check the secret lifetime (counter or timer) as set via set setAttribData. If
	 * the lifetime of the secret has expired, the secret is flushed.
	 */
	protected synchronized TcBlobData getSecret() throws TcTssException
	{
		// if no secret is set, try to obtain it
		if (!secretSet_) {
			if (callback_ != null) {
				// TODO (callback): implement callback functionality to obtain the secret; then do setSecret
				throw new TcTspException(TcTssErrors.TSS_E_NOTIMPL,
						"Callback functionality not implemented");
			} else {
				setSecret(displayPasswordPopup());
			}
		}

		// TODO: better handling of secret == null for all callees (SECRET_MODE_NONE)
		// currently null secrets (i.e. secret_mode_none) are not supported!
		// When done: remove secret_ == null check from if clause below

		// check if the secret was set via callback or popup
		if (!secretSet_ || secret_ == null) {
			throw new TcTspException(TcTssErrors.TSS_E_POLICY_NO_SECRET,
					"No secret set for this policy object");
		}

		// check the lifetime of the secret
		TcBlobData retVal = null;
		if (secretLifetime_ == TcTssConstants.TSS_SECRET_LIFETIME_ALWAYS) {
			retVal = (TcBlobData) secret_.clone();

		} else if (secretLifetime_ == TcTssConstants.TSS_SECRET_LIFETIME_COUNTER) {
			if (secretCounter_ > 0) {
				retVal = (TcBlobData) secret_.clone();
				secretCounter_--;
				if (secretCounter_ == 0) {
					flushSecret();
				}
			} else {
				throw new TcTspException(TcTssErrors.TSS_E_POLICY_NO_SECRET,
						"The lifetime counter for the policy secret is exhausted.");
			}

		} else if (secretLifetime_ == TcTssConstants.TSS_SECRET_LIFETIME_TIMER) {
			if (System.currentTimeMillis() < (timerStart_ + (timerDuration_ * 1000))) {
				retVal = (TcBlobData) secret_.clone();
			} else {
				flushSecret();
				throw new TcTspException(TcTssErrors.TSS_E_POLICY_NO_SECRET,
						"The lifetime timer for the policy secret has expired.");
			}
		}

		return retVal;
	}


	/*************************************************************************************************
	 * This internal method is used to obtain the policy secret as a {@link TcTpmSecret} that can
	 * directly be used in calls send to the TPM. If no secret is set, null is returned.
	 */
	protected synchronized TcTpmSecret getTpmSecret() throws TcTssException
	{
		// TODO: check null secret handling for TSS_SECRET_MODE_NONE
		TcBlobData secret = getSecret();

		if (secret == null) {
			return null;
		} else {
			return new TcTpmSecret(secret);
		}
	}


	/*************************************************************************************************
	 * This method displays a GUI password dialog asking the user to enter a new password. The
	 * password entered by the user is then returned in it's SHA1 hashed form.
	 *
	 * @return SHA1 hash of the password entered by the user.
	 *
	 * @throws TcTssException If the user canceled the process of entering a password, this exception
	 *           is thrown.
	 */
	private synchronized TcBlobData displayPasswordPopup() throws TcTssException
	{
		checkContextOpen();
		if (context_.getAttribSilentMode(0) == TcTssConstants.TSS_TSPATTRIB_CONTEXT_SILENT) {
			throw new TcTspException(TcTssErrors.TSS_E_SILENT_CONTEXT,
					"Popups are disabled when context is in silent mode.");
		}
		TcPolicyPasswortPopup popup = new TcPolicyPasswortPopup(popupString_, true);
		return popup.getPasword().sha1();
	}


	/*************************************************************************************************
	 * Internal method returning a partial clone of the policy. Partial means that all internal state
	 * is cloned with the exception of the assignedWorkingObjects list.
	 */
	protected synchronized TcPolicy getPartialClone() throws TcTssException
	{
		checkContextOpen();
		TcPolicy retVal = new TcPolicy(context_);

		retVal.policyType_ = policyType_;
		retVal.hashModePopup_ = hashModePopup_;
		retVal.secretLifetime_ = secretLifetime_;
		retVal.timerStart_ = timerStart_;
		retVal.timerDuration_ = timerDuration_;
		retVal.secretCounter_ = secretCounter_;
		retVal.popupString_ = (popupString_ == null) ? null : (TcBlobData) popupString_.clone();
		retVal.secret_ = (secret_ == null) ? null : (TcBlobData) secret_.clone();
		retVal.secretSet_ = secretSet_;
		retVal.callback_ = (callback_ == null) ? null : (TcTssCallback) callback_.clone();

		return retVal;
	}


	/*************************************************************************************************
	 * This method returns true if the policy has working objects assigned to it, false otherwise. It
	 * is sued by the context to determine whether or not the policy can be closed.
	 */
	protected synchronized boolean hasAuthObjAssigned()
	{
		return !assignedWorkingObjects_.isEmpty();
	}


	/*************************************************************************************************
	 * This method is used to remove the given object reference from the list of assigned
	 * authorization objects. It is used by the context when closing authorization objects.
	 */
	protected synchronized void removeAssignedAuthObj(TcAuthObject assignedAuthObj)
	{
		assignedWorkingObjects_.remove(assignedAuthObj);
	}


	/*
	 * (non-Javadoc)
	 * @see iaik.tc.tss.impl.java.tsp.TcWorkingObject#closeObject()
	 */
	protected synchronized void closeObject() throws TcTssException
	{
		// Only close policy objects if they have no more auth objects assigned.
		if (!assignedWorkingObjects_.isEmpty()) {
				throw new TcTspException(TcTssErrors.TSS_E_FAIL,
						"Unable to close policy object that still has working objects assigned.");
		}

		super.closeObject();
	}

	// ----------------------------------------------------------------------------------------------
	// TSS attribute getters and setter
	// ----------------------------------------------------------------------------------------------

	/*************************************************************************************************
	 * This method defines the mapping of attribute flags to getter methods.
	 */
	protected void initAttribGetters()
	{
		addGetterUINT32(TcTssConstants.TSS_TSPATTRIB_POLICY_CALLBACK_HMAC, "getAttribCallbackUINT32");
		addGetterUINT32(TcTssConstants.TSS_TSPATTRIB_POLICY_CALLBACK_XOR_ENC, "getAttribCallbackUINT32");
		addGetterUINT32(TcTssConstants.TSS_TSPATTRIB_POLICY_CALLBACK_TAKEOWNERSHIP,
				"getAttribCallbackUINT32");
		addGetterUINT32(TcTssConstants.TSS_TSPATTRIB_POLICY_CALLBACK_CHANGEAUTHASYM,
				"getAttribCallbackUINT32");
		addGetterUINT32(TcTssConstants.TSS_TSPATTRIB_POLICY_SECRET_LIFETIME, "getAttribSecretLifetime");
		addGetterUINT32(TcTssConstants.TSS_TSPATTRIB_POLICY_DELEGATION_INFO,
				"getAttribDelegationInfoUINT32");
		addGetterUINT32(TcTssConstants.TSS_TSPATTRIB_POLICY_DELEGATION_PCR,
				"getAttribDelegationPcrUINT32");
		addGetterUINT32(TcTssConstants.TSS_TSPATTRIB_SECRET_HASH_MODE, "getAttribSecretHashMode");

		addGetterData(TcTssConstants.TSS_TSPATTRIB_POLICY_DELEGATION_INFO, "getAttribDelegationInfo");
		addGetterData(TcTssConstants.TSS_TSPATTRIB_POLICY_DELEGATION_PCR, "getAttribDelegationPcr");
		addGetterData(TcTssConstants.TSS_TSPATTRIB_POLICY_CALLBACK_CHANGEAUTHASYM, "getAttribCallback");
		addGetterData(TcTssConstants.TSS_TSPATTRIB_POLICY_CALLBACK_HMAC, "getAttribCallback");
		addGetterData(TcTssConstants.TSS_TSPATTRIB_POLICY_CALLBACK_SEALX_MASK, "getAttribCallback");
		addGetterData(TcTssConstants.TSS_TSPATTRIB_POLICY_CALLBACK_TAKEOWNERSHIP, "getAttribCallback");
		addGetterData(TcTssConstants.TSS_TSPATTRIB_POLICY_CALLBACK_XOR_ENC, "getAttribCallback");
		addGetterData(TcTssConstants.TSS_TSPATTRIB_POLICY_POPUPSTRING, "getAttribPopupString");
	}


	/*************************************************************************************************
	 * This method defines the mapping of attribute flags to setter methods.
	 */
	protected void initAttribSetters()
	{
		addSetterUINT32(TcTssConstants.TSS_TSPATTRIB_POLICY_CALLBACK_HMAC, "setAttribCallbackUINT32");
		addSetterUINT32(TcTssConstants.TSS_TSPATTRIB_POLICY_CALLBACK_XOR_ENC, "setAttribCallbackUINT32");
		addSetterUINT32(TcTssConstants.TSS_TSPATTRIB_POLICY_CALLBACK_TAKEOWNERSHIP,
				"setAttribCallbackUINT32");
		addSetterUINT32(TcTssConstants.TSS_TSPATTRIB_POLICY_CALLBACK_CHANGEAUTHASYM,
				"setAttribCallbackUINT32");
		addSetterUINT32(TcTssConstants.TSS_TSPATTRIB_POLICY_SECRET_LIFETIME, "setAttribSecretLifetime");
		addSetterUINT32(TcTssConstants.TSS_TSPATTRIB_POLICY_DELEGATION_INFO,
				"setAttribDelegationInfoUINT32");
		addSetterUINT32(TcTssConstants.TSS_TSPATTRIB_POLICY_DELEGATION_PCR,
				"setAttribDelegationPcrUINT32");
		addSetterUINT32(TcTssConstants.TSS_TSPATTRIB_SECRET_HASH_MODE, "setAttribSecretHashMode");

		addSetterData(TcTssConstants.TSS_TSPATTRIB_POLICY_DELEGATION_INFO, "setAttribDelegationInfo");
		addSetterData(TcTssConstants.TSS_TSPATTRIB_POLICY_CALLBACK_HMAC, "setAttribCallback");
		addSetterData(TcTssConstants.TSS_TSPATTRIB_POLICY_CALLBACK_XOR_ENC, "setAttribCallback");
		addSetterData(TcTssConstants.TSS_TSPATTRIB_POLICY_CALLBACK_TAKEOWNERSHIP, "setAttribCallback");
		addSetterData(TcTssConstants.TSS_TSPATTRIB_POLICY_CALLBACK_CHANGEAUTHASYM, "setAttribCallback");
		addSetterData(TcTssConstants.TSS_TSPATTRIB_POLICY_CALLBACK_SEALX_MASK, "setAttribCallback");
		addSetterData(TcTssConstants.TSS_TSPATTRIB_POLICY_POPUPSTRING, "setAttribPopupString");
	}


	/*************************************************************************************************
	 * The sole purpose of this method is to notify callers that TSS 1.1 style callback functions are
	 * not supported.
	 */
	public synchronized void setAttribCallbackUINT32(long subFlag, long attrib) throws TcTssException
	{
		throw new TcTspException(TcTssErrors.TSS_E_NOTIMPL,
				"TSS 1.1. callback functions are not supported.");
	}


	/*************************************************************************************************
	 * The sole purpose of this method is to notify callers that TSS 1.1 style callback functions are
	 * not supported.
	 */
	public synchronized long getAttribCallbackUINT32(long subFlag) throws TcTssException
	{
		throw new TcTspException(TcTssErrors.TSS_E_NOTIMPL,
				"TSS 1.1. callback functions are not supported.");
	}


	/*************************************************************************************************
	 * Not yet supported.
	 */
	public synchronized void setAttribCallback(long subFlag, TcBlobData attrib) throws TcTssException
	{
		throw new TcTspException(TcTssErrors.TSS_E_NOTIMPL,
				"TSS 1.2. callback functions not yet implemented.");
	}


	/*************************************************************************************************
	 * Not yet supported.
	 */
	public synchronized TcBlobData getAttribCallback(long subFlag) throws TcTssException
	{
		throw new TcTspException(TcTssErrors.TSS_E_NOTIMPL,
				"TSS 1.2. callback functions not yet implemented.");
	}


	/*************************************************************************************************
	 * Not yet supported.
	 */
	public synchronized void setAttribDelegationPcrUINT32(long subFlag, long attrib)
		throws TcTssException
	{
		throw new TcTspException(TcTssErrors.TSS_E_NOTIMPL, "Delegation is not yet implemented.");
	}


	/*************************************************************************************************
	 * Not yet supported.
	 */
	public synchronized long getAttribDelegationPcrUINT32(long subFlag) throws TcTssException
	{
		throw new TcTspException(TcTssErrors.TSS_E_NOTIMPL, "Delegation is not yet implemented.");
	}


	/*************************************************************************************************
	 * Not yet supported.
	 */
	public synchronized void setAttribDelegationPcr(long subFlag, TcBlobData attrib)
		throws TcTssException
	{
		throw new TcTspException(TcTssErrors.TSS_E_NOTIMPL, "Delegation is not yet implemented.");
	}


	/*************************************************************************************************
	 * Not yet supported.
	 */
	public synchronized TcBlobData getAttribDelegationPcr(long subFlag) throws TcTssException
	{
		throw new TcTspException(TcTssErrors.TSS_E_NOTIMPL, "Delegation is not yet implemented.");
	}


	/*************************************************************************************************
	 * Not yet supported.
	 */
	public synchronized void setAttribDelegationInfoUINT32(long subFlag, long attrib)
		throws TcTssException
	{
		throw new TcTspException(TcTssErrors.TSS_E_NOTIMPL, "Delegation is not yet implemented.");
	}


	/*************************************************************************************************
	 * Not yet supported.
	 */
	public synchronized long getAttribDelegationInfoUINT32(long subFlag) throws TcTssException
	{
		throw new TcTspException(TcTssErrors.TSS_E_NOTIMPL, "Delegation is not yet implemented.");
	}


	/*************************************************************************************************
	 * Not yet supported.
	 */
	public synchronized void setAttribDelegationInfo(long subFlag, TcBlobData attrib)
		throws TcTssException
	{
		throw new TcTspException(TcTssErrors.TSS_E_NOTIMPL, "Delegation is not yet implemented.");
	}


	/*************************************************************************************************
	 * Not yet supported.
	 */
	public synchronized TcBlobData getAttribDelegationInfo(long subFlag) throws TcTssException
	{
		throw new TcTspException(TcTssErrors.TSS_E_NOTIMPL, "Delegation is not yet implemented.");
	}


	/*************************************************************************************************
	 * This method is a shortcut for calling {@link TcIAttributes#setAttribUint32(long, long, long)}
	 * with {@link TcTssConstants#TSS_TSPATTRIB_POLICY_SECRET_LIFETIME} as flag.
	 *
	 * @param subFlag Valid subFlags are:
	 *          {@link TcTssConstants#TSS_TSPATTRIB_POLICYSECRET_LIFETIME_ALWAYS},
	 *          {@link TcTssConstants#TSS_TSPATTRIB_POLICYSECRET_LIFETIME_COUNTER} and
	 *          {@link TcTssConstants#TSS_TSPATTRIB_POLICYSECRET_LIFETIME_TIMER}.
	 * @param attrib The lifetime value to set.
	 *
	 * @throws {@link TcTssException}
	 */
	public synchronized void setAttribSecretLifetime(long subFlag, long attrib) throws TcTssException
	{
		if (subFlag == TcTssConstants.TSS_TSPATTRIB_POLICYSECRET_LIFETIME_ALWAYS) {
			secretLifetime_ = subFlag;
		} else if (subFlag == TcTssConstants.TSS_TSPATTRIB_POLICYSECRET_LIFETIME_COUNTER) {
			// attrib holds the usage counter
			secretCounter_ = attrib;

		} else if (subFlag == TcTssConstants.TSS_TSPATTRIB_POLICYSECRET_LIFETIME_TIMER) {
			// attrib holds the ttl in seconds
			timerStart_ = System.currentTimeMillis();
			timerDuration_ = attrib;

		} else {
			throw new TcTspException(TcTssErrors.TSS_E_INVALID_ATTRIB_SUBFLAG);
		}
	}


	/*************************************************************************************************
	 * This method is a shortcut for calling {@link TcIAttributes#getAttribUint32(long, long)} with
	 * {@link TcTssConstants#TSS_TSPATTRIB_POLICY_SECRET_LIFETIME} as flag.
	 *
	 * @param subFlag Valid subFlags are:
	 *          {@link TcTssConstants#TSS_TSPATTRIB_POLICYSECRET_LIFETIME_ALWAYS},
	 *          {@link TcTssConstants#TSS_TSPATTRIB_POLICYSECRET_LIFETIME_COUNTER} and
	 *          {@link TcTssConstants#TSS_TSPATTRIB_POLICYSECRET_LIFETIME_TIMER}.
	 *
	 * @return Current secret lifetime.
	 *
	 * @throws {@link TcTssException}
	 */
	public synchronized long getAttribSecretLifetime(long subFlag) throws TcTssException
	{
		long retVal = 0;

		if (subFlag == TcTssConstants.TSS_TSPATTRIB_POLICYSECRET_LIFETIME_ALWAYS) {
			if (secretLifetime_ == TcTssConstants.TSS_TSPATTRIB_POLICYSECRET_LIFETIME_ALWAYS) {
				retVal = Utils.booleanToByte(true);
			} else {
				retVal = Utils.booleanToByte(false);
			}

		} else if (subFlag == TcTssConstants.TSS_TSPATTRIB_POLICYSECRET_LIFETIME_COUNTER) {
			if (secretLifetime_ != TcTssConstants.TSS_TSPATTRIB_POLICYSECRET_LIFETIME_COUNTER) {
				throw new TcTspException(TcTssErrors.TSS_E_BAD_PARAMETER, "Counter for secret not set.");
			}
			retVal = secretCounter_;

		} else if (subFlag == TcTssConstants.TSS_TSPATTRIB_POLICYSECRET_LIFETIME_TIMER) {
			if (secretLifetime_ != TcTssConstants.TSS_TSPATTRIB_POLICYSECRET_LIFETIME_COUNTER) {
				throw new TcTspException(TcTssErrors.TSS_E_BAD_PARAMETER, "Timer for secret not set.");
			}
			if (System.currentTimeMillis() < (timerStart_ + (timerDuration_ * 1000))) {
				retVal = ((timerStart_ + (timerDuration_ * 1000)) - System.currentTimeMillis()) / 1000;
			} else {
				flushSecret();
				retVal = 0;
			}

		} else {
			throw new TcTspException(TcTssErrors.TSS_E_BAD_PARAMETER, "Unknown subFlag.");
		}

		return retVal;
	}


	/*************************************************************************************************
	 * This method is a shortcut for calling {@link TcIAttributes#setAttribUint32(long, long, long)}
	 * with {@link TcTssConstants#TSS_TSPATTRIB_SECRET_HASH_MODE} as flag.
	 *
	 * @param subFlag Valid subFlags are: {@link TcTssConstants#TSS_TSPATTRIB_SECRET_HASH_MODE_POPUP}
	 * @param attrib The hash mode to set.
	 *
	 * @throws {@link TcTssException}
	 */
	public synchronized void setAttribSecretHashMode(long subFlag, long attrib) throws TcTssException
	{
		if (subFlag == TcTssConstants.TSS_TSPATTRIB_SECRET_HASH_MODE_POPUP) {
			if (attrib == TcTssConstants.TSS_TSPATTRIB_HASH_MODE_NOT_NULL
					|| attrib == TcTssConstants.TSS_TSPATTRIB_HASH_MODE_NULL) {
				hashModePopup_ = attrib;
			} else {
				throw new TcTspException(TcTssErrors.TSS_E_INVALID_ATTRIB_DATA);
			}
		} else {
			throw new TcTspException(TcTssErrors.TSS_E_INVALID_ATTRIB_SUBFLAG);
		}
	}


	/*************************************************************************************************
	 * This method is a shortcut for calling {@link TcIAttributes#setAttribUint32(long, long, long)}
	 * with {@link TcTssConstants#TSS_TSPATTRIB_SECRET_HASH_MODE} as flag.
	 *
	 * @param subFlag Valid subFlags are: {@link TcTssConstants#TSS_TSPATTRIB_SECRET_HASH_MODE_POPUP}.
	 *
	 * @return Current hash mode.
	 *
	 * @throws {@link TcTssException}
	 */
	public synchronized long getAttribSecretHashMode(long subFlag) throws TcTssException
	{
		if (subFlag == TcTssConstants.TSS_TSPATTRIB_SECRET_HASH_MODE_POPUP) {
			return hashModePopup_;
		} else {
			throw new TcTspException(TcTssErrors.TSS_E_INVALID_ATTRIB_SUBFLAG);
		}
	}


	/*************************************************************************************************
	 * This method is a shortcut for calling
	 * {@link TcIAttributes#setAttribData(long, long, TcBlobData)} with
	 * {@link TcTssConstants#TSS_TSPATTRIB_POLICY_POPUPSTRING} as flag.
	 *
	 * @param subFlag Ignored.
	 * @param attrib Popup string.
	 *
	 * @throws {@link TcTssException}
	 */
	public synchronized void setAttribPopupString(long subFlag, TcBlobData attrib)
		throws TcTssException
	{
		CheckPrecondition.notNull(attrib, "attrib");
		popupString_ = attrib;
	}


	/*************************************************************************************************
	 * This method is a shortcut for calling {@link TcIAttributes#getAttribData(long, long)} with
	 * {@link TcTssConstants#TSS_TSPATTRIB_POLICY_POPUPSTRING} as flag.
	 *
	 * @param subFlag Ignored.
	 *
	 * @return Current popup string.
	 *
	 * @throws {@link TcTssException}
	 */
	public synchronized TcBlobData getAttribPopupString(long subFlag) throws TcTssException
	{
		return (TcBlobData) popupString_.clone();
	}

	/**
	 * Returns the state of the secret, without trying to get it from the user or by callback.
	 */
   public synchronized boolean isSecretSet()
   {
	   return secretSet_;
   }

	/**
	 * This methode is needed for returning the current policytype.
	 *
	 * @return the policytype
	 */
	public long getPolicyType()
	{
		return policyType_;
	}

	
	@Override
	protected void finalize() throws Throwable {
	
		flushSecret();
		
		super.finalize();
	}
	
}

