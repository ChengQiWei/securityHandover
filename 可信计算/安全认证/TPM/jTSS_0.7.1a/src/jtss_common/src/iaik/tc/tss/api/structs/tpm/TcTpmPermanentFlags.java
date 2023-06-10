/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.api.structs.tpm;


import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder;
import iaik.tc.utils.misc.Utils;

public class TcTpmPermanentFlags extends TcCompositeTypeDecoder {
	protected int tag_;

	protected boolean disable_;

	protected boolean ownership_;

	protected boolean deactivated_;

	protected boolean readPubek_;

	protected boolean disableOwnerClear_;

	protected boolean allowMaintenance_;

	protected boolean physicalPresenceLifetimeLock_;

	protected boolean physicalPresenceHWEnable_;

	protected boolean physicalPresenceCMDEnable_;

	protected boolean CEKPUsed_;

	protected boolean TPMpost_;

	protected boolean TPMpostLock_;

	protected boolean FIPS_;

	protected boolean Operator_;

	protected boolean enableRevokeEK_;

	protected boolean nvLocked_;

	protected boolean readSRKPub_;

	protected boolean tpmEstablished_;

	protected boolean maintenanceDone_;


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder()
	 */
	public TcTpmPermanentFlags()
	{
		super();
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcBlobData)
	 */
	public TcTpmPermanentFlags(TcBlobData data)
	{
		super(data);
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcBlobData,
	 *      int)
	 */
	public TcTpmPermanentFlags(TcBlobData data, int offset)
	{
		super(data, offset);
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder)
	 */
	public TcTpmPermanentFlags(TcCompositeTypeDecoder composite)
	{
		super(composite);
	}


	/*************************************************************************************************
	 * This method decodes the TPM_PERMANENT_FLAGS from the byte blob.
	 */
	protected void decode()
	{
		checkBoundaryPreconditions(2 + 19);

		tag_ = decodeUINT16();
		disable_ = decodeBoolean();
		ownership_ = decodeBoolean();
		deactivated_ = decodeBoolean();
		readPubek_ = decodeBoolean();
		disableOwnerClear_ = decodeBoolean();
		allowMaintenance_ = decodeBoolean();
		physicalPresenceLifetimeLock_ = decodeBoolean();
		physicalPresenceHWEnable_ = decodeBoolean();
		physicalPresenceCMDEnable_ = decodeBoolean();
		CEKPUsed_ = decodeBoolean();
		TPMpost_ = decodeBoolean();
		TPMpostLock_ = decodeBoolean();
		FIPS_ = decodeBoolean();
		Operator_ = decodeBoolean();
		enableRevokeEK_ = decodeBoolean();
		nvLocked_ = decodeBoolean();
		readSRKPub_ = decodeBoolean();
		tpmEstablished_ = decodeBoolean();
		maintenanceDone_ = decodeBoolean();
	}


	/*************************************************************************************************
	 * This method encodes the TPM_PERMANENT_FLAGS as a byte blob.
	 */
	public TcBlobData getEncoded()
	{
		TcBlobData retVal = TcBlobData.newUINT16( tag_);
		retVal.append(TcBlobData.newBYTE(Utils.booleanToByte(disable_)));
		retVal.append(TcBlobData.newBYTE(Utils.booleanToByte(ownership_)));
		retVal.append(TcBlobData.newBYTE(Utils.booleanToByte(deactivated_)));
		retVal.append(TcBlobData.newBYTE(Utils.booleanToByte(readPubek_)));
		retVal.append(TcBlobData.newBYTE(Utils.booleanToByte(disableOwnerClear_)));
		retVal
				.append(TcBlobData.newBYTE(Utils.booleanToByte(allowMaintenance_)));
		retVal.append(TcBlobData.newBYTE(
				Utils.booleanToByte(physicalPresenceLifetimeLock_)));
		retVal.append(TcBlobData.newBYTE(
				Utils.booleanToByte(physicalPresenceHWEnable_)));
		retVal.append(TcBlobData.newBYTE(
				Utils.booleanToByte(physicalPresenceCMDEnable_)));
		retVal.append(TcBlobData.newBYTE(Utils.booleanToByte(CEKPUsed_)));
		retVal.append(TcBlobData.newBYTE(Utils.booleanToByte(TPMpost_)));
		retVal.append(TcBlobData.newBYTE(Utils.booleanToByte(TPMpostLock_)));
		retVal.append(TcBlobData.newBYTE(Utils.booleanToByte(FIPS_)));
		retVal.append(TcBlobData.newBYTE(Utils.booleanToByte(Operator_)));
		retVal.append(TcBlobData.newBYTE(Utils.booleanToByte(enableRevokeEK_)));
		retVal.append(TcBlobData.newBYTE(Utils.booleanToByte(nvLocked_)));
		retVal.append(TcBlobData.newBYTE(Utils.booleanToByte(readSRKPub_)));
		retVal.append(TcBlobData.newBYTE(Utils.booleanToByte(tpmEstablished_)));
		retVal.append(TcBlobData.newBYTE(Utils.booleanToByte(maintenanceDone_)));

		return retVal;
	}


	/*************************************************************************************************
	 * This method returns a String representation of the object.
	 */
	public String toString()
	{
		StringBuffer retVal = new StringBuffer();

		retVal.append("tag: ");
		retVal.append(tag_);
		retVal.append(Utils.getNL());
		retVal.append("disable: ");
		retVal.append(disable_);
		retVal.append(Utils.getNL());
		retVal.append("ownership: ");
		retVal.append(ownership_);
		retVal.append(Utils.getNL());
		retVal.append("deactivated: ");
		retVal.append(deactivated_);
		retVal.append(Utils.getNL());
		retVal.append("readPubek: ");
		retVal.append(readPubek_);
		retVal.append(Utils.getNL());
		retVal.append("disableOwnerClear: ");
		retVal.append(disableOwnerClear_);
		retVal.append(Utils.getNL());
		retVal.append("allowMaintenance: ");
		retVal.append(allowMaintenance_);
		retVal.append(Utils.getNL());
		retVal.append("physicalPresenceLifetimeLock: ");
		retVal.append(physicalPresenceLifetimeLock_);
		retVal.append(Utils.getNL());
		retVal.append("physicalPresenceHWEnable: ");
		retVal.append(physicalPresenceHWEnable_);
		retVal.append(Utils.getNL());
		retVal.append("physicalPresenceCMDEnable: ");
		retVal.append(physicalPresenceCMDEnable_);
		retVal.append(Utils.getNL());
		retVal.append("CEKPUsed: ");
		retVal.append(CEKPUsed_);
		retVal.append(Utils.getNL());
		retVal.append("TPMpost: ");
		retVal.append(TPMpost_);
		retVal.append(Utils.getNL());
		retVal.append("TPMpostLock: ");
		retVal.append(TPMpostLock_);
		retVal.append(Utils.getNL());
		retVal.append("FIPS: ");
		retVal.append(FIPS_);
		retVal.append(Utils.getNL());
		retVal.append("Operator: ");
		retVal.append(Operator_);
		retVal.append(Utils.getNL());
		retVal.append("enableRevokeEK: ");
		retVal.append(enableRevokeEK_);
		retVal.append(Utils.getNL());
		retVal.append("nvLocked: ");
		retVal.append(nvLocked_);
		retVal.append(Utils.getNL());
		retVal.append("readSRKPub: ");
		retVal.append(readSRKPub_);
		retVal.append(Utils.getNL());
		retVal.append("tpmEstablished: ");
		retVal.append(tpmEstablished_);
		retVal.append(Utils.getNL());
		retVal.append("maintenanceDone: ");
		retVal.append(maintenanceDone_);
		retVal.append(Utils.getNL());

		return retVal.toString();
	}


	/*************************************************************************************************
	 * Returns contents of the tag field.
	 */
	public int getTag()
	{
		return tag_;
	}


	/*************************************************************************************************
	 * Sets the tag field.
	 */
	public void setTag(int tag)
	{
		tag_ = tag;
	}


	/*************************************************************************************************
	 * Returns contents of the disable field.
	 */
	public boolean getDisable()
	{
		return disable_;
	}


	/*************************************************************************************************
	 * Sets the disable field.
	 */
	public void setDisable(boolean disable)
	{
		disable_ = disable;
	}


	/*************************************************************************************************
	 * Returns contents of the ownership field.
	 */
	public boolean getOwnership()
	{
		return ownership_;
	}


	/*************************************************************************************************
	 * Sets the ownership field.
	 */
	public void setOwnership(boolean ownership)
	{
		ownership_ = ownership;
	}


	/*************************************************************************************************
	 * Returns contents of the deactivated field.
	 */
	public boolean getDeactivated()
	{
		return deactivated_;
	}


	/*************************************************************************************************
	 * Sets the deactivated field.
	 */
	public void setDeactivated(boolean deactivated)
	{
		deactivated_ = deactivated;
	}


	/*************************************************************************************************
	 * Returns contents of the readPubek field.
	 */
	public boolean getReadPubek()
	{
		return readPubek_;
	}


	/*************************************************************************************************
	 * Sets the readPubek field.
	 */
	public void setReadPubek(boolean readPubek)
	{
		readPubek_ = readPubek;
	}


	/*************************************************************************************************
	 * Returns contents of the disableOwnerClear field.
	 */
	public boolean getDisableOwnerClear()
	{
		return disableOwnerClear_;
	}


	/*************************************************************************************************
	 * Sets the disableOwnerClear field.
	 */
	public void setDisableOwnerClear(boolean disableOwnerClear)
	{
		disableOwnerClear_ = disableOwnerClear;
	}


	/*************************************************************************************************
	 * Returns contents of the allowMaintenance field.
	 */
	public boolean getAllowMaintenance()
	{
		return allowMaintenance_;
	}


	/*************************************************************************************************
	 * Sets the allowMaintenance field.
	 */
	public void setAllowMaintenance(boolean allowMaintenance)
	{
		allowMaintenance_ = allowMaintenance;
	}


	/*************************************************************************************************
	 * Returns contents of the physicalPresenceLifetimeLock field.
	 */
	public boolean getPhysicalPresenceLifetimeLock()
	{
		return physicalPresenceLifetimeLock_;
	}


	/*************************************************************************************************
	 * Sets the physicalPresenceLifetimeLock field.
	 */
	public void setPhysicalPresenceLifetimeLock(boolean physicalPresenceLifetimeLock)
	{
		physicalPresenceLifetimeLock_ = physicalPresenceLifetimeLock;
	}


	/*************************************************************************************************
	 * Returns contents of the physicalPresenceHWEnable field.
	 */
	public boolean getPhysicalPresenceHWEnable()
	{
		return physicalPresenceHWEnable_;
	}


	/*************************************************************************************************
	 * Sets the physicalPresenceHWEnable field.
	 */
	public void setPhysicalPresenceHWEnable(boolean physicalPresenceHWEnable)
	{
		physicalPresenceHWEnable_ = physicalPresenceHWEnable;
	}


	/*************************************************************************************************
	 * Returns contents of the physicalPresenceCMDEnable field.
	 */
	public boolean getPhysicalPresenceCMDEnable()
	{
		return physicalPresenceCMDEnable_;
	}


	/*************************************************************************************************
	 * Sets the physicalPresenceCMDEnable field.
	 */
	public void setPhysicalPresenceCMDEnable(boolean physicalPresenceCMDEnable)
	{
		physicalPresenceCMDEnable_ = physicalPresenceCMDEnable;
	}


	/*************************************************************************************************
	 * Returns contents of the CEKPUsed field.
	 */
	public boolean getCEKPUsed()
	{
		return CEKPUsed_;
	}


	/*************************************************************************************************
	 * Sets the CEKPUsed field.
	 */
	public void setCEKPUsed(boolean CEKPUsed)
	{
		CEKPUsed_ = CEKPUsed;
	}


	/*************************************************************************************************
	 * Returns contents of the TPMpost field.
	 */
	public boolean getTPMpost()
	{
		return TPMpost_;
	}


	/*************************************************************************************************
	 * Sets the TPMpost field.
	 */
	public void setTPMpost(boolean TPMpost)
	{
		TPMpost_ = TPMpost;
	}


	/*************************************************************************************************
	 * Returns contents of the TPMpostLock field.
	 */
	public boolean getTPMpostLock()
	{
		return TPMpostLock_;
	}


	/*************************************************************************************************
	 * Sets the TPMpostLock field.
	 */
	public void setTPMpostLock(boolean TPMpostLock)
	{
		TPMpostLock_ = TPMpostLock;
	}


	/*************************************************************************************************
	 * Returns contents of the FIPS field.
	 */
	public boolean getFIPS()
	{
		return FIPS_;
	}


	/*************************************************************************************************
	 * Sets the FIPS field.
	 */
	public void setFIPS(boolean FIPS)
	{
		FIPS_ = FIPS;
	}


	/*************************************************************************************************
	 * Returns contents of the Operator field.
	 */
	public boolean getOperator()
	{
		return Operator_;
	}


	/*************************************************************************************************
	 * Sets the Operator field.
	 */
	public void setOperator(boolean Operator)
	{
		Operator_ = Operator;
	}


	/*************************************************************************************************
	 * Returns contents of the enableRevokeEK field.
	 */
	public boolean getEnableRevokeEK()
	{
		return enableRevokeEK_;
	}


	/*************************************************************************************************
	 * Sets the enableRevokeEK field.
	 */
	public void setEnableRevokeEK(boolean enableRevokeEK)
	{
		enableRevokeEK_ = enableRevokeEK;
	}


	/*************************************************************************************************
	 * Returns contents of the nvLocked field.
	 */
	public boolean getNvLocked()
	{
		return nvLocked_;
	}


	/*************************************************************************************************
	 * Sets the nvLocked field.
	 */
	public void setNvLocked(boolean nvLocked)
	{
		nvLocked_ = nvLocked;
	}


	/*************************************************************************************************
	 * Returns contents of the readSRKPub field.
	 */
	public boolean getReadSRKPub()
	{
		return readSRKPub_;
	}


	/*************************************************************************************************
	 * Sets the readSRKPub field.
	 */
	public void setReadSRKPub(boolean readSRKPub)
	{
		readSRKPub_ = readSRKPub;
	}


	/*************************************************************************************************
	 * Returns contents of the tpmEstablished field.
	 */
	public boolean getTpmEstablished()
	{
		return tpmEstablished_;
	}


	/*************************************************************************************************
	 * Sets the tpmEstablished field.
	 */
	public void setTpmEstablished(boolean tpmEstablished)
	{
		tpmEstablished_ = tpmEstablished;
	}


	/*************************************************************************************************
	 * Returns contents of the maintenanceDone field.
	 */
	public boolean getMaintenanceDone()
	{
		return maintenanceDone_;
	}


	/*************************************************************************************************
	 * Sets the maintenanceDone field.
	 */
	public void setMaintenanceDone(boolean maintenanceDone)
	{
		maintenanceDone_ = maintenanceDone;
	}

}
