/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.api.structs.tsp;


import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.utils.misc.Utils;

/***************************************************************************************************
 * This class provides information about an individual PCR extend event.
 *
 * @TSS_V1 46
 *
 * @TSS_1_2_EA 103
 */
public class TcTssPcrEvent {

	/**
	 * Version data set by the TSP.
	 */
	protected TcTssVersion versionInfo_ = null; // TSS_VERSION

	/**
	 * Index of the PCR this event belongs to set by the TSP.
	 */
	protected long pcrIndex_ = 0; // UINT32

	/**
	 * Flag indicating the type of the event.
	 */
	protected long eventType_ = 0; // TSS_EVENTTYPE (UINT32)

	/**
	 * The value extended into the TPM.
	 */
	protected TcBlobData pcrValue_ = null; // BYTE*

	/**
	 * Event information data.
	 */
	protected TcBlobData event_ = null; // BYTE*



	/*************************************************************************************************
	 * Default constructor.
	 */
	public TcTssPcrEvent()
	{
	}


	/*************************************************************************************************
	 * Initialization method taking and setting all parameters at once.
	 */
	public TcTssPcrEvent init(TcTssVersion versionInfo, long pcrIndex, long eventType,
			TcBlobData pcrValue, TcBlobData event)
	{
		versionInfo_ = versionInfo;
		pcrIndex_ = pcrIndex;
		eventType_ = eventType;
		pcrValue_ = pcrValue;
		event_ = event;

		return this;
	}


	/*************************************************************************************************
	 * Returns length of the event.
	 */
	public long getEventLength()
	{
		if (event_ == null) {
			return 0;
		} else {
			return event_.getLengthAsLong();
		}
	}


	/*************************************************************************************************
	 * Returns contents of the eventType field.
	 */
	public long getEventType()
	{
		return eventType_;
	}


	/*************************************************************************************************
	 * Sets the eventType field.
	 */
	public void setEventType(long eventType)
	{
		eventType_ = eventType;
	}


	/*************************************************************************************************
	 * Returns contents of the pcrIndex field.
	 */
	public long getPcrIndex()
	{
		return pcrIndex_;
	}


	/*************************************************************************************************
	 * Sets the pcrIndex field.
	 */
	public void setPcrIndex(long pcrIndex)
	{
		this.pcrIndex_ = pcrIndex;
	}


	/*************************************************************************************************
	 * Returns the length of the PCR value.
	 */
	public long getPcrValueLength()
	{
		if (pcrValue_ == null) {
			return 0;
		} else {
			return pcrValue_.getLengthAsLong();
		}
	}


	/*************************************************************************************************
	 * Returns contents of the event field.
	 */
	public TcBlobData getEvent()
	{
		return event_;
	}


	/*************************************************************************************************
	 * Sets the event field.
	 */
	public void setEvent(TcBlobData event)
	{
		event_ = event;
	}


	/*************************************************************************************************
	 * Returns contents of the pcrValue field.
	 */
	public TcBlobData getPcrValue()
	{
		return pcrValue_;
	}


	/*************************************************************************************************
	 * Sets the pcrValue field.
	 */
	public void setPcrValue(TcBlobData pcrValue)
	{
		pcrValue_ = pcrValue;
	}


	/*************************************************************************************************
	 * Returns contents of the versionInfo field.
	 */
	public TcTssVersion getVersionInfo()
	{
		return versionInfo_;
	}


	/*************************************************************************************************
	 * Sets the versionInfo field.
	 */
	public void setVersionInfo(TcTssVersion versionInfo)
	{
		versionInfo_ = versionInfo;
	}


	/*************************************************************************************************
	 * Returns a String representation of the object.
	 */
	public String toString()
	{
		StringBuffer retVal = new StringBuffer();
		retVal.append("pcr index:             ");
		retVal.append(getPcrIndex());
		retVal.append(Utils.getNL());
		retVal.append("event type:            ");
		retVal.append(getEventType());
		retVal.append(Utils.getNL());
		retVal.append("event length:          ");
		retVal.append(getEventLength());
		retVal.append(Utils.getNL());
		if (getEventLength() > 0) {
			retVal.append("Event:                 ");
			retVal.append(getEvent().toString());
			retVal.append(Utils.getNL());
		}
		retVal.append("extended data length:  ");
		retVal.append(getPcrValueLength());
		retVal.append(Utils.getNL());
		if (getPcrValueLength() > 0) {
			retVal.append("extended data:        ");
			retVal.append(getPcrValue().toHexStringNoWrap());
			retVal.append(Utils.getNL());
		}
		if (getVersionInfo() != null) {
			retVal.append(getVersionInfo().toString());
		}
		return retVal.toString();
	}
}
