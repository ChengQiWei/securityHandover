/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.api.structs.tsp;


import iaik.tc.utils.misc.Utils;

import java.util.Arrays;
import java.util.StringTokenizer;

/***************************************************************************************************
 * This structure provides information about an UUID identifier that is unique within a particular
 * key hierarchy for a given platform. Several UUIDs are reserved for particular keys such as the
 * SRK. These UUIDs are used to register keys in the persistent storage of the TSS Key Manager.
 * 
 * @TSS_V1 48
 * 
 * @TSS_1_2_EA 106
 */
/*
 * Note: The reason why the TssUuid is part of the TCS is that it is required for interaction with
 * the SystemePS.
 */
public class TcTssUuid {

	/**
	 * The low field of the timestamp.
	 */
	protected long timeLow_ = 0; // UNIT32

	/**
	 * The middle field of the timestamp.
	 */
	protected int timeMid_ = 0; // UNIT16

	/**
	 * The high field of the timestamp multiplexed with the version number.
	 */
	protected int timeHigh_ = 0; // UNIT16

	/**
	 * The high field of the clock sequence multiplexed with the variant.
	 */
	protected short clockSeqHigh_ = 0; // BYTE

	/**
	 * The low field of the clock sequence.
	 */
	protected short clockSeqLow_ = 0; // BYTE

	/**
	 * The spatially unique node identifier.
	 */
	protected short[] node_ = new short[6]; // BYTE[]


	/*************************************************************************************************
	 * Default constructor.
	 */
	public TcTssUuid()
	{
	}


	/*************************************************************************************************
	 * Constructor taking all required arguments to fully initialize the UUID.
	 */
	public TcTssUuid init(final long timeLow, final int timeMid, final int timeHigh,
			final short clockSeqLow, final short clockSeqHigh, final short[] node)
	{
		if (node.length != 6) {
			throw new IllegalArgumentException("Node length must be 6.");
		}

		timeLow_ = timeLow;
		timeMid_ = timeMid;
		timeHigh_ = timeHigh;
		clockSeqHigh_ = clockSeqHigh;
		clockSeqLow_ = clockSeqLow;
		System.arraycopy(node, 0, node_, 0, 6);

		return this;
	}


	/*************************************************************************************************
	 */
	protected boolean equalsShortArray(final short[] lhs, final short[] rhs)
	{
		if (lhs.length != rhs.length) {
			return false;
		}

		for (int i = 0; i < lhs.length; i++) {
			if (lhs[i] != rhs[i]) {
				return false;
			}
		}

		return true;
	}


	/*************************************************************************************************
	 * Compares two UUIDs.
	 * 
	 * @return true if uuids are the same, false otherwise
	 */
	public boolean equals(final Object obj)
	{
		if (!(obj instanceof TcTssUuid)) {
			return false;
		}

		TcTssUuid other = (TcTssUuid) obj;

		if (getTimeLow() != other.getTimeLow() || getTimeMid() != other.getTimeMid()
				|| getTimeHigh() != other.getTimeHigh() || getClockSeqHigh() != other.getClockSeqHigh()
				|| getClockSeqLow() != other.getClockSeqLow()
				|| !equalsShortArray(getNode(), other.getNode())) {
			return false;
		} else {
			return true;
		}
	}


	/*************************************************************************************************
	 * Returns a String representation of the object.
	 */
	public String toString()
	{
		StringBuffer retVal = new StringBuffer();
		retVal.append("UUID: ");
		retVal.append(toStringNoPrefix());
		return retVal.toString();
	}


	/*************************************************************************************************
	 * Returns a String representation of the object.
	 */
	public String toStringNoPrefix()
	{
		StringBuffer retVal = new StringBuffer();
		retVal.append(prependZeros(Utils.longToHexNoPrefix(getTimeLow()), 8));
		retVal.append("-");
		retVal.append(prependZeros(Utils.longToHexNoPrefix(getTimeMid()), 4));
		retVal.append("-");
		retVal.append(prependZeros(Utils.longToHexNoPrefix(getTimeHigh()), 4));
		retVal.append("-");
		retVal.append(prependZeros(Utils.longToHexNoPrefix(getClockSeqLow()), 2));
		retVal.append(prependZeros(Utils.longToHexNoPrefix(getClockSeqHigh()), 2));
		retVal.append("-");
		short[] node = getNode();
		retVal.append(Utils.shortArrayToHexString(node));
		return retVal.toString();
	}


	/*************************************************************************************************
	 * This internal method is used to pad strings with zeros such that they meet the requested
	 * length.
	 */
	protected String prependZeros(String input, int reqLen)
	{
		if (reqLen > input.length()) {
			char[] paddingString = new char[reqLen - input.length()];
			Arrays.fill(paddingString, '0');
			return new String(paddingString) + input;
		} else {
			return input;
		}
	}


	/*************************************************************************************************
	 * Constructor taking all required arguments as a string to fully initialize the UUID. The format
	 * expected for the UUID string is the same as produced by the toStringNoPrefix() method.
	 */
	public TcTssUuid initString(String uuid)
	{
		StringTokenizer st = new StringTokenizer(uuid, "-");
		if (st.countTokens() != 5) {
			throw new IllegalArgumentException(
					"Unable to parse UUID string (unexpected number of elements)");
		}
		setTimeLow(Long.parseLong(st.nextToken(), 16));
		setTimeMid(Integer.parseInt(st.nextToken(), 16));
		setTimeHigh(Integer.parseInt(st.nextToken(), 16));

		String clockSeq = st.nextToken();
		setClockSeqLow(Short.parseShort(clockSeq.substring(0, 2), 16));
		setClockSeqHigh(Short.parseShort(clockSeq.substring(2, 4), 16));

		setNode(Utils.hexStringToShortArray(st.nextToken()));

		return this;
	}


	/*************************************************************************************************
	 * Returns a clone of the object.
	 */
	public Object clone()
	{
		TcTssUuid uuid = new TcTssUuid();

		uuid.setClockSeqHigh(getClockSeqHigh());
		uuid.setClockSeqLow(getClockSeqLow());
		short[] newNode = new short[node_.length];
		System.arraycopy(node_, 0, newNode, 0, node_.length);
		uuid.setNode(newNode); //
		uuid.setTimeHigh(getTimeHigh());
		uuid.setTimeLow(getTimeLow());
		uuid.setTimeMid(getTimeMid());

		return uuid;
	}


	/*************************************************************************************************
	 * Returns contents of the clockSeqHigh field.
	 */
	public short getClockSeqHigh()
	{
		return clockSeqHigh_;
	}


	/*************************************************************************************************
	 * Sets the clockSeqHigh field.
	 */
	public void setClockSeqHigh(final short clockSeqHigh)
	{
		clockSeqHigh_ = clockSeqHigh;
	}


	/*************************************************************************************************
	 * Returns contents of the clockSeqLow field.
	 */
	public short getClockSeqLow()
	{
		return clockSeqLow_;
	}


	/*************************************************************************************************
	 * Sets the clockSeqLow field.
	 */
	public void setClockSeqLow(final short clockSeqLow)
	{
		clockSeqLow_ = clockSeqLow;
	}


	/*************************************************************************************************
	 * Returns contents of the node field.
	 */
	public short[] getNode()
	{
		return node_;
	}


	/*************************************************************************************************
	 * Sets the node field.
	 */
	public void setNode(final short[] node)
	{
		node_ = node;
	}


	/*************************************************************************************************
	 * Returns contents of the timeHigh field.
	 */
	public int getTimeHigh()
	{
		return timeHigh_;
	}


	/*************************************************************************************************
	 * Sets the timeHigh field.
	 */
	public void setTimeHigh(final int timeHigh)
	{
		timeHigh_ = timeHigh;
	}


	/*************************************************************************************************
	 * Returns contents of the timeLow field.
	 */
	public long getTimeLow()
	{
		return timeLow_;
	}


	/*************************************************************************************************
	 * Sets the timeLow field.
	 */
	public void setTimeLow(final long timeLow)
	{
		timeLow_ = timeLow;
	}


	/*************************************************************************************************
	 * Returns contents of the timeMid field.
	 */
	public int getTimeMid()
	{
		return timeMid_;
	}


	/*************************************************************************************************
	 * Sets the timeMid field.
	 */
	public void setTimeMid(final int timeMid)
	{
		timeMid_ = timeMid;
	}
}
