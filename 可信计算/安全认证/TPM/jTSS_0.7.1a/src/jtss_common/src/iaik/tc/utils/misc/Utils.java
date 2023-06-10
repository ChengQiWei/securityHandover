/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 */

package iaik.tc.utils.misc;

/**
 * This class contains a collection of helper methods.
 */
public class Utils {
	
	// hidden constructor
	private Utils() {
	}
	
	public final static String lineSeperator = System.getProperty("line.separator");

	/**
	 * This method converts a byte representation of a boolean value into the Java boolean type
	 */
	public static boolean byteToBoolean(final byte value)
	{
		if (value != 0) {
			return true;
		} else {
			return false;
		}
	}


	/**
	 * This method converts a short representation of a boolean value into the Java boolean type.
	 */
	public static boolean shortToBoolean(final short value)
	{
		if (value != 0) {
			return true;
		} else {
			return false;
		}
	}


	/**
	 * This method converts a short representation of a boolean value into the Java boolean type.
	 */
	public static boolean longToBoolean(final long value)
	{
		if (value != 0) {
			return true;
		} else {
			return false;
		}
	}

	
	
	/**
	 * This method converts a Java boolean into a byte representation.
	 */
	public static byte booleanToByte(final boolean value)
	{
		if (value == true) {
			return 1;
		} else {
			return 0;
		}
	}


	/**
	 * This method returns a String representation (i.e. "true" or "false") of the given boolean
	 * value.
	 */
	public static String booleanToString(final boolean value)
	{
		if (value == true) {
			return "true";
		} else {
			return "false";
		}
	}


	/**
	 * This method converts a long into an Hex-String of the form 0x1234.
	 */
	public static String longToHex(final long value)
	{
		return "0x" + longToHexNoPrefix(value);
	}


	/**
	 * This method converts a long into a Hex-String without leading 0x.
	 */
	public static String longToHexNoPrefix(final long value)
	{
		String retVal = Long.toHexString(value);
		if (retVal.length() % 2 != 0) {
			retVal = "0" + retVal;
		}
		return retVal;
	}


	/**
	 * This method returns the platform specific character sequence for "new line".
	 */
	public static String getNL()
	{
		return lineSeperator;
	}

	
	/**
	 * This method returns the platform specific character sequence for "new line".
	 */
	public static String getFSep()
	{
		return System.getProperty("file.separator");
	}

	/**
	 * This method converts an unsigned byte value into a short value. Note: The provided byte value
	 * is interpreted as unsigned although the byte type of java is signed.
	 */
	public static short unsignedByteToShort(final byte b)
	{
		return (short) (b & 0xff);
	}


	/**
	 * This method converts a byte array into a short array.
	 */
	public static short[] byteArrayToShortArray(final byte[] input)
	{
		short[] retVal = new short[input.length];
		for (int i = 0; i < input.length; i++) {
			retVal[i] = unsignedByteToShort(input[i]);
		}
		return retVal;
	}


	/**
	 * This method returns a Hex-String of the provided byte array.
	 */
	public static String byteArrayToHexString(final byte[] data)
	{
		return byteArrayToHexString(data, " ", 16);
	}


	/**
	 * This method returns a Hex-String of the provided byte array.
	 */
	public static String byteArrayToHexString(final byte[] data, String delimiter, int octetsPerLine)
	{
		StringBuffer retVal = new StringBuffer();
		for (int i = 0; i < data.length; i++) {
			if (octetsPerLine > 0 && i % octetsPerLine == 0 && i != 0) {
				retVal.append(getNL());
			}
			retVal.append(delimiter + longToHexNoPrefix(unsignedByteToShort(data[i])));
		}
		return retVal.toString();
	}

	
	/**
	 * This method converts the given hex string into a byte array. It is the
	 * opposite the the byteArrayToHexString method.
	 */
	public static byte[] hexStringToByteArray(String data)
	{
		if ((data.length() % 2) != 0) {
			throw new IllegalArgumentException("Length of provided string is not a multiple of 2.");
		}
		byte[] retVal = new byte[data.length() / 2];

		for (int i = 0; i < retVal.length; i++) {
			retVal[i] = (byte)Short.parseShort(data.substring(2 * i, 2 * i + 2), 16);
		}
		
		return retVal;
	}

	
	/**
	 * This method returns a Hex-String of the provided short array.
	 */
	public static String shortArrayToHexString(final short[] data)
	{
		StringBuffer retVal = new StringBuffer();
		for (int i = 0; i < data.length; i++) {
			retVal.append(longToHexNoPrefix(data[i]));
		}
		return retVal.toString();
	}


	/**
	 * This method converts the given hex string into a short array. It is the
	 * opposite the the shortArrayToHexString method.
	 */
	public static short[] hexStringToShortArray(String data)
	{
		if ((data.length() % 2) != 0) {
			throw new IllegalArgumentException("Length of provided string is not a multiple of 2.");
		}
		short[] retVal = new short[data.length() / 2];

		for (int i = 0; i < retVal.length; i++) {
			retVal[i] = (short)Short.parseShort(data.substring(2 * i, 2 * i + 2), 16);
		}
		
		return retVal;
	}

	
	/**
	 * This method returns a byte array of the provided short array. The values contained in the short
	 * array must not be outside the 0 to 255 range.
	 */
	public static byte[] shortArrayToByteArray(final short[] input)
	{
		byte[] retVal = new byte[input.length];
		for (int i = 0; i < input.length; i++) {
			if (input[i] < 0 || input[i] > 255) {
				throw new IllegalArgumentException(
						"Array contains illegal characters (outside range: 0 to 255)");
			}

			retVal[i] = (byte) input[i];
		}
		return retVal;
	}
}
