/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 */

package iaik.tc.utils.misc;


public class OsDetection {

	/** OS id string for LINUX. */
	public static final String OS_LINUX = "Linux";

	/** OS id string for Windows Vista and higher. */
	public static final String OS_WINDOWS_VISTA = "Windows Vista";
	public static final String OS_WINDOWS_SEVEN = "Windows 7";
	public static final String OS_WINDOWS_EIGHT = "Windows 8";
	public static final String OS_WINDOWS_EIGHT_ONE = "Windows 8.1";
	public static final String OS_WINDOWS_MMVIII = "Windows Server 2008";
	public static final String OS_WINDOWS_MMVIIIR2 = "Windows Server 2008 R2";
	public static final String OS_WINDOWS_UNKNOWN = "Windows NT (unknown)"; //if the JRE is older than the windows or beta windows with undefined product name
	

	

	/**
	 * This method returns true if the id string of the current operating system matches the given
	 * one.
	 */
	public static boolean operatingSystemIs(String osId)
	{
		return System.getProperty("os.name").toLowerCase().equals(osId.toLowerCase());
	}

	/**
	 * This method returns true if the id string of the current operating system
	 * matches one of the known Windows id strings.
	 */
	public static boolean operatingSystemIsWindows() {
		String os = System.getProperty("os.name");
		return os.equalsIgnoreCase(OS_WINDOWS_VISTA)
				|| os.equalsIgnoreCase(OS_WINDOWS_SEVEN)
				|| os.equalsIgnoreCase(OS_WINDOWS_EIGHT)
				|| os.equalsIgnoreCase(OS_WINDOWS_EIGHT_ONE)
				|| os.equalsIgnoreCase(OS_WINDOWS_MMVIII)
				|| os.equalsIgnoreCase(OS_WINDOWS_MMVIIIR2)
				|| os.equalsIgnoreCase(OS_WINDOWS_UNKNOWN);
	}
}
