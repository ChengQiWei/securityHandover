/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.api.structs.common;

import iaik.tc.utils.logging.Log;

import java.nio.ByteOrder;

/**
 * This class provides big endian/little endian byte order labels.  
 */
public class TcByteOrder {

	/** Constant for big endian byte order (MSB first). */
	public static final byte BYTE_ORDER_BE = 0;
	
	/** Constant for little endian byte order (LSB first). */
	public static final byte BYTE_ORDER_LE = 1;
	
	/** Byte order used by the TPM 
	 * @TPM_V1 16
	 */
	public static final byte TPM_BYTE_ORDER = BYTE_ORDER_BE;
	
	/** Java Virtual Machine byte order */
	public static final byte JVM_BYTE_ORDER = BYTE_ORDER_BE;

	/** Byte order of the system's CPU. */
	public static final byte SYSTEM_BYTE_ORDER = getCpuByteOrder();

	/**
	 * Hidden default constructor.
	 */
	private TcByteOrder() {
	}
	
	/**
	 * This method determines the byte order of the system's CPU. 
	 */
	protected static byte getCpuByteOrder()
	{
		// first try to determine byteOrder using Java 1.4 and above
		
		try {
			if (ByteOrder.nativeOrder() == ByteOrder.LITTLE_ENDIAN) {
				return BYTE_ORDER_LE;
			} else {
				return BYTE_ORDER_BE;
			}
		} catch (NoClassDefFoundError e) {
			System.out.println("Note: Java 1.4 features not available. Using alternative mechanism to determine platform byte order.");
		}
		
		// try to determine the platform byte order on SUN VMs
		
		String endianness = System.getProperty("sun.cpu.endian");
		if (endianness != null) {
			if (endianness.equalsIgnoreCase("little")) {
				return BYTE_ORDER_LE;
			} else {
				return BYTE_ORDER_BE;
			}
		}

		// try to determine the platform byte order on VMs using GNU classpath

		endianness = System.getProperty("gnu.cpu.endian");
		if (endianness != null) {
			if (endianness.equalsIgnoreCase("little")) {
				return BYTE_ORDER_LE;
			} else {
				return BYTE_ORDER_BE;
			}
		}

		// try to determine the platform byte order based on the OS architecture
		
		String osArch = System.getProperty("os.arch");
		if (osArch != null) {
			if (osArch.equalsIgnoreCase("i386")) {
				return BYTE_ORDER_LE;
			}
		}

		Log.warn("Unable to determine platform byte order. Assuming little endian.");
		return BYTE_ORDER_LE;
		
		// TODO (later versions): Either totally remove the requirement to determine the
		// platform byte order or find a way that always works with Java Versions < 1.4.
	}
}
