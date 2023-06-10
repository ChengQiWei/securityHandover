/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.api.constants.pcclient;


public class TcPcclientConstants {

	// Making constructor unavailable
	protected TcPcclientConstants()
	{
	}

	/**
	 * Defines a stored certificate
	 */
	public static final int TCG_TAG_PCCLIENT_STORED_CERT = 0x1001;

	/**
	 * Defines a full certificate
	 */
	public static final int TCG_TAG_PCCLIENT_FULL_CERT = 0x1002;

	/**
	 * Defines a partial small certificate.
	 */
	public static final int TCG_TAG_PCCLIENT_PART_SMALL_CERT = 0x1003;

	/**
	 * The cert field contains a full certificate. (Can determine type of certificate by looking at
	 * its contents).
	 */
	public static final int TCG_FULL_CERT = 0x0;

	/**
	 * The storage element includes only the signature element of the certificate; the remaining
	 * portions of the certificate must be built from information available from the TPM, Host
	 * Platform, and/or local or remote storage.
	 */
	public static final int TCG_PARTIAL_SMALL_CERT = 0x1;
}
