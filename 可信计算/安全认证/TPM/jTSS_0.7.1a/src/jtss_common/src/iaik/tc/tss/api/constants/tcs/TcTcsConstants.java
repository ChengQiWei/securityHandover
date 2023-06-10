/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.api.constants.tcs;


public class TcTcsConstants {

	private TcTcsConstants()
	{
	}

	/** Handle specifying NULL object. */
	public static final long NULL_HOBJECT = 0x0;

	public static final long TCS_TCSATTRIB_TRANSPORT_DEFAULT = 0x00000000;

	public static final long TCS_TCSATTRIB_TRANSPORT_EXCLUSIVE = 0x00000001;

	// Values for the ulCredentialType parameter to Tcsi_GetCredential
	public static final long TSS_TCS_CREDENTIAL_EKCERT = 0x00000001;

	public static final long TSS_TCS_CREDENTIAL_TPM_CC = 0x00000002;

	public static final long TSS_TCS_CREDENTIAL_PLATFORMCERT = 0x00000003;

	// Values for the ulCredentialAccessMode parameter to Tcsi_GetCredential
	// TSS_TCS_CERT_ACCESS_AUTO triggers the default behavior.
	// Values with TSS_TCS_CERT_VENDOR_SPECIFIC_BIT set trigger
	// vendor specific behavior.
	public static final long TSS_TCS_CERT_ACCESS_AUTO = 0x00000001;

	public static final long TSS_TCS_CERT_VENDOR_SPECIFIC_BIT = 0x80000000;

	// TSS Core Service Capabilities

	/** Queries whether an algorithm is supported. (subCap: TcTssConstants.TSS_ALG_XXX) */
	public static final long TSS_TCSCAP_ALG = 0x00000001;

	/** Queries the current TCS version. (subCap: none) */
	public static final long TSS_TCSCAP_VERSION = 0x00000002;

	/**
	 * Queries the support of key and authorization caching. <br>
	 * Valid subCaps are:
	 * <ul>
	 * <li>{@link TcTcsConstants#TSS_TCSCAP_PROP_KEYCACHE}</li>
	 * <li>{@link TcTcsConstants#TSS_TCSCAP_PROP_AUTHCACHE}</li>
	 * </ul>
	 */
	public static final long TSS_TCSCAP_CACHING = 0x00000003;

	/** Queries the support of a persistent storage. (subCap: none) */
	public static final long TSS_TCSCAP_PERSSTORAGE = 0x00000004;

	/**
	 * Queries the manufacturer information. <br>
	 * Valid subCaps are:
	 * <ul>
	 * <li>{@link TcTcsConstants#TSS_TCSCAP_PROP_MANUFACTURER_STR}</li>
	 * <li>{@link TcTcsConstants#TSS_TCSCAP_PROP_MANUFACTURER_ID}</li>
	 * </ul>
	 */
	public static final long TSS_TCSCAP_MANUFACTURER = 0x00000005;

	// Sub-Capability Flags TSS-CoreService-Capabilities

	/**
	 * TRUE indicates that the TCS supports key caching, FALSE indicates that the TCS does not support
	 * key caching.
	 */
	public static final long TSS_TCSCAP_PROP_KEYCACHE = 0x00000100;

	/**
	 * TRUE indicates that the TCS supports authorization session caching, FALSE indicates that the
	 * TCS does not support authorization session caching.
	 */
	public static final long TSS_TCSCAP_PROP_AUTHCACHE = 0x00000101;

	/**
	 * Returns an Unicode string of the TCS manufacturer. The contents of this string is determined by
	 * the manufacturer and is subject to change in subsequent releases of the TCS.
	 */
	public static final long TSS_TCSCAP_PROP_MANUFACTURER_STR = 0x00000102;

	/** Returns the manufacturer or implementer of the TCS. */
	public static final long TSS_TCSCAP_PROP_MANUFACTURER_ID = 0x00000103;

	// TSS Service Provider Capabilities

	/** Queries whether an algorithm is supported. */
	public static final long TSS_TSPCAP_ALG = 0x00000010;

	/** Queries whether an algorithm is supported. (subCap: none) */
	public static final long TSS_TSPCAP_VERSION = 0x00000011;

	/** Queries the support of a persistent storage. (subCap: none) */
	public static final long TSS_TSPCAP_PERSSTORAGE = 0x00000012;

}
