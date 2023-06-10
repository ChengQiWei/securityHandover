/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.test.tsp.java;


import iaik.tc.tss.api.constants.tsp.TcTssConstants;
import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.tss.api.tspi.TcIPolicy;

public class TestDefines {
	
	public static final TcBlobData KEY_USG_SECRET = TcBlobData.newString("keySecret");

	public static final TcBlobData KEY_MIG_SECRET = TcBlobData.newString("keySecret");

	
	public static final long OWNER_SECRET_MODE = TcTssConstants.TSS_SECRET_MODE_PLAIN;

	public static final long SRK_SECRET_MODE = TcTssConstants.TSS_SECRET_MODE_SHA1;
//	public static final long SRK_SECRET_MODE = TcTssConstants.TSS_SECRET_MODE_PLAIN;
	
	public static final long KEY_SECRET_MODE = TcTssConstants.TSS_SECRET_MODE_PLAIN;
	
	
	// UNICODE (UTF-16LE) String without NULL termination
	public static TcBlobData ownerSecret = TcBlobData.newString("opentc");
	//public static final TcBlobData OWNER_SECRET = TcBlobData.newString("hugoowner");

	// The TSS_WELL_KNOWN_SECRET goes in "as is".
	public static TcBlobData srkSecret = TcBlobData.newByteArray(TcTssConstants.TSS_WELL_KNOWN_SECRET);
	//public static final TcBlobData SRK_SECRET=TcBlobData.newString("hugosrk"); //Remember to change the SRK_SECRET_MODE as well


	public static TcIPolicy keyUsgPolicy = null;

	public static TcIPolicy keyMigPolicy = null;

	public static TcIPolicy tpmPolicy = null;
	
	public static TcIPolicy srkPolicy = null;

}
