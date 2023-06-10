/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.test.tcs.java;

import iaik.tc.tss.api.structs.common.TcBlobData;

public class TestDefines {

	// UNICODE (UTF-16LE) String without NULL termination
	public static final TcBlobData OWNER_SECRET = TcBlobData.newString("opentc");

	// UNICODE (UTF-16LE) String without NULL termination
	public static final TcBlobData COUNTER_SECRET = TcBlobData.newString("counterSecret");
	
}
