/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Christian Pointner
 */

package iaik.tc.tss.test.tcs.java;

import iaik.tc.tss.test.tcs.java.counter.TestCounter;
import iaik.tc.tss.test.tcs.java.eventmgr.TestEventMgr;
import junit.framework.TestSuite;
import iaik.tc.utils.logging.Log;
import iaik.tc.utils.logging.LogLevels;

public class TestMain extends Thread {
	public void run()
	{
		allTests();
	}


	public void allTests()
	{
		final int numRuns = 1;

		Log.setLogLevel(LogLevels.DEBUG);

		Log.debug("testsuite starting up");

		for (int i = 0; i < numRuns; i++) {
			TestSuite suite = new TestSuite();
      
			suite.addTestSuite(TestCounter.class);
			suite.addTestSuite(TestEventMgr.class);

			junit.textui.TestRunner.run(suite);
		}
	}


	public void memUsage(String msg)
	{
		System.gc();
		long total = Runtime.getRuntime().totalMemory();
		long free = Runtime.getRuntime().freeMemory();
		long used = total - free;

		System.out.println(msg + "total: " + total + " free: " + free + " used: " + used);
	}


	public static void main(String argv[])
	{
		int numThreads = 1;

		for (int i = 0; i < numThreads; i++) {
			Thread t = new TestMain();
			t.start();
		}

	}

}
