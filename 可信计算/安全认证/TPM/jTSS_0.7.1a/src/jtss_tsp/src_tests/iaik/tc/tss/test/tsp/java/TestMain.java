/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.test.tsp.java;


import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.tss.test.tsp.config.TestConfigParams;
import iaik.tc.tss.test.tsp.config.TestConfigReader;
import iaik.tc.tss.test.tsp.java.context.TestContext;
import iaik.tc.tss.test.tsp.java.data.TestEncData;
import iaik.tc.tss.test.tsp.java.hash.TestHash;
import iaik.tc.tss.test.tsp.java.identity.TestIdentityCreation;
import iaik.tc.tss.test.tsp.java.keys.TestKeys;
import iaik.tc.tss.test.tsp.java.ownership.TestTakeOwnership;
import iaik.tc.tss.test.tsp.java.pcrs.TestEventLog;
import iaik.tc.tss.test.tsp.java.pcrs.TestPcrs;
import iaik.tc.tss.test.tsp.java.tpm.TestEkCerts;
import iaik.tc.tss.test.tsp.java.tpm.TestQuote;
import iaik.tc.tss.test.tsp.java.tpm.TestTpm;
import iaik.tc.tss.test.tsp.java.persistentstorage.TestPersistentStorage;
import iaik.tc.tss.test.tsp.java.timestamping.TestTimeStamping;
import iaik.tc.utils.cmdline.ParamParser;
import iaik.tc.utils.logging.Log;
import iaik.tc.utils.logging.LogLevels;
import junit.framework.TestSuite;

import java.io.IOException;
import java.util.Vector;


public class TestMain extends Thread {

	private static Vector<String> tests = null;

	public void run()
	{
		if (tests != null) {
			specificTests();
		} else {
			allTests();
		}
	}


	public void allTests()
	{
		final int numRuns = 1;

		Log.setLogLevel(LogLevels.DEBUG);

		Log.debug("testsuite starting up");

		for (int i = 0; i < numRuns; i++) {
      TestSuite suite = new TestSuite();

      suite.addTestSuite(TestContext.class);
      suite.addTestSuite(TestTakeOwnership.class);
      suite.addTestSuite(TestTpm.class);
      // suite.addTestSuite(TestClearOwner.class);
      suite.addTestSuite(TestPcrs.class);
      suite.addTestSuite(TestEventLog.class);
      suite.addTestSuite(TestKeys.class);
      suite.addTestSuite(TestQuote.class);
      suite.addTestSuite(TestEkCerts.class);
      suite.addTestSuite(TestIdentityCreation.class);
      // suite.addTestSuite(TestIdentityCreationSplit.class);
      suite.addTestSuite(TestHash.class);
      suite.addTestSuite(TestEncData.class);
      // suite.addTestSuite(TestChangeAuth.class);
      // suite.addTestSuite(TestOrdinals.class);
      // suite.addTestSuite(TestMisc.class);


      suite.addTestSuite(TestPersistentStorage.class);
      suite.addTestSuite(TestTimeStamping.class);

      junit.textui.TestRunner.run(suite);
		}
	}

	public void specificTests() {

		Log.setLogLevel(LogLevels.DEBUG);

		Log.debug("testsuite starting up");

		TestSuite suite = new TestSuite();

		for (int i = 0; i < tests.size(); i++) {
			try {
				Class c = Class.forName(tests.elementAt(i));
				suite.addTestSuite(c);
			} catch (ClassNotFoundException e) {
				Log.err("No testsuite with name : " + e.getMessage());
			}
		}

		junit.textui.TestRunner.run(suite);
	}


	public void memUsage(String msg)
	{
		System.gc();
		long total = Runtime.getRuntime().totalMemory();
		long free = Runtime.getRuntime().freeMemory();
		long used = total - free;

		System.out.println(msg + "total: " + total + " free: " + free + " used: " + used);
	}

	public static void parseArguments(String argv[]) {

		ParamParser parser = new ParamParser();

		parser.addParam(TestConfigParams.getOwnerSecretParam());
		parser.addParam(TestConfigParams.getSrkSecretParam());
		parser.addParam(TestConfigParams.getEncodingParam());
		parser.addParam(TestConfigParams.getNullTermParam());
		parser.addParam(TestConfigParams.getConfigFileParam());

		if (argv.length == 0) {
			parser.printUsage();
		}

		parser.parse(argv);

		String encoding = parser.getValue(TestConfigParams.PARAM_STRING_ENCODING);

		boolean appendNullTerm = false;
		if (parser.isPresent(TestConfigParams.PARAM_APPEND_NULLTERM)) {
			appendNullTerm = true;
		}

		if (parser.isPresent(TestConfigParams.PARAM_OWNER_SECRET)) {
			TcBlobData ownerSecret = TcBlobData.newString(parser
					.getValue(TestConfigParams.PARAM_OWNER_SECRET),
					appendNullTerm, encoding);
			TestDefines.ownerSecret = ownerSecret;
		}

		if (parser.isPresent(TestConfigParams.PARAM_SRK_SECRET)) {
			TcBlobData srkSecret = TcBlobData.newString(parser
					.getValue(TestConfigParams.PARAM_SRK_SECRET),
					appendNullTerm, encoding);
			TestDefines.srkSecret = srkSecret;
		}

		if (parser.isPresent(TestConfigParams.PARAM_CONFIG_FILE)) {
			String filename = parser.getValue(TestConfigParams.PARAM_CONFIG_FILE);
			tests = null;
			try {
				tests = TestConfigReader.getTestClassesAsStrings(filename);
			} catch (IOException e) {
				Log.err(e);
			}
		}

	}


	public static void main(String argv[])
	{
		parseArguments(argv);

		int numThreads = 1;

		for (int i = 0; i < numThreads; i++) {
			Thread t = new TestMain();
			t.start();
		}

	}

}
