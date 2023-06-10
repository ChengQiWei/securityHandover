/*
 * Copyright (C) 2008 IAIK, Graz University of Technology
 * authors: Thomas Holzmann, Ronald Toegl
 */

package iaik.tc.tss.test.tcs.java.eventmgr;

import iaik.tc.tss.test.tcs.java.TestCommon;
import iaik.tc.tss.impl.java.tcs.TcTcsProperties;
import iaik.tc.tss.impl.java.tcs.eventmgr.TcITcsEventMgr;
import iaik.tc.tss.impl.java.tcs.eventmgr.TcTcsEventMgrFlatFile;
import iaik.tc.tss.api.structs.tsp.TcTssPcrEvent;
import iaik.tc.tss.api.structs.common.TcBlobData;

import java.io.File;
import java.io.FileWriter;
import java.io.FileReader;
import java.io.BufferedReader;

public class TestEventMgr extends TestCommon {
	/***************************************************************************
	 * This test writes a log file and then checks if the whole log file is like
	 * it should be
	 * 
	 * NOTE: This only works with TcTcsEventMgrFlatFile
	 * NOTE: Corrupts exisiting log file, must not be tested on production systems.
	 */
	public void NOtestWriteLogFile() {
		File sml = null;
		File smlCompare = null;
		try {
			// create the file to compare with
			smlCompare = new File("test_compare.sml").getCanonicalFile();
			FileWriter writer = new FileWriter(smlCompare, true);

			String version = getTPMVersion().toString().substring(9);

			String description = "Everything works fine in PCR ";
			for (int i = 0; i < 5; i++) {
				if (i == 0) {
					writer.write("tpm_version=" + version);
					writer.append(System.getProperty("line.separator"));
				}
				TcBlobData event = TcBlobData.newString(description + i);
				TcBlobData pcrValue = event.sha1();
				writer.write(String.valueOf(i) + " "
						+ pcrValue.toHexStringNoWrap().replace(" ", "")
						+ " 5 [" + event + "]");
				writer.append(System.getProperty("line.separator"));
			}
			writer.close();
					
			
			// creates the test file
			String filename = TcTcsProperties.getInstance().getProperty(
					"TcTcsEventMgrFlatFile", "file");
			sml = new File(filename).getCanonicalFile();
			
			//sml = new File("test.sml").getCanonicalFile();
			TcITcsEventMgr eventMgr = TcTcsEventMgrFlatFile.getInstance(sml);
			for (int i = 0; i < 5; i++) {
				TcBlobData event = TcBlobData.newString(description + i);
				TcBlobData pcrValue = event.sha1();
				TcTssPcrEvent pcrEvent = new TcTssPcrEvent().init(
						getTPMVersion(), i, 5, pcrValue, event);
				eventMgr.logPcrEvent(pcrEvent);
			}
			BufferedReader test = new BufferedReader(new FileReader(sml));
			BufferedReader testCompare = new BufferedReader(new FileReader(
					smlCompare));
			while (true) {
				String testString = test.readLine();
				String testCompareString = testCompare.readLine();
				if (testString != null && testCompareString != null) {
					if (testString.compareTo(testCompareString) == 0)
						continue;
					else {
						throw new Exception();
					}
				} else if (testString == null && testCompareString == null) {
					assertTrue("comparing log files succeeded", true);
					break;
				} else
					throw new Exception();
			}

		} catch (Exception e) {
			assertTrue("comparing log files failed", false);
		} finally {
			sml.delete();
			smlCompare.delete();
		}
	}

}