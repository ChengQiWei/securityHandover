/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler, Thomas Holzmann, Ronald Toegl
 */

package iaik.tc.tss.test.tsp.java.pcrs;

import iaik.tc.tss.api.constants.tsp.TcTssConstants;
import iaik.tc.tss.api.exceptions.common.TcTssException;
import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.tss.api.structs.tsp.TcTssPcrEvent;
import iaik.tc.tss.api.tspi.TcITpm;
import iaik.tc.tss.test.tsp.java.TestCommon;
import iaik.tc.utils.logging.Log;

public class TestEventLog extends TestCommon {

	private int numberOfPCRs_;

	protected void setUp() throws Exception {
		super.setUp();
		numberOfPCRs_ = 16;

	}

	public void testExtendLog() {
		try {
			TcITpm tpm = context_.getTpmObject();

			long pcrIndex = 10;
			TcBlobData pcrValue = TcBlobData.newString(
					"some data to be extended into the PCR").sha1();

			TcTssPcrEvent pcrEvent = new TcTssPcrEvent();
			pcrEvent.init(getRealTpmVersion(), pcrIndex,
					TcTssConstants.TSS_EV_ACTION, null, TcBlobData
							.newString("description of the log entry"));

			int oldEventCounter = tpm.getEventCount(pcrIndex);

			tpm.pcrExtend(pcrIndex, pcrValue, pcrEvent);
			tpm.pcrExtend(pcrIndex, pcrValue, pcrEvent);
			tpm.pcrExtend(pcrIndex, pcrValue, pcrEvent);
			tpm.pcrExtend(pcrIndex, pcrValue, pcrEvent);

			if (tpm.getEventCount(pcrIndex) != oldEventCounter + 4) {
				assertTrue("wrong number of events reported", false);
			}

			TcTssPcrEvent[] events = tpm.getEventLog();

			if (events.length < 4) {
				assertTrue("wrong number of events reported", false);
			}

			// tpm.getEvent(pcrIndex, 0);
			// tpm.getEvent(pcrIndex, 3);
			//
			// try {
			// tpm.getEvent(pcrIndex, 4);
			// assertTrue("get event entry 4 succeed alsthough it should not",
			// false);
			// } catch (TcTssException e) {
			// if (e.getErrCode() == TcTcsErrors.TCS_E_BAD_PARAMETER) {
			// // expected behavior
			// } else {
			// throw e;
			// }
			// }
			//
			// events = tpm.getEvents(pcrIndex, 0, 10);
			// if (events.length != 4) {
			// assertTrue("wrong number of events reported", false);
			// }

		} catch (TcTssException e) {
			if (PRINT_TRACE) {
				Log.err(e);
			}
			assertTrue("testPcrExtendAndReadWithoutEvent failed", false);
		}

	}

	public void testEventCount() {
		try {
			TcITpm tpm = context_.getTpmObject();
			int size = numberOfPCRs_;

			for (int i = 0; i < size; i++) {
				tpm.getEventCount(i);
			}
		} catch (TcTssException e) {
			if (PRINT_TRACE) {
				Log.err(e);
			}
			assertTrue("event count failed", false);
		}
	}

	public void NOtestGetPcrEvent() {
		try {
			TcITpm tpm = context_.getTpmObject();
			int size = numberOfPCRs_;
			for (int i = 0; i < size; i++) {
				tpm.getEvent(i, 0);
			}
		} catch (TcTssException e) {
			if (PRINT_TRACE) {
				Log.err(e);
			}
			assertTrue("get event failed", false);
		}
	}

	public void testGetPcrEventsByPcr() {
		try {
			TcITpm tpm = context_.getTpmObject();
			int size = numberOfPCRs_;
			for (int i = 0; i < size; i++) {
				tpm.getEvents(i, 0, 1);
				
			}
		} catch (TcTssException e) {
			if (PRINT_TRACE) {
				Log.err(e);
			}
			assertTrue("get event by pcr failed", false);
		}
	}

	/***************************************************************************
	 * Reads out the event log with getPcrEventLog(), getPcrEventsByPcr() and
	 * getPcrEvent(), compares if they are the same events (if there exist
	 * events for a register) and checks if getPcrEventLog() has returned as
	 * much elements as getPcrEventCount() has counted.
	 */

	public void testGetPcrEventComparison() {
		try {
			TcITpm tpm = context_.getTpmObject();
			TcTssPcrEvent[] eventLog = tpm.getEventLog();
			int size = numberOfPCRs_;

			int eventCount = 0;
			for (int i = 0; i < size; i++) {
				int localEventCount = (int) tpm.getEventCount(i);
				if (localEventCount != 0) {
					TcTssPcrEvent[] pcrEvents = tpm.getEvents(i, 0,
							localEventCount);
					try {
						for (int j = 0; j < localEventCount; j++) {
							String eventString = pcrEvents[j].toString();
							String eventLogString = eventLog[eventCount + j]
									.toString();
							String pcrEventString = tpm.getEvent(i, j)
									.toString();
							if ((eventString.compareTo(eventLogString) != 0)
									|| (eventLogString
											.compareTo(pcrEventString) != 0))
								throw new Exception(
										"Compared events do not match.");
						}
					} catch (Exception e) {
						if (PRINT_TRACE) {
							Log.err(e);
						}
						assertTrue("comparing events failed", false);
					}

				}
				eventCount += localEventCount;
			}
			assertTrue("Comparing events succeeded", true);
		} catch (TcTssException e) {
			if (PRINT_TRACE) {
				Log.err(e);
			}
			assertTrue("reading out log failed", false);
		}
	}

	public void NOtestGetPcrEventLog() {
		try {
			TcITpm tpm = context_.getTpmObject();
			tpm.getEventLog();
		} catch (TcTssException e) {
			if (PRINT_TRACE) {
				Log.err(e);
			}
			assertTrue("get event log failed", false);
		}
	}

	/***************************************************************************
	 * Tries to log an event, read it out and then compares if it's the same
	 */
	public void testLogAndGetEvent() {
		try {
			TcITpm tpm = context_.getTpmObject();
			TcBlobData pcrValue = TcBlobData
					.newString("Hello World from IAIK!").sha1();

			int size = numberOfPCRs_;

			for (int i = 0; i < size; i++) {
				TcBlobData eventDescription = TcBlobData
						.newString("Hello World from IAIK!" + i);
				TcTssPcrEvent event = new TcTssPcrEvent();
				event.init(getRealTpmVersion(), i,
						TcTssConstants.TSS_EV_ACTION, null, eventDescription);

				tpm.pcrExtend(i, pcrValue, event);
				int eventNumber = tpm.getEventCount(i);
				TcTssPcrEvent newEvent = tpm.getEvent(i, eventNumber - 1);

				// we ignore the version information
				newEvent.setVersionInfo(event.getVersionInfo());

				String newEventDescription = newEvent.toString();
				String oldEventDescription = event.toString();
				int result = newEventDescription.compareTo(oldEventDescription);
				assertTrue("comparison failed", result == 0);

			}

		} catch (TcTssException e) {
			if (PRINT_TRACE) {
				Log.err(e);
			}
			assertTrue("logging failed", false);
		}
	}

	public void testLogPcrEvent() {
		try {
			TcBlobData pcrValue = TcBlobData
					.newString("Hello World from IAIK!").sha1();
			TcBlobData eventDescription = TcBlobData
					.newString("Hello World from IAIK!");
			TcITpm tpm = context_.getTpmObject();
			int size = numberOfPCRs_;

			for (int i = 0; i < size; i++) {
				TcTssPcrEvent event = new TcTssPcrEvent();
				event.init(getRealTpmVersion(), i, 0, pcrValue,
						eventDescription);
				tpm.pcrExtend(i, pcrValue, event);
			}
		} catch (TcTssException e) {
			if (PRINT_TRACE) {
				Log.err(e);
			}
			assertTrue("logging event failed", false);
		}
	}

}
