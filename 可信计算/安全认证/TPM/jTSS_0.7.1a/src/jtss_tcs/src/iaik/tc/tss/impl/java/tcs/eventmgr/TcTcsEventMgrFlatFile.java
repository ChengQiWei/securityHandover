/*
 * Copyright (C) 2008 IAIK, Graz University of Technology
 * authors: Thomas Holzmann
 */

package iaik.tc.tss.impl.java.tcs.eventmgr;

import iaik.tc.tss.api.constants.tcs.TcTcsErrors;
import iaik.tc.tss.api.exceptions.common.TcTssException;
import iaik.tc.tss.api.exceptions.tcs.TcTcsException;
import iaik.tc.tss.api.structs.tsp.TcTssPcrEvent;
import iaik.tc.tss.api.structs.tsp.TcTssVersion;
import iaik.tc.tss.impl.java.tcs.TcTcsCommon;
import iaik.tc.tss.impl.java.tcs.TcTcsProperties;
import iaik.tc.utils.misc.Utils;
import iaik.tc.utils.logging.Log;
import iaik.tc.utils.misc.CheckPrecondition;
import iaik.tc.tss.api.structs.common.TcBlobData;

import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/*******************************************************************************
 * This class implements a flat file event manager. The event information is
 * stored in a stored measurement log (SML) file described in the configuration
 * file. The event log has the following format:<br><br>
 *
 * [PCR] [measurement hash] [event] [event description]
 * <br><br>
 * The PCR is a decimal number, the measurement hash and event are hexadecimal
 * numbers.
 */
public class TcTcsEventMgrFlatFile implements TcITcsEventMgr {

	/**
	 * this objects holds an opened RandomAccessFile of the SML
	 */
	private RandomAccessFile sml_ = null;
	/**
	 * Stores the number of PCRs available.
	 */
	private int numOfPcrs_ = 0;
	/**
	 * Stores the offsets of events in the file related to the PCR index
	 */
	private Map<Long, List<Long>> pcrInfos_ = null;

	private static TcTcsEventMgrFlatFile instance_=null;

	public static synchronized TcITcsEventMgr getInstance() throws TcTcsException {
		if (instance_ == null) {

			//TODO: for a full fledged event manager support a "collector event
			// manager" collecting events
			// from multiple sources such as BIOS, IMA, ... is required.

			try {
				String filename = TcTcsProperties.getInstance().getProperty(
						"TcTcsEventMgrFlatFile", "file");
				File logfile = new File(filename).getCanonicalFile();
				instance_ = new TcTcsEventMgrFlatFile(logfile);
			} catch (Exception e) {
				Log.err("Unable to initialize TcTcsEventMgrFlatFile. Please check the"
						+ " configuration file.");
			}
		}
		return instance_;
	}

	public static synchronized TcITcsEventMgr getInstance(File sml) throws TcTcsException {
		if (instance_ == null) {

			//TODO: for a full fledged event manager support a "collector event
			// manager" collecting events
			// from multiple sources such as BIOS, IMA, ... is required.

			try {
				instance_ = new TcTcsEventMgrFlatFile(sml);
			} catch (Exception e) {
				Log
						.err("Unable to initialize TcTcsEventMgrFlatFile. Please check the"
								+ " configuration file.");
			}
		}
		return instance_;
	}


	/***************************************************************************
	 * Constructor. Gets the desired log file, stores its reference into sml_
	 * and determines the number of PCRs available,
	 */
	protected TcTcsEventMgrFlatFile(File logfile) throws TcTcsException {
		try {
			numOfPcrs_ = (int) TcTcsCommon.getNumPcrs();
			File sml = logfile;

			pcrInfos_ = new HashMap<Long, List<Long>>();
			for (int i = 0; i < numOfPcrs_; i++) {
				pcrInfos_.put(new Long(i), new ArrayList<Long>());
			}

			if (!sml.isFile()) {
				sml.createNewFile();
			}

			sml_ = new RandomAccessFile(sml, "rwd");

			parse();

			Log.info("Using \"flat file\" event log.");
		} catch (IOException e) {
			throw new TcTcsException(TcTcsErrors.TCS_E_INTERNAL_ERROR,
					"Unable to create the logfile.");
		} catch (TcTssException e) {
			throw new TcTcsException(TcTcsErrors.TCS_E_INTERNAL_ERROR,
					"Unable to determine the number of PCRs");
		}
	}

	/***************************************************************************
	 * Reads out the desired event using getPcrEventsByPcr().
	 */
	public TcTssPcrEvent getPcrEvent(long pcrIndex, long pNumber)
			throws TcTcsException {
		TcTssPcrEvent[] event = getPcrEventsByPcr(pcrIndex, pNumber, 1);
		return event[0];
	}

	/***************************************************************************
	 * Counts the events of a PCR
	 */
	public long getPcrEventCount(long pcrIndex) throws TcTcsException {
		CheckPrecondition.gtOrEq(pcrIndex, "pcrIndex", 0);
		CheckPrecondition.ltOrEq(pcrIndex, "pcrIndex", numOfPcrs_);

		return pcrInfos_.get(new Long(pcrIndex)).size();
	}

	/***************************************************************************
	 * Reads out the desired events from the log file and returns it as an array
	 * of TcTssPcrEvent[].
	 */
	public TcTssPcrEvent[] getPcrEventsByPcr(long pcrIndex, long firstEvent,
			long eventCount) throws TcTcsException {

		synchronized (sml_) {
			long numOfEvents = getPcrEventCount(pcrIndex);

			CheckPrecondition.gtOrEq(pcrIndex, "pcrIndex", 0);
			CheckPrecondition.ltOrEq(pcrIndex, "pcrIndex", numOfPcrs_ - 1);
			CheckPrecondition.gtOrEq(firstEvent, "firstEvent", 0);
			CheckPrecondition.gtZero(eventCount, "eventCount");

			if (firstEvent > (numOfEvents)) {
				return null;
			}

			if ((firstEvent + eventCount) > numOfEvents) {
				eventCount = (numOfEvents - firstEvent);
				if (eventCount == 0) {
					return null;
				}
			}

			int length = (int) eventCount;

			TcTssPcrEvent[] events = new TcTssPcrEvent[length];

			for (int i = (int) firstEvent; i < (firstEvent + length); i++) {
				String current = null;
				long offset = pcrInfos_.get(pcrIndex).get(i);
				try {
					sml_.seek(offset);
					current = sml_.readLine();
				} catch (IOException e) {
					throw new TcTcsException(TcTcsErrors.TCS_E_FAIL,
							"internal error parsing logfile");
				}

				events[i - (int) firstEvent] = logStringToEvent(current);
			}

			return events;
		}
	}

	/***************************************************************************
	 * Reads out all PCR events with getPcrEventsByPcr() an then returns it all
	 * together.
	 */
	public TcTssPcrEvent[] getPcrEventLog() throws TcTcsException {
		synchronized (sml_) {
			int numOfEvents = 0;
			int currentEvent = 0;

			for (int pcr = 0; pcr < numOfPcrs_; pcr++) {
				if (((int) getPcrEventCount(pcr)) < getPcrEventCount(pcr)) {
					throw new TcTcsException(TcTcsErrors.TCS_E_INTERNAL_ERROR,
							"integer overflow detected");
				}
				numOfEvents += (int) getPcrEventCount(pcr);
			}

			TcTssPcrEvent[] log = new TcTssPcrEvent[numOfEvents];

			for (int pcr = 0; pcr < numOfPcrs_; pcr++) {
				int pcrEventCount = (int) getPcrEventCount(pcr);
				TcTssPcrEvent[] pcrEvents = null;
				if (pcrEventCount > 0) {
					pcrEvents = getPcrEventsByPcr(pcr, 0, pcrEventCount);
					System.arraycopy(pcrEvents, 0, log, currentEvent, pcrEvents.length);
					currentEvent += pcrEvents.length;
				}
			}
			return log;
		}
	}

	/***************************************************************************
	 * Converts the input event to a string and writes it into the log file.
	 */
	public long logPcrEvent(TcTssPcrEvent pcrEvent) throws TcTcsException {
		CheckPrecondition.notNull(pcrEvent, "pcrEvent");

		// reads out the values and converts them into hexadecimal values
		String pcr = Long.toString(pcrEvent.getPcrIndex());
		String hash = pcrEvent.getPcrValue().toHexStringNoWrap();
		String event = Long.toHexString(pcrEvent.getEventType());

		String description = pcrEvent.getEvent().toString();
		long position = 0;
		synchronized (sml_) {
			try {
				sml_.seek(sml_.length());
				position = pcrInfos_.get(pcrEvent.getPcrIndex()).size();
				pcrInfos_.get(pcrEvent.getPcrIndex()).add(sml_.getFilePointer());

				sml_.writeBytes(pcr + " " + hash.replace(" ", "") + " "
						+ event.replace(" ", "") + " [" + description + "]");
				sml_.writeBytes(Utils.lineSeperator);
			} catch (IOException e) {
				throw new TcTcsException(TcTcsErrors.TCS_E_INTERNAL_ERROR,
						"Could not write to the log file.");
			}
			return position;
		}
	}

	/***************************************************************************
	 * Converts a given event string from the log file to a TcTssPcrEvent.
	 *
	 * @param log
	 *            the event string from the log file
	 * @return the same converted into a TcTssPcrEvent
	 */
	private TcTssPcrEvent logStringToEvent(String log) {
		String[] eventParts = log.split(" ", 4);
		long pcrIndex = Long.parseLong(eventParts[0]);
		long eventType = Long.parseLong(eventParts[2], 16);
		TcBlobData pcrValue = TcBlobData.newByteArray(Utils
				.hexStringToByteArray(eventParts[1]));
		int length = eventParts[3].length();
		String eventString = eventParts[3].substring(1, length - 1);
		TcBlobData event = TcBlobData.newString(eventString);

		TcTssVersion version = new TcTssVersion();

		return new TcTssPcrEvent().init(version, pcrIndex, eventType, pcrValue, event);
	}

	/***************************************************************************
	 *
	 */
	private void parse() {
		try {
			synchronized (sml_) {
				String currentLine = null;
				long currentFp = 0;
				sml_.seek(currentFp);

				while (true) {
					currentFp = sml_.getFilePointer();
					currentLine = sml_.readLine();

					if (currentLine == null) {
						break;
					}

					Long currentPcr = new Long(Long.parseLong(currentLine.substring(0, 2).trim()));
					pcrInfos_.get(currentPcr).add(currentFp);
				}
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
}
