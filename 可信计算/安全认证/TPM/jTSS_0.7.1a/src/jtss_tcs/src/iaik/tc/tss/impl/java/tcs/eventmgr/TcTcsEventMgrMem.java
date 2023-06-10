/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.impl.java.tcs.eventmgr;

import iaik.tc.tss.api.constants.tcs.TcTcsErrors;
import iaik.tc.tss.api.exceptions.common.TcTssException;
import iaik.tc.tss.api.exceptions.tcs.TcTcsException;
import iaik.tc.tss.api.structs.tsp.TcTssPcrEvent;
import iaik.tc.tss.impl.java.tcs.TcTcsCommon;
import iaik.tc.utils.logging.Log;
import iaik.tc.utils.misc.CheckPrecondition;

import java.util.Vector;

/**
 * This class implements a basic "in memory" event manager. That is, all events
 * are stored in memory. Since the TCS is a software that might run long times
 * without being restarted this type of implementation has the drawback that the
 * memory footprint will increase over time (events do not get removed from the
 * log once they are added).
 * 
 * Alternative implementations might use some database and/or disk backends to
 * provide better scalability and efficiency.
 */
public class TcTcsEventMgrMem implements TcITcsEventMgr {

	/**
	 * This filed holds the PCR events individually for every PCR of the
	 * system's TPM. For the individual PCRs, the events are added in the order
	 * they are received.
	 */
	protected Vector[] eventsByPcr_ = null;

	protected static TcTcsEventMgrMem instance_ = null;

	/***************************************************************************
	 * Constructor. Determine the number of PCRs supported by the TPM and
	 * initialize the events array accordingly.
	 */
	protected TcTcsEventMgrMem() throws TcTcsException {
		Log.info("Using \"in memory\" event log.");
		try {
			eventsByPcr_ = new Vector[(int) TcTcsCommon.getNumPcrs()];
			for (int i = 0; i < eventsByPcr_.length; i++) {
				eventsByPcr_[i] = new Vector();
			}
		} catch (TcTssException e) {
			throw new TcTcsException(TcTcsErrors.TCS_E_INTERNAL_ERROR,
					"Unable to determine the number of PCRs");
		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see iaik.tc.tss.impl.java.tcs.eventmgr.TcTcsEventMgr#getPcrEvent(long,
	 *      long)
	 */
	public TcTssPcrEvent getPcrEvent(long pcrIndex, long number)
			throws TcTcsException {
		synchronized (eventsByPcr_) {
			CheckPrecondition.gtOrEq(pcrIndex, "pcrIndex", 0);
			CheckPrecondition.ltOrEq(pcrIndex, "pcrIndex",
					eventsByPcr_.length - 1);
			CheckPrecondition.gtOrEq(number, "number", 0);
			if (number > eventsByPcr_[(int) pcrIndex].size() - 1) {
				throw new TcTcsException(
						TcTcsErrors.TCS_E_BAD_PARAMETER,
						"The requested number of elements exceeds the number of events logged for this PCR.");
			}

			return (TcTssPcrEvent) eventsByPcr_[(int) pcrIndex]
					.elementAt((int) number);
		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see iaik.tc.tss.impl.java.tcs.eventmgr.TcTcsEventMgr#getPcrEventCount(long)
	 */
	public long getPcrEventCount(long pcrIndex) throws TcTcsException {
		CheckPrecondition.gtOrEq(pcrIndex, "pcrIndex", 0);
		CheckPrecondition.ltOrEq(pcrIndex, "pcrIndex", eventsByPcr_.length - 1);

		synchronized (eventsByPcr_) {
			return eventsByPcr_[(int) pcrIndex].size();
		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see iaik.tc.tss.impl.java.tcs.eventmgr.TcTcsEventMgr#getPcrEventLog()
	 */
	public TcTssPcrEvent[] getPcrEventLog() throws TcTcsException {
		synchronized (eventsByPcr_) {
			int numEventsTotal = 0;
			for (int i = 0; i < eventsByPcr_.length; i++) {
				numEventsTotal += getPcrEventCount(i);
			}
			TcTssPcrEvent[] retVal = new TcTssPcrEvent[numEventsTotal];

			// Log.warn("total event count " + numEventsTotal);

			int retValIdx = 0;
			for (int i = 0; i < eventsByPcr_.length; i++) {
				for (int j = 0; j < eventsByPcr_[i].size(); j++) {
					retVal[retValIdx++] = (TcTssPcrEvent) eventsByPcr_[i]
							.elementAt(j);
				}
			}

			return retVal;
		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see iaik.tc.tss.impl.java.tcs.eventmgr.TcTcsEventMgr#getPcrEventsByPcr(long,
	 *      long, long)
	 */
	public TcTssPcrEvent[] getPcrEventsByPcr(long pcrIndex, long firstEvent,
			long eventCount) throws TcTcsException {
		synchronized (eventsByPcr_) {
			CheckPrecondition.gtOrEq(pcrIndex, "pcrIndex", 0);
			CheckPrecondition.ltOrEq(pcrIndex, "pcrIndex",
					eventsByPcr_.length - 1);
			CheckPrecondition.gtOrEq(firstEvent, "firstEvent", 0);
			if (firstEvent > (eventsByPcr_[(int) pcrIndex].size())) {
				throw new TcTcsException(TcTcsErrors.TCS_E_BAD_PARAMETER,
						"firstEvent offset exceeds size of event log.");
			}
			CheckPrecondition.gtZero(eventCount, "eventCount");

			int lastEvent = (int) (firstEvent + eventCount - 1);
			if (lastEvent >= (eventsByPcr_[(int) pcrIndex].size())) {
				lastEvent = eventsByPcr_[(int) pcrIndex].size() - 1;
			}

			TcTssPcrEvent[] retVal = new TcTssPcrEvent[lastEvent
					- (int) firstEvent + 1];
			for (int i = (int) firstEvent; i <= lastEvent; i++) {
				retVal[i] = (TcTssPcrEvent) eventsByPcr_[(int) pcrIndex]
						.elementAt(i);
			}

			return retVal;
		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see iaik.tc.tss.impl.java.tcs.eventmgr.TcTcsEventMgr#logPcrEvent(iaik.tc.tss.api.structs.tsp.TcTssPcrEvent)
	 */
	public long logPcrEvent(TcTssPcrEvent pcrEvent) throws TcTcsException {
		CheckPrecondition.notNull(pcrEvent, "pcrEvent");

		long pcrIndex = pcrEvent.getPcrIndex();
		synchronized (eventsByPcr_) {
			eventsByPcr_[(int) pcrIndex].add(pcrEvent);
			return eventsByPcr_[(int) pcrIndex].size() - 1;
		}
	}

	public static TcITcsEventMgr getInstance() throws TcTcsException {
		if (instance_ == null)
			instance_ = new TcTcsEventMgrMem();

		return instance_;
	}
}