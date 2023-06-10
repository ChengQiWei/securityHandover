/*
 * Copyright (C) 2007-2008 IAIK, Graz University of Technology
 * authors: Thomas Winkler, Thomas Holzmann
 */

package iaik.tc.tss.impl.java.tcs.eventmgr;

import iaik.tc.tss.api.exceptions.tcs.TcTcsException;
import iaik.tc.tss.api.structs.tsp.TcTssPcrEvent;
import iaik.tc.tss.impl.java.tcs.tcsi.TcTcsi;

/**
 * This class can only be instantiated once (Singleton). The log file
 * implementation must be configured in jtss_tcs.ini
 * 
 * Any implementation MUST IMPLEMENT an getInstance() method.
 */
public interface TcITcsEventMgr {

	/***************************************************************************
	 * {@link TcTcsi#TcsiGetPcrEvent(long, long, long)}
	 */
	public TcTssPcrEvent getPcrEvent(long pcrIndex, long pNumber)
			throws TcTcsException;

	/***************************************************************************
	 * {@link TcTcsi#TcsiGetPcrEventCount(long, long)}
	 */
	public long getPcrEventCount(long pcrIndex) throws TcTcsException;

	/***************************************************************************
	 * {@link TcTcsi#TcsiGetPcrEventsByPcr(long, long, long, long)}
	 */
	public TcTssPcrEvent[] getPcrEventsByPcr(long pcrIndex, long firstEvent,
			long eventCount) throws TcTcsException;

	/***************************************************************************
	 * {@link TcTcsi#TcsiGetPcrEventLog(long)}
	 */
	public TcTssPcrEvent[] getPcrEventLog() throws TcTcsException;

	/***************************************************************************
	 * {@link TcTcsi#TcsiLogPcrEvent(long, TcTssPcrEvent)}
	 */
	public long logPcrEvent(TcTssPcrEvent pcrEvent) throws TcTcsException;
}
