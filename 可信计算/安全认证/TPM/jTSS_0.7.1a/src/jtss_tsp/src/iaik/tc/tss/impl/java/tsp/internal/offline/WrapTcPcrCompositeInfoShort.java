/*
 * Copyright (C) 2010 IAIK, Graz University of Technology
 */

package iaik.tc.tss.impl.java.tsp.internal.offline;

import iaik.tc.tss.api.constants.tsp.TcTssConstants;
import iaik.tc.tss.api.exceptions.common.TcTssException;
import iaik.tc.tss.api.structs.tpm.TcTpmPcrInfoShort;
import iaik.tc.tss.impl.java.tsp.TcPcrCompositeInfoShort;

/**
 * A wrapping around {@link TcPcrCompositeInfoShort}.<br>
 * With this wrapping it is easy to calculate composite hashes without the need
 * of a present TPM.<br>
 * This wrapping also allows to get access to the internal
 * {@link TcTpmPcrInfoShort} struct via
 * {@link WrapTcPcrCompositeInfoShort#getPcrInfoShort()} method.
 */
public class WrapTcPcrCompositeInfoShort extends TcPcrCompositeInfoShort {

	public static final int NUM_PCRS = 24;

	protected WrapTcPcrCompositeInfoShort() throws TcTssException {
		super(null);
	}

	/**
	 * Always returns {@link WrapTcPcrCompositeInfoShort#NUM_PCRS} independent of
	 * an actual TPM. <br>
	 * This is OK because we need this struct to always produce an TPM 1.2
	 * compatible PcrInfoShort.
	 */
	protected int getNumPcrs() {
		return NUM_PCRS;
	}

	public TcTpmPcrInfoShort getPcrInfoShort() {
		return pcrInfo_;
	}

	public void selectPcrIndex(long pcrIndex) {
		try {
			selectPcrIndexEx(pcrIndex, TcTssConstants.TSS_PCRS_DIRECTION_RELEASE);
		} catch (TcTssException e) {
			// This shouldn't happen
			throw new AssertionError(e);
		}
	}

	/**
	 * Create an instance of {@link WrapTcPcrCompositeInfoShort}
	 */
	public static WrapTcPcrCompositeInfoShort getInstance() {
		try {
			return new WrapTcPcrCompositeInfoShort();
		} catch (TcTssException e) {
			return null;
		}
	}
}
