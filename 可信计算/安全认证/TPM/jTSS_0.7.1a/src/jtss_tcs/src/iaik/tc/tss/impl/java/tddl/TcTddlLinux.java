/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.impl.java.tddl;

import iaik.tc.tss.api.constants.tcs.TcTddlErrors;
import iaik.tc.tss.api.exceptions.tcs.TcTddlException;
import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.tss.impl.java.tcs.TcTcsProperties;
import iaik.tc.utils.logging.Log;
import iaik.tc.utils.misc.Utils;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.RandomAccessFile;

/**
 * This class implements the TDDL layer for LINUX operating systems. The basic
 * assumption is that the TPM is made available by means of a character device
 * (e.g. /dev/tpm0).
 */
public class TcTddlLinux extends TcTddl {

	/** Size of receive buffer. */
	protected int RX_BLOB_LEN = 8192;

	/** List if devices that are checked. */
	protected String tpmDevices_[] = new String[] { "/dev/tpm0", "/dev/tpm1",
			"/dev/tpm2", "/dev/tpm3", "/dev/tpm" };

	/** Holds the device name that was actually opened in the open method. */
	protected String devTpm_ = "";

	/** File handle for the opened TPM device. */
	protected RandomAccessFile tpm_ = null;

	/***************************************************************************
	 * Make constructor unavailable - Singleton pattern.
	 */
		TcTddlLinux() {

		String filename="";

		try {
			filename = TcTcsProperties.getInstance().getProperty(
					TcTcsProperties.TCS_INI_SEC_TPMDEVICE,
					TcTcsProperties.TCS_INI_KEY_LINUX_TPMDEVICE);

		} catch (Exception e) {
			Log.info("Found no TPM device configuration in ini file. Will later attempt auto-detection.");
		}

		if (filename != "")
			tpmDevices_ = new String[] { filename };

	}

	/***************************************************************************
	 * This method opens the TPM device. I tries to open predefined device file
	 * names one after the other until a device file could be opened for
	 * read/write access.
	 * 
	 * @throws TcTddlException
	 *             This exception is thrown if no TPM device could not be
	 *             opened.
	 */
	public void open() throws TcTddlException {
		if (isOpen()) {
			return;
		}

		StringBuffer errLog = new StringBuffer();

		for (int i = 0; i < tpmDevices_.length; i++) {
			String devTpm = tpmDevices_[i];

			File f = new File(devTpm);
			if (!f.exists()) {
				continue;
			}
			if (!f.canRead()) {
				errLog.append("Unable to open TPM device file " + devTpm
						+ " for reading (permissions problem?).");
				errLog.append(Utils.getNL());
				continue;
			}
			if (!f.canWrite()) {
				errLog.append("Unable to open TPM device file " + devTpm
						+ " for writing (permissions problem?).");
				errLog.append(Utils.getNL());
				continue;
			}

			try {
				tpm_ = new RandomAccessFile(devTpm, "rw");
				devTpm_ = devTpm;
				break;
			} catch (FileNotFoundException e) {
				errLog.append("Unable to open TPM device file " + devTpm + ".");
				errLog.append(Utils.getNL());
				errLog.append("Reason: " + e.getMessage());
				errLog.append(Utils.getNL());
				tpm_ = null;
			}
		}

		if (tpm_ == null) {
			String msg;
			if (errLog.length() == 0) {
				msg = "No TPM device file found. (checked devices: ";
				for (int i = 0; i < tpmDevices_.length - 1; i++) {
					msg += tpmDevices_[i] + ", ";
				}
				msg += tpmDevices_[tpmDevices_.length - 1] + ").";
			} else {
				msg = errLog.toString();
			}
			Log.warn(msg);
			throw new TcTddlException(TcTddlErrors.TDDL_E_IOERROR, msg);
		}
	}

	/***************************************************************************
	 * This method returns true if the TPM device is already open, false
	 * otherwise.
	 */
	public boolean isOpen() {
		if (tpm_ == null) {
			return false;
		} else {
			return true;
		}
	}

	/***************************************************************************
	 * This method closes the previously opened TPM device.
	 */
	public void close() throws TcTddlException {
		if (!isOpen()) {
			throw new TcTddlException(TcTddlErrors.TDDL_E_ALREADY_CLOSED);
		}

		synchronized (tpm_) {
			try {
				tpm_.close();
				tpm_ = null;
			} catch (IOException e) {
			}
		}
	}

	/***************************************************************************
	 * This sends the given byte blob to the TPM.
	 * 
	 * @param command
	 *            The command blob to the sent to the TPM.
	 * 
	 * @throws TcTddlException
	 *             This exception is thrown if writing to or reading from the
	 *             TPM device failed.
	 */
	public TcBlobData transmitData(TcBlobData command) throws TcTddlException {
		int bytesReceived = 0;
		byte[] retData = new byte[RX_BLOB_LEN];

		if (!isOpen()) {
			throw new TcTddlException(TcTddlErrors.TDDL_E_ALREADY_CLOSED,
					"TPM device was not (yet) opened!");
		}

		// Note: According to the TSS specification, no synchronization needs to
		// be done at TDDL level
		// (this has to be done already at TCS level). Nevertheless, an
		// additional safeguard is included
		// here to ensure proper TPM access synchronization.
		synchronized (tpm_) {
			try {
				Log.debug("to TPM: " + command.toHexString());
				tpm_.write(command.asByteArray());
			} catch (IOException e) {
				throw new TcTddlException(TcTddlErrors.TDDL_E_IOERROR, e
						.getMessage()
						+ Utils.getNL()
						+ "Writing to TPM device ("
						+ devTpm_
						+ ") failed.");
			}


			
			try {
				bytesReceived = tpm_.read(retData);
			} catch (IOException e) {
				throw new TcTddlException(TcTddlErrors.TDDL_E_IOERROR, e
						.getMessage()
						+ Utils.getNL()
						+ "Reading from TPM device ("
						+ devTpm_
						+ ") failed.");
			}
		}

		if (bytesReceived <= 0) {
			throw new TcTddlException(TcTddlErrors.TDDL_E_FAIL,
					"No response from TPM received.");
		}

		if (bytesReceived == RX_BLOB_LEN) {
			throw new TcTddlException(TcTddlErrors.TDDL_E_INSUFFICIENT_BUFFER,
					"Receive buffer too small?");
		}

		TcBlobData retBlob = TcBlobData.newByteArray(retData, 0, bytesReceived);
		Log.debug("from TPM: " + retBlob.toHexString());
		return retBlob;
	}

	// This TDDL does not implement the functionality that is not absolutely
	// required by a TSS.

	/***************************************************************************
	 * This method is not implemented by this TDDL.
	 */
	public void cancel() throws TcTddlException {
		throw new TcTddlException(TcTddlErrors.TDDL_E_FAIL,
				"The cancel method is not implemented.");
	}

	/***************************************************************************
	 * This method is not implemented by this TDDL.
	 */
	public void getCapability() throws TcTddlException {
		throw new TcTddlException(TcTddlErrors.TDDL_E_FAIL,
				"The getCapability method is not implemented.");
	}

	/***************************************************************************
	 * This method is not implemented by this TDDL.
	 */
	public void setCapability() throws TcTddlException {
		throw new TcTddlException(TcTddlErrors.TDDL_E_FAIL,
				"The setCapability method is not implemented.");
	}

	/***************************************************************************
	 * This method is not implemented by this TDDL.
	 */
	public void getStatus() throws TcTddlException {
		throw new TcTddlException(TcTddlErrors.TDDL_E_FAIL,
				"The getStatus method is not implemented.");
	}

	/***************************************************************************
	 * This method is not implemented by this TDDL.
	 */
	public void setStatus() throws TcTddlException {
		throw new TcTddlException(TcTddlErrors.TDDL_E_FAIL,
				"The setStatus method is not implemented.");
	}

	/***************************************************************************
	 * This method is not implemented by this TDDL.
	 */
	public void powerManagement() throws TcTddlException {
		throw new TcTddlException(TcTddlErrors.TDDL_E_FAIL,
				"The powerManagement method is not implemented.");
	}

	/***************************************************************************
	 * This method is not implemented by this TDDL.
	 */
	public void powerManagementControl() throws TcTddlException {
		throw new TcTddlException(TcTddlErrors.TDDL_E_FAIL,
				"The powerManagementControl method is not implemented.");
	}
}
