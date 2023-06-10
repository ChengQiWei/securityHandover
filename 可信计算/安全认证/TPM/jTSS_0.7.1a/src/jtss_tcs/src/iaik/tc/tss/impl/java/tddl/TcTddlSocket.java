/*
 * Copyright (C) 2010 IAIK, Graz University of Technology
 * authors: Ronald Toegl
 */

package iaik.tc.tss.impl.java.tddl;

import iaik.tc.tss.api.constants.tcs.TcTddlErrors;
import iaik.tc.tss.api.exceptions.tcs.TcTddlException;
import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.tss.impl.java.tcs.TcTcsProperties;
import iaik.tc.utils.logging.Log;
import iaik.tc.utils.logging.LogLevels;
import iaik.tc.utils.misc.Utils;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;

/**
 * This class implements the TDDL layer to connect to TPM accessibly via a TCP/IP socket.
 * It is designed to be used with IBM's software TPM.
 */
public class TcTddlSocket extends TcTddl {

	/** Size of receive buffer. */
	protected final int RX_BLOB_LEN = 8192;

	protected String serverName_;
	protected int port_;

	boolean isOpen_ = false;

	/***************************************************************************
	 * Make constructor unavailable - Singleton pattern.
	 */
	TcTddlSocket() {
		
		Log.setLogLevel(TcTddlSocket.class, LogLevels.INFO); //disable detailed output

		try {
			serverName_ = TcTcsProperties.getInstance().getProperty(
					TcTcsProperties.TCS_INI_SEC_TPMSOCKET,
					TcTcsProperties.TCS_INI_KEY_TPMSOCKET_TPMSERVER_NAME);

			port_ = Integer.parseInt(TcTcsProperties.getInstance().getProperty(
					TcTcsProperties.TCS_INI_SEC_TPMSOCKET,
					TcTcsProperties.TCS_INI_KEY_TPMSOCKET_TPMSERVER_PORT));

		} catch (Exception e) {
			Log.err("Failed to read ini file for Socket-based TDDL configuration");
		}

	}

	/***************************************************************************
	 * This method opens the TPM device. 
	 * IBM's implementation always closes the connection after each command, so this opens and closes an empty session to test if the server can be reached.
	 * @throws TcTddlException
	 *             This exception is thrown if no TPM device could not be
	 *             opened.
	 */
	public void open() throws TcTddlException {
		if (isOpen()) {
			return;
		}

		try {

			Socket tpmSocket = new Socket(serverName_, port_);
			tpmSocket.close();
			// Its possible to connect
			isOpen_ = true;

		} catch (Exception e) {
			throw new TcTddlException(TcTddlErrors.TDDL_E_ALREADY_CLOSED,
					"Could not open socket to TPM Server at " + serverName_
							+ ":" + port_ + ".");
		}

	}

	/***************************************************************************
	 * This method returns true if the TPM device is already open, false
	 * otherwise.
	 */
	public boolean isOpen() {
		return isOpen_;
	}

	/***************************************************************************
	 * This method closes the previously opened TPM device.
	 */
	public void close() throws TcTddlException {
		if (!isOpen()) {
			throw new TcTddlException(TcTddlErrors.TDDL_E_ALREADY_CLOSED);
		}

		isOpen_ = false;

	}

	/***************************************************************************
	 * This sends the given byte blob to the TPM.
	 * IBM's implementation alway closes the connection after each command, so we need to open a new one for each transmission.
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
					"TPM device socket was not (yet) opened!");
		}

		Socket tpmSocket;
		DataInputStream is;
		DataOutputStream os;

		try {

			tpmSocket = new Socket(serverName_, port_);
			os = new DataOutputStream(tpmSocket.getOutputStream());
			is = new DataInputStream(tpmSocket.getInputStream());

		} catch (IOException e) {
			throw new TcTddlException(TcTddlErrors.TDDL_E_IOERROR, e
					.getMessage()
					+ Utils.getNL()
					+ "Connect to TPM server at socket ("
					+ serverName_ + ":" + port_ + ") failed.");
		}

		Log.debug("to TPM: " + command.toHexString());

		try {
			os.write(command.asByteArray());
			os.flush();

		} catch (IOException e) {
			throw new TcTddlException(TcTddlErrors.TDDL_E_IOERROR, e
					.getMessage()
					+ Utils.getNL()
					+ "Writing to TPM socket ("
					+ serverName_
					+ ":" + port_ + ") failed.");
		}

		try {
			bytesReceived = is.read(retData);

		} catch (IOException e) {
			throw new TcTddlException(TcTddlErrors.TDDL_E_IOERROR, e
					.getMessage()
					+ Utils.getNL()
					+ "Reading from TPM socket ("
					+ serverName_
					+ ":" + port_ + ") failed.");
		}

		try {
			is.close();
			os.close();
			tpmSocket.close();

		} catch (IOException e) {
			throw new TcTddlException(TcTddlErrors.TDDL_E_IOERROR, e
					.getMessage()
					+ Utils.getNL()
					+ "Closing TPM socket ("
					+ serverName_
					+ ":" + port_ + ") failed.");
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
