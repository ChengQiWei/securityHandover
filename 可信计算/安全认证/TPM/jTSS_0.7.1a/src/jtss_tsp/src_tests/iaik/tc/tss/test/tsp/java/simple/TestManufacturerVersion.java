/*
 * Copyright (C) 2010 IAIK, Graz University of Technology
 * authors: Josef Sabongui
 */

package iaik.tc.tss.test.tsp.java.simple;

import iaik.tc.tss.api.constants.tsp.TcTssConstants;
import iaik.tc.tss.api.exceptions.common.TcTssException;
import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.tss.api.structs.tsp.TcTssVersion;
import iaik.tc.tss.api.tspi.TcIContext;
import iaik.tc.tss.api.tspi.TcTssContextFactory;

import java.awt.Frame;

public class TestManufacturerVersion implements SimpleTest {

	protected TcIContext context_ = null;

	/**
	 * A simple test which reads out the manufacturer and the TPM version and
	 * then opens a popup window
	 */
	public void runTest() {
		try {

			//get the context via the factory and connect to it
			context_ = new TcTssContextFactory().newContextObject();
			context_.connect();

			//retrieve the version of the TPM
			TcTssVersion version = getRealTpmVersion();
			TcBlobData subCap = TcBlobData
					.newUINT32(TcTssConstants.TSS_TPMCAP_PROP_MANUFACTURER);
			//get the name of the manufacturer
			TcBlobData tpmMan = context_.getTpmObject().getCapability(
					TcTssConstants.TSS_TPMCAP_PROPERTY, subCap);

			//close the context
			context_.closeContext();


			String msg1 = "The manufacturer of your TPM is: "
					+ tpmMan.toStringASCII().substring(0, tpmMan.toStringASCII().length()-1) ;
			String msg2 = "The version of your TPM is: "
					+ version.getMajor()+"."+version.getMinor();
			String msg3 = "Congratulations! The communication with the jTSS Core Services and the TPM was successful!";
			Frame frame = new Frame("Manufacturer and device info");

			MsgBox msgBox = new MsgBox(frame, msg3, msg1, msg2, false);

			if (msgBox.isOk) {
				msgBox.dispose();
				frame.dispose();
			}

		} catch (Exception e) {
			e.printStackTrace();
			Frame frame = new Frame("Manufacturer and device info");
			MsgBox msgBox = new MsgBox(frame,
					"The communication with the TPM failed.", false);
			msgBox.dispose();
			frame.dispose();
		}

	}

	protected TcTssVersion getRealTpmVersion() throws TcTssException {
		TcTssVersion tpmVersion = null;
		try {
			// first try 1.2 style
			tpmVersion = context_.getTpmObject().getCapabilityVersion(
					TcTssConstants.TSS_TPMCAP_VERSION_VAL, null);
		} catch (TcTssException e) {
			// alternatively try 1.1 style
			tpmVersion = context_.getTpmObject().getCapabilityVersion(
					TcTssConstants.TSS_TPMCAP_VERSION, null);
		}

		return tpmVersion;
	}
}