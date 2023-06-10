/*
 * Copyright (C) 2010 IAIK, Graz University of Technology
 * author: Josef Sabongui
 */


package iaik.tc.tss.test.tsp.java.simple;

import iaik.tc.tss.api.constants.tsp.TcTssConstants;
import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.tss.api.structs.tpm.TcTpmPermanentFlags;
import iaik.tc.tss.api.structs.tpm.TcTpmStClearFlags;
import iaik.tc.tss.api.tspi.TcIContext;
import iaik.tc.tss.api.tspi.TcITpm;
import iaik.tc.tss.api.tspi.TcTssContextFactory;
import iaik.tc.utils.misc.Utils;

import java.awt.Frame;
import java.util.StringTokenizer;
import java.util.Vector;

public class TestTpmFlags implements SimpleTest {
	
	protected TcIContext context_ = null;

	/**
	 * A simple test which reads the current TPM flags and
	 * then opens a popup window
	 */
	public void runTest() {
		try {
			//get the context via the factory and connect to it
			context_ = new TcTssContextFactory().newContextObject();
			context_.connect();

			// get the TPM object
			TcITpm tpm = context_.getTpmObject();

			//get the TPM flags
			TcBlobData flags = tpm.getCapability(TcTssConstants.TSS_TPMCAP_FLAG, null);

			// close the context
			context_.closeContext();
			
			//just preparing the information for display
			StringBuffer buffer = new StringBuffer();

			buffer.append("TPM_PERMANENT_FLAGS:");
			buffer.append(Utils.getNL());
			TcTpmPermanentFlags pflags = new TcTpmPermanentFlags(flags, 0);
			buffer.append(pflags.toString().replaceAll("^tag.*\n",""));

			buffer.append("______________________" + Utils.getNL());
			buffer.append("                      " + Utils.getNL());

			buffer.append("TPM_STCLEAR_FLAGS:");
			buffer.append(Utils.getNL());
			TcTpmStClearFlags vflags = new TcTpmStClearFlags(flags, 0);
			buffer.append(vflags.toString().replaceAll("^tag.*\n",""));

			Vector<String> msgs = new Vector<String>();
			StringTokenizer tokenizer = new StringTokenizer(buffer.toString(), Utils.getNL());
			while (tokenizer.hasMoreTokens()) {
				msgs.addElement(tokenizer.nextToken() + Utils.getNL());
			}

			String msg1 = new String("TPM Flags:");

			Frame frame = new Frame("Show the currently set TPM flags");
			MsgBox msgBox = new MsgBox(frame, msg1, msgs, false);

			if (msgBox.isOk) {
				msgBox.dispose();
				frame.dispose();
			}


		} catch (Exception e) {
			e.printStackTrace();
			Frame frame = new Frame("jTSS Test");
			MsgBox msgBox = new MsgBox(frame,
					"The communication with the TPM failed.", false);
			msgBox.dispose();
			frame.dispose();
		}

	}

}
