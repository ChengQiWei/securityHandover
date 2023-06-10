/*
 * Copyright (C) 2010 IAIK, Graz University of Technology
 * author: Josef Sabongui
 */


package iaik.tc.tss.test.tsp.java.simple;

import iaik.tc.tss.api.constants.tsp.TcTssConstants;
import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.tss.api.tspi.TcIContext;
import iaik.tc.tss.api.tspi.TcITpm;
import iaik.tc.tss.api.tspi.TcTssContextFactory;
import iaik.tc.utils.misc.Utils;

import java.awt.Frame;
import java.util.Vector;

public class TestReadPcrs implements SimpleTest {

	protected TcIContext context_ = null;

	/**
	 * A simple test which reads the values of the PCRs available
	 * on your TPM and then displays it via a popup window
	 */
	public void runTest() {
		try {
			//get the context via the factory and connect to it 通过工厂获取上下文并连接到它
			context_ = new TcTssContextFactory().newContextObject();
			context_.connect();

			// get the TPM object 
			TcITpm tpm = context_.getTpmObject();
			TcBlobData subCap = TcBlobData.newUINT32((int)TcTssConstants.TSS_TPMCAP_PROP_PCR);

			// get the number of available PCRs from the TPM
			long numPcrs = tpm.getCapabilityUINT32(TcTssConstants.TSS_TPMCAP_PROPERTY, subCap);

			Vector<String> msgs = new Vector<String>();

			for (int i = 0; i < numPcrs; i++) {
				StringBuffer buffer = new StringBuffer();
				if (i < 10) {
					buffer.append("0" + i + ": ");
				} else {
					buffer.append(i + ": ");
				}
				//read the value of the PCR with index i
				TcBlobData pcrValue = tpm.pcrRead(i);

				buffer.append(pcrValue.toHexStringNoWrap());
				buffer.append(Utils.getNL());
				msgs.addElement(buffer.toString());
			}

			// close the context
			context_.closeContext();

			String msg1 = new String("Number of PCRs: "+ numPcrs);

			Frame frame = new Frame("Read PCR Values");
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
