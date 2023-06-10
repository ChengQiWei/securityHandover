/*
 * Copyright (C) 2011 IAIK, Graz University of Technology
 * authors: Robert Stoegbuchner
 */

package iaik.tc.tss.test.tsp.java.simple;


import iaik.tc.tss.api.constants.tsp.TcTssConstants;
import iaik.tc.tss.api.exceptions.common.TcTssException;
import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.tss.api.tspi.TcIContext;
import iaik.tc.tss.api.tspi.TcIPcrComposite;
import iaik.tc.tss.api.tspi.TcIPolicy;
import iaik.tc.tss.api.tspi.TcIRsaKey;
import iaik.tc.tss.api.tspi.TcITpm;
import iaik.tc.tss.api.tspi.TcTssContextFactory;
import iaik.tc.utils.misc.Utils;

import java.awt.Frame;
import java.util.Vector;

public class TestWinDenyCommand implements SimpleTest {

	protected TcIContext context_ = null;
	protected TcIRsaKey srk_ = null;
	
	/**
	 * A simple test tests the Windows settings
	 * Tries to quote the PCR
	 * If this fails it's very likely that the windows 
	 * "ignore default list of blocked TPM commands" is not set.
	 */
	public void runTest() {
		
		Vector<String> msgs = new Vector<String>();
		try {
			//get the context via the factory and connect to it
			context_ = new TcTssContextFactory().newContextObject();
			context_.connect();
			//srk_ = context_.getKeyByUuid(TcTssConstants.TSS_PS_TYPE_SYSTEM,
			//		TcUuidFactory.getInstance().getUuidSRK());
			TcIRsaKey srk_ = context_.createRsaKeyObject(TcTssConstants.TSS_KEY_TSP_SRK);

			try {
				// set SRK policy
				TcIPolicy srkPolicy = context_.createPolicyObject(TcTssConstants.TSS_POLICY_USAGE);
				srkPolicy.setSecret(TcTssConstants.TSS_SECRET_MODE_SHA1, 
						TcBlobData.newByteArray(TcTssConstants.TSS_WELL_KNOWN_SECRET));
				srkPolicy.assignToObject(srk_);
			} catch (TcTssException e) {
				e.printStackTrace();
			}
				
			TcIRsaKey key = context_.createRsaKeyObject(TcTssConstants.TSS_KEY_TYPE_SIGNING 
					| TcTssConstants.TSS_KEY_AUTHORIZATION);
			
			// setup key policy for testing
			TcIPolicy keyUsgPolicy = context_.createPolicyObject(TcTssConstants.TSS_POLICY_USAGE);
			keyUsgPolicy.setSecret(TcTssConstants.TSS_SECRET_MODE_PLAIN, TcBlobData.newString("keySecret"));
			TcIPolicy keyMigPolicy = context_.createPolicyObject(TcTssConstants.TSS_POLICY_MIGRATION);	
			keyMigPolicy.setSecret(TcTssConstants.TSS_SECRET_MODE_PLAIN, TcBlobData.newString("keySecret"));
			keyUsgPolicy.assignToObject(key);
			keyMigPolicy.assignToObject(key);
			
			key.createKey(srk_, null);
			key.loadKey(srk_);

			TcIPcrComposite pcrComp = context_.createPcrCompositeObject(TcTssConstants.TSS_PCRS_STRUCT_INFO);
			pcrComp.selectPcrIndex(1);
			pcrComp.selectPcrIndex(10);

			TcITpm tpm = context_.getTpmObject();
			
			//This command might be blocked!
			tpm.quote(key, pcrComp, null);

			//If the PCR values are needed for validation they must be fetched manually.
			pcrComp.setPcrValue(1, tpm.pcrRead(1));
			pcrComp.setPcrValue(10, tpm.pcrRead(10));
			
			key.unloadKey();

			// close the context
			context_.closeContext();
			

			Frame frame = new Frame("Quote PCR Value");
			String msg0 = new String("TPM command do not appear to be blocked!");
			MsgBox msgBox = new MsgBox(frame, msg0, false);

			if (msgBox.isOk) {
				msgBox.dispose();
				frame.dispose();
			}
			
		} catch (TcTssException e) {
			
			if (e.getErrOsSpeific()==0)
				{
				e.printStackTrace();
				}
			
			Frame frame = new Frame("jTSS Test");
			msgs.addElement("The communication with the TPM failed. " + Utils.getNL() + Utils.getNL()); 
			msgs.addElement("If this test is the only one failing note that the " + Utils.getNL());
			msgs.addElement("default configuration of Windows blocks some TPM commands " + Utils.getNL());
			msgs.addElement("for quoting and PCR access in the group policies. " + Utils.getNL());
			msgs.addElement("Take a look at the jTSS documentation to solve this problem.");
			MsgBox msgBox = new MsgBox(frame,"Error" ,msgs, false);
			msgBox.dispose();
			frame.dispose();
		}
	}
}
