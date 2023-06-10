/**
 * Implements test cases for usage of the monotonic counter timing schemes
 * ATTENTION: This hardware feature is only supported from TPM 1.2 on.
 */
package iaik.tc.tss.test.tsp.java.timestamping;

import iaik.tc.tss.api.tspi.TcIHash;
import iaik.tc.tss.api.tspi.TcIRsaKey;
import iaik.tc.tss.api.tspi.TcITpm;
import iaik.tc.tss.test.tsp.java.TestCommon;
import iaik.tc.tss.test.tsp.java.TestDefines;

import java.math.BigInteger;
import java.util.Random;

import iaik.tc.tss.api.constants.tsp.TcTssConstants;
import iaik.tc.tss.api.exceptions.common.TcTssException;
import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.tss.api.structs.tpm.TcTpmCurrentTicks;
import iaik.tc.tss.api.structs.tsp.TcTssValidation;
import iaik.tc.tss.api.structs.tsp.TcTssVersion;
import iaik.tc.utils.logging.Log;


/**
 * @author rtoegl
 *
 */
public class TestTimeStamping extends TestCommon {

	/**
	 * Tests reading out the current ticks from TPM
	 * 
	 */
	public void testReadCurrentTicks() throws Exception
	{
		TcITpm tpm = context_.getTpmObject();
				
		//Run the test
		
		TcTpmCurrentTicks first  = tpm.readCurrentTicks();
		Thread.sleep(10000);
		TcTpmCurrentTicks second = tpm.readCurrentTicks();
		  	
		BigInteger firstTime=first.getCurrentTicks();
		BigInteger secondTime=second.getCurrentTicks();

		

		//IFX hardware and TPM emu always return the same nonce...
		//assertFalse (first.getTickNonce().equals(second.getTickNonce()));
		
		assertFalse(firstTime.equals(secondTime));
		assertTrue(secondTime.compareTo(firstTime) > 0);
		
	}

/**
 * Tests if this a 1.2 TPM and not ETH Zurich's emulator, which has in its current version (0.5) problems with time stamping
 * @return
 * @throws TcTssException
 */
	private boolean isTpmReal1_2() throws TcTssException {
		
		TcITpm tpm = context_.getTpmObject();
		
		try{
			//Should only work on a 1.2 TPM
			TcTssVersion tpmVersion = tpm.getCapabilityVersion(TcTssConstants.TSS_TPMCAP_VERSION_VAL, null);
		
			//just to make sure
			if (!TcTssVersion.TPM_V1_2.equalsMinMaj(tpmVersion)) 
			{
				return false;
			}
			
			if (tpmManufactuerIs(TPM_MAN_ETHZ))
			{
				return false;
			}
			
			return true;
					
		} catch (Exception e)
		{	//in this case it is most likely a 1.1 TPM
			
		}
		return false;
	}
	
	
	/** Tests the time stamping functionality
	 */
	public void testTicksStampHash() throws Exception
	{
						
		if (!isTpmReal1_2())
		{
			Log.warn("Skipped Test, because feature is not supported by the available TPM.");
			return;
		}
		
		TcITpm tpm = context_.getTpmObject();
		
		TcIRsaKey signKey = context_.createRsaKeyObject( //
				TcTssConstants.TSS_KEY_SIZE_2048 | //
						TcTssConstants.TSS_KEY_TYPE_SIGNING | //
						TcTssConstants.TSS_KEY_MIGRATABLE | //
						TcTssConstants.TSS_KEY_AUTHORIZATION);

		// set secret for signing key
		TestDefines.keyUsgPolicy.assignToObject(signKey);
		TestDefines.keyMigPolicy.assignToObject(signKey);

		// create singing key and load it
		signKey.createKey(srk_, null);
		signKey.loadKey(srk_);
		
		Random rnd = new Random();
		int nonce = rnd.nextInt();
		nonce = nonce * Integer.signum(nonce); //must be a positive value for translation into a blob
		TcBlobData validationDataBlob = TcBlobData.newUINT32(nonce).sha1();
		TcTssValidation validationData = new TcTssValidation();
		validationData.setExternalData(validationDataBlob);
		
		TcIHash hash = context_.createHashObject(TcTssConstants.TSS_HASH_SHA1);
		TcBlobData data = TcBlobData.newString("Hello World");
		hash.setHashValue(data.sha1()); 
		Object[] results = hash.tickStampBlob(signKey, validationData);
			
		TcTssValidation returnedValidation = (TcTssValidation) results[0];
		TcTpmCurrentTicks currentTicks = (TcTpmCurrentTicks) results[1];
		

	}
	
}
