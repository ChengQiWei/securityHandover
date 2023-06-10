/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.impl.java.tsp;


import iaik.tc.tss.api.constants.tpm.TcTpmConstants;
import iaik.tc.tss.api.constants.tsp.TcTssConstants;
import iaik.tc.tss.api.constants.tsp.TcTssErrors;
import iaik.tc.tss.api.exceptions.tsp.TcTspException;
import iaik.tc.tss.api.structs.tpm.TcITpmKeyNew;
import iaik.tc.tss.api.structs.tpm.TcTpmKey12New;
import iaik.tc.tss.api.structs.tpm.TcTpmKeyNew;
import iaik.tc.tss.api.structs.tpm.TcTpmKeyParms;
import iaik.tc.tss.api.structs.tpm.TcTpmRsaKeyParms;
import iaik.tc.tss.api.structs.tpm.TcTpmStructVer;

public class TcRsaKeyTemplates {

	private TcRsaKeyTemplates()
	{
	}


	protected static TcITpmKeyNew getEmptyKeyTemplate(long structVer)
		throws TcTspException
	{
		if (structVer != TcTssConstants.TSS_KEY_STRUCT_KEY12
				&& structVer != TcTssConstants.TSS_KEY_STRUCT_KEY) {
			throw new TcTspException(TcTssErrors.TSS_E_BAD_PARAMETER, "Unknown struct version.");
		}

		TcTpmRsaKeyParms rsaKeyParms = new TcTpmRsaKeyParms();
		rsaKeyParms.setExponent(null); // using default
		rsaKeyParms.setNumPrimes(2);
		rsaKeyParms.setKeyLength(2048);

		TcTpmKeyParms algorithmParms = new TcTpmKeyParms();
		algorithmParms.setAlgorithmID(TcTpmConstants.TPM_ALG_RSA);
		algorithmParms.setEncScheme(TcTpmConstants.TPM_ES_NONE);
		algorithmParms.setSigScheme(TcTpmConstants.TPM_SS_NONE);
		algorithmParms.setParms(rsaKeyParms.getEncoded());
		
		TcITpmKeyNew keyInfo = null;
		if (structVer == TcTssConstants.TSS_KEY_STRUCT_KEY12) {
			keyInfo = new TcTpmKey12New();
			((TcTpmKey12New) keyInfo).setTag(TcTpmConstants.TPM_TAG_KEY12);
			((TcTpmKey12New) keyInfo).setFill(0);
		} else {
			keyInfo = new TcTpmKeyNew();
			((TcTpmKeyNew) keyInfo).setVer(TcTpmStructVer.TPM_V1_1);
		}
		// keyInfo.setKeyUsage(TcTpmConstants.TPM_KEY_XXX); // set up in specific templates
		keyInfo.setKeyFlags(0);
		keyInfo.setAuthDataUsage(TcTpmConstants.TPM_AUTH_NEVER); // default according to TSS_1_2_EA 54
		keyInfo.setAlgorithmParms(algorithmParms);
		keyInfo.setPcrInfo(null);
		keyInfo.setEncData(null);
		keyInfo.setPubKey(null);

		return keyInfo;
	}

	
	// Note: For key flag definitions see TPM Spec Part 2 (101) p31 (TPM_KEY_USAGE values)

	protected static TcITpmKeyNew getBindKeyTemplate(long structVer) throws TcTspException
	{
		TcITpmKeyNew retVal = getEmptyKeyTemplate(structVer);
		retVal.getAlgorithmParms().setEncScheme(TcTpmConstants.TPM_ES_RSAESOAEP_SHA1_MGF1);
		// ES alternatives: TPM_ES_RSAESPKCSV15
		retVal.getAlgorithmParms().setSigScheme(TcTpmConstants.TPM_SS_NONE);
		retVal.setKeyUsage(TcTpmConstants.TPM_KEY_BIND);
		
		return retVal;
	}


	protected static TcITpmKeyNew getSigningKeyTemplate(long structVer) throws TcTspException
	{
		TcITpmKeyNew retVal = getEmptyKeyTemplate(structVer);
		retVal.getAlgorithmParms().setEncScheme(TcTpmConstants.TPM_ES_NONE);
		retVal.getAlgorithmParms().setSigScheme(TcTpmConstants.TPM_SS_RSASSAPKCS1v15_SHA1); 
		// SS alternatives: TPM_SS_RSASSAPKCS1v15_DER, TPM_SS_RSASSAPKCS1v15_INFO
		retVal.setKeyUsage(TcTpmConstants.TPM_KEY_SIGNING);
		
		return retVal;
	}


	// can perform signing and binding
	protected static TcITpmKeyNew getLegacyKeyTemplate(long structVer) throws TcTspException
	{
		TcITpmKeyNew retVal = getEmptyKeyTemplate(structVer);
		retVal.getAlgorithmParms().setEncScheme(TcTpmConstants.TPM_ES_RSAESOAEP_SHA1_MGF1);
		// ES alternatives: TPM_ES_RSAESPKCSV15
		retVal.getAlgorithmParms().setSigScheme(TcTpmConstants.TPM_SS_RSASSAPKCS1v15_SHA1); 
		// SS alternatives: TPM_SS_RSASSAPKCS1v15_DER
		retVal.setKeyUsage(TcTpmConstants.TPM_KEY_LEGACY);

		return retVal;
	}


	protected static TcITpmKeyNew getAuthChangeKeyTemplate(long structVer) throws TcTspException
	{
		TcITpmKeyNew retVal = getEmptyKeyTemplate(structVer);
		retVal.getAlgorithmParms().setEncScheme(TcTpmConstants.TPM_ES_RSAESOAEP_SHA1_MGF1);
		retVal.getAlgorithmParms().setSigScheme(TcTpmConstants.TPM_SS_NONE);
		retVal.setKeyUsage(TcTpmConstants.TPM_KEY_AUTHCHANGE);

		return retVal;
	}


	protected static TcITpmKeyNew getIdentityKeyTemplate(long structVer) throws TcTspException
	{
		TcITpmKeyNew retVal = getEmptyKeyTemplate(structVer);
		retVal.getAlgorithmParms().setEncScheme(TcTpmConstants.TPM_ES_NONE);
		retVal.getAlgorithmParms().setSigScheme(TcTpmConstants.TPM_SS_RSASSAPKCS1v15_SHA1);
		retVal.setKeyUsage(TcTpmConstants.TPM_KEY_IDENTITY);

		return retVal;
	}


	public static TcITpmKeyNew getStorageKeyTemplate(long structVer) throws TcTspException
	{
		TcITpmKeyNew retVal = getEmptyKeyTemplate(structVer);
		
		retVal.getAlgorithmParms().setEncScheme(TcTpmConstants.TPM_ES_RSAESOAEP_SHA1_MGF1);
		retVal.getAlgorithmParms().setSigScheme(TcTpmConstants.TPM_SS_NONE);
		retVal.setKeyUsage(TcTpmConstants.TPM_KEY_STORAGE);

		return retVal;
	}


	protected static TcITpmKeyNew getMigrateKeyTemplate(long structVer) throws TcTspException
	{
		TcITpmKeyNew retVal = getEmptyKeyTemplate(structVer);
		retVal.getAlgorithmParms().setEncScheme(TcTpmConstants.TPM_ES_RSAESOAEP_SHA1_MGF1);
		retVal.getAlgorithmParms().setSigScheme(TcTpmConstants.TPM_SS_NONE);
		retVal.setKeyUsage(TcTpmConstants.TPM_KEY_MIGRATE);

		return retVal;
	}

}
