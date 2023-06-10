/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.impl.java.tsp;


import iaik.tc.tss.api.constants.tpm.TcTpmConstants;
import iaik.tc.tss.api.constants.tsp.TcTssConstants;
import iaik.tc.tss.api.constants.tsp.TcTssErrors;
import iaik.tc.tss.api.exceptions.tsp.TcTspException;
import iaik.tc.tss.api.structs.common.TcBasicTypeDecoder;
import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.utils.misc.CheckPrecondition;

import java.util.HashMap;
import java.util.Map;

public class TcConstantsMappings {

	/**
	 * This class implements a bidirectional or reversible map allowing lookups in both directions.
	 * TCG defines numerous constants at TPM and TSS level. These constants have to be translated
	 * either to their TPM or TSS value depending on the direction of a call.
	 */
	protected static class ReversibleMap {

		/**
		 * Map holding TSS to TPM value mappings.
		 */
		private Map tssToTpm = new HashMap();

		/**
		 * Map holding TPM to TSS value mappings.
		 */
		private Map tpmToTss = new HashMap();


		/**
		 * This method adds a key (TSS constant) value (TPM constant) pair to the map.
		 */
		public synchronized void put(long tssVal, long tpmVal)
		{
			tssToTpm.put(new Long(tssVal), new Long(tpmVal));
			tpmToTss.put(new Long(tpmVal), new Long(tssVal));
		}


		/**
		 * This method takes a TSS UINT32 constant, looks it up in the internal data structure and (if
		 * found) returns the corresponding TPM constant.
		 */
		public synchronized TcBlobData getTpmForTssVal(TcBlobData tssValbUINT32) throws TcTspException
		{
			CheckPrecondition.notNull(tssValbUINT32, "tssValbUINT32");
			long val = (new TcBasicTypeDecoder(tssValbUINT32).decodeUINT32());
			TcBlobData retVal = TcBlobData.newUINT32(((Long) tssToTpm.get(new Long(val))).longValue());
			if (retVal == null) {
				throw new TcTspException(TcTssErrors.TSS_E_INTERNAL_ERROR,
						"Unable to find TPM value for given TSS value (" + tssValbUINT32 + ").");
			}
			return retVal;
		}


		/**
		 * This method takes a TPM UINT32 constant, looks it up in the internal data structure and (if
		 * found) returns the corresponding TSS constant.
		 */
		public synchronized TcBlobData getTssForTpmVal(TcBlobData tpmValUINT32) throws TcTspException
		{
			CheckPrecondition.notNull(tpmValUINT32, "tpmValUINT32");
			long val = (new TcBasicTypeDecoder(tpmValUINT32).decodeUINT32());
			TcBlobData retVal = TcBlobData.newUINT32(((Long) tpmToTss.get(new Long(val))).longValue());
			if (retVal == null) {
				throw new TcTspException(TcTssErrors.TSS_E_INTERNAL_ERROR,
						"Unable to find TSS value for given TPM value (" + tpmValUINT32 + ").");
			}
			return retVal;
		}


		/**
		 * This method takes a TSS long constant, looks it up in the internal data structure and (if
		 * found) returns the corresponding TPM constant.
		 */
		public synchronized long getTpmForTssVal(long tssVal) throws TcTspException
		{
			Long retVal = (Long) tssToTpm.get(new Long(tssVal));
			if (retVal == null) {
				throw new TcTspException(TcTssErrors.TSS_E_INTERNAL_ERROR,
						"Unable to find TPM value for given TSS value (" + tssVal + ").");
			}
			return retVal.longValue();
		}


		/**
		 * This method takes a TPM long constant, looks it up in the internal data structure and (if
		 * found) returns the corresponding TSS constant.
		 */
		public synchronized long getTssForTpmVal(long tpmVal) throws TcTspException
		{
			Long retVal = (Long) tpmToTss.get(new Long(tpmVal));
			if (retVal == null) {
				throw new TcTspException(TcTssErrors.TSS_E_INTERNAL_ERROR,
						"Unable to find TSS value for given TPM value (" + tpmVal + ").");
			}
			return retVal.longValue();
		}
	}

	// ----------------------------------------------------------------------------------------------

	/**
	 * Map holding property mappings.
	 */
	protected static ReversibleMap propMap = new ReversibleMap();

	/**
	 * Map holding algorithm ID mappings.
	 */
	protected static ReversibleMap algMap = new ReversibleMap();

	/**
	 * Map holding resource type mappings.
	 */
	protected static ReversibleMap rtMap = new ReversibleMap();

	/**
	 * Map holding encryption scheme mappings.
	 */
	protected static ReversibleMap esMap = new ReversibleMap();

	/**
	 * Map holding encryption signature mappings.
	 */
	protected static ReversibleMap ssMap = new ReversibleMap();

	/**
	 * Map holding encryption key usage mappings.
	 */
	protected static ReversibleMap keyUsageMap = new ReversibleMap();
	
	/**
	 * Map holding migration scheme mappings.
	 */
	protected static ReversibleMap msMap = new ReversibleMap();

	/*
	 * Synchronization Note: Access to the maps is not synchronized since they are
	 * filled in a static block and after that only are accessed read only.  
	 */
	static {
		propMap.put(TcTssConstants.TSS_TPMCAP_PROP_PCR, TcTpmConstants.TPM_CAP_PROP_PCR);
		propMap.put(TcTssConstants.TSS_TPMCAP_PROP_DIR, TcTpmConstants.TPM_CAP_PROP_DIR);
		propMap.put(TcTssConstants.TSS_TPMCAP_PROP_MANUFACTURER,
				TcTpmConstants.TPM_CAP_PROP_MANUFACTURER);
		propMap.put(TcTssConstants.TSS_TPMCAP_PROP_SLOTS, TcTpmConstants.TPM_CAP_PROP_SLOTS);
		// TODO: missing in the TSS spec
		// propMap.put(TcTssConstants.TSS_TPMCAP_PROP_MIN_COUNTER,
		// TcTpmConstants.TPM_CAP_PROP_MIN_COUNTER);
		propMap.put(TcTssConstants.TSS_TPMCAP_PROP_FAMILYROWS, TcTpmConstants.TPM_CAP_PROP_FAMILYROWS);
		propMap.put(TcTssConstants.TSS_TPMCAP_PROP_DELEGATEROWS,
				TcTpmConstants.TPM_CAP_PROP_DELEGATE_ROW);
		propMap.put(TcTssConstants.TSS_TPMCAP_PROP_OWNER, TcTpmConstants.TPM_CAP_PROP_OWNER);
		propMap.put(TcTssConstants.TSS_TPMCAP_PROP_MAXKEYS, TcTpmConstants.TPM_CAP_PROP_MAX_KEYS);
		propMap.put(TcTssConstants.TSS_TPMCAP_PROP_AUTHSESSIONS, TcTpmConstants.TPM_CAP_PROP_AUTHSESS);
		propMap.put(TcTssConstants.TSS_TPMCAP_PROP_MAXAUTHSESSIONS,
				TcTpmConstants.TPM_CAP_PROP_MAX_AUTHSESS);
		propMap.put(TcTssConstants.TSS_TPMCAP_PROP_TRANSESSIONS, TcTpmConstants.TPM_CAP_PROP_TRANSSESS);
		propMap.put(TcTssConstants.TSS_TPMCAP_PROP_MAXTRANSESSIONS,
				TcTpmConstants.TPM_CAP_PROP_MAX_TRANSSESS);
		propMap.put(TcTssConstants.TSS_TPMCAP_PROP_SESSIONS, TcTpmConstants.TPM_CAP_PROP_SESSIONS);
		propMap.put(TcTssConstants.TSS_TPMCAP_PROP_MAXSESSIONS,
				TcTpmConstants.TPM_CAP_PROP_MAX_SESSIONS);
		propMap.put(TcTssConstants.TSS_TPMCAP_PROP_CONTEXTS, TcTpmConstants.TPM_CAP_PROP_CONTEXT);
		propMap
				.put(TcTssConstants.TSS_TPMCAP_PROP_MAXCONTEXTS, TcTpmConstants.TPM_CAP_PROP_MAX_CONTEXT);
		propMap.put(TcTssConstants.TSS_TPMCAP_PROP_DAASESSIONS, TcTpmConstants.TPM_CAP_PROP_DAA_SESS);
		propMap.put(TcTssConstants.TSS_TPMCAP_PROP_MAXDAASESSIONS, TcTpmConstants.TPM_CAP_PROP_DAA_MAX);
		propMap.put(TcTssConstants.TSS_TPMCAP_PROP_DAA_INTERRUPT,
				TcTpmConstants.TPM_CAP_PROP_DAA_INTERRUPT);
		propMap.put(TcTssConstants.TSS_TPMCAP_PROP_COUNTERS, TcTpmConstants.TPM_CAP_PROP_COUNTERS);
		propMap.put(TcTssConstants.TSS_TPMCAP_PROP_MAXCOUNTERS,
				TcTpmConstants.TPM_CAP_PROP_MAX_COUNTERS);
		propMap.put(TcTssConstants.TSS_TPMCAP_PROP_ACTIVECOUNTER,
				TcTpmConstants.TPM_CAP_PROP_ACTIVE_COUNTER);
		propMap
				.put(TcTssConstants.TSS_TPMCAP_PROP_TISTIMEOUTS, TcTpmConstants.TPM_CAP_PROP_TIS_TIMEOUT);
		propMap.put(TcTssConstants.TSS_TPMCAP_PROP_STARTUPEFFECTS,
				TcTpmConstants.TPM_CAP_PROP_STARTUP_EFFECT);
		propMap.put(TcTssConstants.TSS_TPMCAP_PROP_MAXCONTEXTCOUNTDIST,
				TcTpmConstants.TPM_CAP_PROP_CONTEXT_DIST);
		propMap.put(TcTssConstants.TSS_TPMCAP_PROP_CMKRESTRICTION,
				TcTpmConstants.TPM_CAP_PROP_CMK_RESTRICTION);
		propMap.put(TcTssConstants.TSS_TPMCAP_PROP_DURATION, TcTpmConstants.TPM_CAP_PROP_DURATION);
		propMap.put(TcTssConstants.TSS_TPMCAP_PROP_MAXNVAVAILABLE,
				TcTpmConstants.TPM_CAP_PROP_MAX_NV_AVAILABLE);
		propMap.put(TcTssConstants.TSS_TPMCAP_PROP_INPUTBUFFERSIZE,
				TcTpmConstants.TPM_CAP_PROP_INPUT_BUFFER);
		// TODO: missing in the TSS and TPM spec
		// propMap.put(TcTssConstants.TSS_TPMCAP_PROP_MAXNVWRITE,
		// TcTpmConstants.TPM_CAP_PROP_MAX_NV_WRITE);
		// TODO: missing in the TPM spec
		// propMap.put(TcTssConstants.TSS_TPMCAP_PROP_REVISION,
		// TcTpmConstants.TPM_CAP_PROP_REVISION);
		// propMap.put(TcTssConstants.TSS_TPMCAP_PROP_LOCALITIES_AVAIL,
		// TcTpmConstants.TPM_CAP_PROP_LOCALITIES_AVAIL);

		// ---------------------

		algMap.put(TcTssConstants.TSS_ALG_AES, TcTpmConstants.TPM_ALG_AES);
		algMap.put(TcTssConstants.TSS_ALG_AES128, TcTpmConstants.TPM_ALG_AES128);
		algMap.put(TcTssConstants.TSS_ALG_AES192, TcTpmConstants.TPM_ALG_AES192);
		algMap.put(TcTssConstants.TSS_ALG_AES256, TcTpmConstants.TPM_ALG_AES256);
		algMap.put(TcTssConstants.TSS_ALG_DES, TcTpmConstants.TPM_ALG_DES);
		algMap.put(TcTssConstants.TSS_ALG_3DES, TcTpmConstants.TPM_ALG_3DES);
		algMap.put(TcTssConstants.TSS_ALG_HMAC, TcTpmConstants.TPM_ALG_HMAC);
		algMap.put(TcTssConstants.TSS_ALG_MGF1, TcTpmConstants.TPM_ALG_MGF1);
		algMap.put(TcTssConstants.TSS_ALG_RSA, TcTpmConstants.TPM_ALG_RSA);
		algMap.put(TcTssConstants.TSS_ALG_SHA, TcTpmConstants.TPM_ALG_SHA);
		algMap.put(TcTssConstants.TSS_ALG_XOR, TcTpmConstants.TPM_ALG_XOR);

		// ---------------------

		rtMap.put(TcTssConstants.TSS_RT_AUTH, TcTpmConstants.TPM_RT_AUTH);
		rtMap.put(TcTssConstants.TSS_RT_COUNTER, TcTpmConstants.TPM_RT_COUNTER);
		rtMap.put(TcTssConstants.TSS_RT_KEY, TcTpmConstants.TPM_RT_KEY);
		rtMap.put(TcTssConstants.TSS_RT_TRANS, TcTpmConstants.TPM_RT_TRANS);

		// ---------------------

		esMap.put(TcTssConstants.TSS_ES_NONE, TcTpmConstants.TPM_ES_NONE);
		esMap.put(TcTssConstants.TSS_ES_RSAESOAEP_SHA1_MGF1, TcTpmConstants.TPM_ES_RSAESOAEP_SHA1_MGF1);
		esMap.put(TcTssConstants.TSS_ES_RSAESPKCSV15, TcTpmConstants.TPM_ES_RSAESPKCSv15);
		esMap.put(TcTssConstants.TSS_ES_SYM_CBC_PKCS5PAD, TcTpmConstants.TPM_ES_SYM_CBC_PKCS5PAD);
		esMap.put(TcTssConstants.TSS_ES_SYM_CNT, TcTpmConstants.TPM_ES_SYM_CNT);
		esMap.put(TcTssConstants.TSS_ES_SYM_OFB, TcTpmConstants.TPM_ES_SYM_OFB);

		// ---------------------

		ssMap.put(TcTssConstants.TSS_SS_NONE, TcTpmConstants.TPM_SS_NONE);
		ssMap.put(TcTssConstants.TSS_SS_RSASSAPKCS1V15_DER, TcTpmConstants.TPM_SS_RSASSAPKCS1v15_DER);
		ssMap.put(TcTssConstants.TSS_SS_RSASSAPKCS1V15_SHA1, TcTpmConstants.TPM_SS_RSASSAPKCS1v15_SHA1);
		ssMap.put(TcTssConstants.TSS_SS_RSASSAPKCS1V15_INFO, TcTpmConstants.TPM_SS_RSASSAPKCS1v15_INFO);
		

		// ---------------------

		keyUsageMap.put(TcTssConstants.TSS_KEYUSAGE_AUTHCHANGE, TcTpmConstants.TPM_KEY_AUTHCHANGE);
		keyUsageMap.put(TcTssConstants.TSS_KEYUSAGE_BIND, TcTpmConstants.TPM_KEY_BIND);
		keyUsageMap.put(TcTssConstants.TSS_KEYUSAGE_IDENTITY, TcTpmConstants.TPM_KEY_IDENTITY);
		keyUsageMap.put(TcTssConstants.TSS_KEYUSAGE_LEGACY, TcTpmConstants.TPM_KEY_LEGACY);
		keyUsageMap.put(TcTssConstants.TSS_KEYUSAGE_MIGRATE, TcTpmConstants.TPM_KEY_MIGRATE);
		keyUsageMap.put(TcTssConstants.TSS_KEYUSAGE_SIGN, TcTpmConstants.TPM_KEY_SIGNING);
		keyUsageMap.put(TcTssConstants.TSS_KEYUSAGE_STORAGE, TcTpmConstants.TPM_KEY_STORAGE);
	
		// ---------------------

		msMap.put(TcTssConstants.TSS_MS_MIGRATE, TcTpmConstants.TPM_MS_MIGRATE);
		msMap.put(TcTssConstants.TSS_MS_REWRAP, TcTpmConstants.TPM_MS_REWRAP);
		msMap.put(TcTssConstants.TSS_MS_MAINT, TcTpmConstants.TPM_MS_MAINT);
		msMap.put(TcTssConstants.TSS_MS_RESTRICT_MIGRATE, TcTpmConstants.TPM_MS_RESTRICT_MIGRATE);
		msMap.put(TcTssConstants.TSS_MS_RESTRICT_MIGRATE_EXTERNAL, TcTpmConstants.TPM_MS_RESTRICT_MIGRATE_EXTERNAL);
		msMap.put(TcTssConstants.TSS_MS_RESTRICT_APPROVE_DOUBLE, TcTpmConstants.TPM_MS_RESTRICT_APPROVE_DOUBLE);
	}
}
