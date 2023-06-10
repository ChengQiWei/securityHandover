/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.test.tsp.java.identity.split;

import iaik.tc.tss.api.constants.tpm.TcTpmConstants;
import iaik.tc.tss.api.constants.tsp.TcTssConstants;
import iaik.tc.tss.test.tsp.java.TestCommon;

public class Constants {

	/**
	 * Enable this flag to be compatibility with the TrouSerS 1.1 TSS. Note: Experimental. Use at your
	 * own risk.
	 */
	public static boolean TROUSERS_COMPATIBILITY = false;

	
	/**
	 * Key length used for CA keys.
	 */
	public static final int CA_KEY_LENGTH = 512; // TCG recommends 2048; smaller keys speed up testing...

	/**
	 * Parameters for symmetric encryption algorithm.
	 */
	public static final long SYM_ALGO = TcTssConstants.TSS_ALG_AES; // AES, AES128, AES192, AES256, 3DES

	// note: for TrouSerS only use AES

	public static long SYM_ALGO_TSS; // do not change manually

	public static String SYM_ALGO_JAVA; // do not change manually

	public static long SYM_KEY_LEN; // do not change manually

	public static long SYM_BLOCK_SIZE; // do not change manually

	public static long SYM_IV_LEN; // do not change manually

	
	static {
		switch ((int) SYM_ALGO) {
			case (int) TcTssConstants.TSS_ALG_3DES:
				SYM_ALGO_TSS = TcTpmConstants.TPM_ALG_3DES;
				SYM_ALGO_JAVA = "DESede";
				SYM_KEY_LEN = 192;
				SYM_BLOCK_SIZE = 64;
				SYM_IV_LEN = SYM_BLOCK_SIZE;
				break;

			case (int) TcTssConstants.TSS_ALG_AES128:
				// note: ALG_AES is the same as AES_128
				SYM_ALGO_TSS = TcTpmConstants.TPM_ALG_AES128;
				SYM_ALGO_JAVA = "AES";
				SYM_KEY_LEN = 128;
				SYM_BLOCK_SIZE = 128;
				SYM_IV_LEN = SYM_BLOCK_SIZE;
				break;

			case (int) TcTssConstants.TSS_ALG_AES192:
				SYM_ALGO_TSS = TcTpmConstants.TPM_ALG_AES192;
				SYM_ALGO_JAVA = "AES";
				SYM_KEY_LEN = 192;
				SYM_BLOCK_SIZE = 128;
				SYM_IV_LEN = SYM_BLOCK_SIZE;
				break;

			case (int) TcTssConstants.TSS_ALG_AES256:
				SYM_ALGO_TSS = TcTpmConstants.TPM_ALG_AES256;
				SYM_ALGO_JAVA = "AES";
				SYM_KEY_LEN = 256;
				SYM_BLOCK_SIZE = 128;
				SYM_IV_LEN = SYM_BLOCK_SIZE;
				break;

			default:
				break;
		}

	}

	
}
