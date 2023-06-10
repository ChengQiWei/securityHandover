/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.impl.java.tcs.pbg;


import iaik.tc.tss.api.constants.tpm.TcTpmConstants;
import iaik.tc.tss.api.constants.tpm.TcTpmOrdinals;
import iaik.tc.tss.api.exceptions.tcs.TcTddlException;
import iaik.tc.tss.api.exceptions.tcs.TcTpmException;
import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.tss.api.structs.tcs.TcTcsAuth;
import iaik.tc.tss.api.structs.tpm.TcTpmAuthdata;
import iaik.tc.tss.api.structs.tpm.TcTpmCmkAuth;
import iaik.tc.tss.api.structs.tpm.TcTpmDigest;
import iaik.tc.tss.api.structs.tpm.TcTpmEncauth;
import iaik.tc.tss.api.structs.tpm.TcTpmGenericReturnBlob;
import iaik.tc.tss.api.structs.tpm.TcTpmKey12;
import iaik.tc.tss.api.structs.tpm.TcTpmMigrationkeyAuth;
import iaik.tc.tss.api.structs.tpm.TcTpmMsaComposite;
import iaik.tc.tss.api.structs.tpm.TcTpmNonce;
import iaik.tc.tss.api.structs.tpm.TcTpmPubkey;
import iaik.tc.tss.impl.java.tddl.TcIStreamDest;

public class TcTpmCmdMigration extends TcTpmCmdCommon {

	/*************************************************************************************************
	 * 
	 * 
	 * @param dest The destination where the byte stream is written to.
	 * @param inAuth1 Authorization values for first authorization session.
	 * @param inAuth2 Authorization values for second authorization session.
	 * @param parentHandle Handle of the parent key that can decrypt encData.
	 * @param migrationType The migration type, either MIGRATE or REWRAP
	 * @param migrationKeyAuth Migration public key and its authorization session digest.
	 * @param encData The encrypted entity that is to be modified.
	 * 
	 * @return The returned Object[] holds the following elements:
	 *         <ul>
	 *         <li> 0 ... TPM return code (Long)
	 *         <li> 1 ... outgoing authorization for 1st session containing new nonceEven (TcTpmAuth)
	 *         <li> 2 ... outgoing authorization for 2nd session containing new nonceEven (TcTpmAuth)
	 *         <li> 3 ... String used for xor encryption (TcBlobData)
	 *         <li> 4 ... The modified, encrypted entity. (TcBlobData)
	 *         </ul>
	 * 
	 * @throws  TcTpmException This exception indicates that a TPM error has occurred. The specific
	 *           error code id held by the exception.
	 * 
	 * @TPM_V2_R101 82
	 */
	public static Object[] TpmCreateMigrationBlob(TcIStreamDest dest, long parentHandle,
			int migrationType, TcTpmMigrationkeyAuth migrationKeyAuth, TcBlobData encData,
			TcTcsAuth inAuth1, TcTcsAuth inAuth2) throws TcTddlException, TcTpmException
	{

		TcBlobData inBlob = blobUINT16(TcTpmConstants.TPM_TAG_RQU_AUTH2_COMMAND);
		inBlob.append(blobUINT32(0)); // paramSize is set later
		inBlob.append(blobUINT32(TcTpmOrdinals.TPM_ORD_CreateMigrationBlob));
		inBlob.append(blobUINT32(parentHandle));
		inBlob.append(blobUINT16(migrationType));
		inBlob.append(migrationKeyAuth.getEncoded());
		inBlob.append(blobUINT32(encData.getLengthAsLong()));
		inBlob.append(encData);
		inBlob.append(blobUINT32(inAuth1.getAuthHandle()));
		inBlob.append(inAuth1.getNonceOdd().getEncoded());
		inBlob.append(blobBOOL(inAuth1.getContAuthSession()));
		inBlob.append(inAuth1.getHmac().getEncoded());
		inBlob.append(blobUINT32(inAuth2.getAuthHandle()));
		inBlob.append(inAuth2.getNonceOdd().getEncoded());
		inBlob.append(blobBOOL(inAuth2.getContAuthSession()));
		inBlob.append(inAuth2.getHmac().getEncoded());

		// all parameters filled in - set the length of the blob
		setParamSize(inBlob);

		// send byte stream
		TcBlobData tpmOutBlob = dest.transmitData(inBlob);
		TcTpmGenericReturnBlob outBlob = new TcTpmGenericReturnBlob(tpmOutBlob);

		// check TPM return code: if call was not successful, an exception is thrown
		try {
			handleRetCode(outBlob);
		} catch (TcTpmException e) {
			invalidataAuthSession(inAuth1);
			invalidataAuthSession(inAuth2);
			throw e;
		}

		// decode output values
		long randomSize = outBlob.decodeUINT32();
		TcBlobData random = outBlob.decodeBytes(randomSize);
		long outDataSize = outBlob.decodeUINT32();
		TcBlobData outData = outBlob.decodeBytes(outDataSize);

		// decode 1st output auth
		TcTcsAuth outAuth1 = new TcTcsAuth();
		outAuth1.setAuthHandle(inAuth1.getAuthHandle());
		outAuth1.setNonceOdd(inAuth1.getNonceOdd());
		outAuth1.setNonceEven(new TcTpmNonce(outBlob)); // new nonce even from TPM
		outAuth1.setContAuthSession(outBlob.decodeBoolean());
		outAuth1.setHmac(new TcTpmAuthdata(outBlob));
		trackAuthSession(inAuth1, outAuth1);

		// decode 2nd output auth
		TcTcsAuth outAuth2 = new TcTcsAuth();
		outAuth2.setAuthHandle(inAuth2.getAuthHandle());
		outAuth2.setNonceOdd(inAuth2.getNonceOdd());
		outAuth2.setNonceEven(new TcTpmNonce(outBlob)); // new nonce even from TPM
		outAuth2.setContAuthSession(outBlob.decodeBoolean());
		outAuth2.setHmac(new TcTpmAuthdata(outBlob));
		trackAuthSession(inAuth2, outAuth2);

		return new Object[] { outBlob.getRetCodeAsLong(), outAuth1, outAuth2, random, outData };
	}


	/*************************************************************************************************
	 * 
	 * 
	 * @param dest The destination where the byte stream is written to.
	 * @param inAuth1 Authorization values for first authorization session.
	 * @param parentHandle Handle of a loaded key that can decrypt keys.
	 * @param inData The XOR'd and encrypted key
	 * @param random Random value used to hide key data.
	 * 
	 * @return The returned Object[] holds the following elements:
	 *         <ul>
	 *         <li> 0 ... TPM return code (Long)
	 *         <li> 1 ... outgoing authorization for session containing new nonceEven (TcTpmAuth)
	 *         <li> 2 ... The encrypted private key that canbe loaded with TPM_LoadKey (TcBlobData)
	 *         </ul>
	 * 
	 * @throws  TcTpmException This exception indicates that a TPM error has occurred. The specific
	 *           error code id held by the exception.
	 * 
	 * @TPM_V2_R101 86
	 */
	public static Object[] TpmConvertMigrationBlob(TcIStreamDest dest, long parentHandle,
			TcBlobData inData, TcBlobData random, TcTcsAuth inAuth1) throws TcTddlException, TcTpmException
	{

		TcBlobData inBlob = blobUINT16(TcTpmConstants.TPM_TAG_RQU_AUTH1_COMMAND);
		inBlob.append(blobUINT32(0)); // paramSize is set later
		inBlob.append(blobUINT32(TcTpmOrdinals.TPM_ORD_ConvertMigrationBlob));
		inBlob.append(blobUINT32(parentHandle));
		inBlob.append(blobUINT32(inData.getLengthAsLong()));
		inBlob.append(inData);
		inBlob.append(blobUINT32(random.getLengthAsLong()));
		inBlob.append(random);
		inBlob.append(blobUINT32(inAuth1.getAuthHandle()));
		inBlob.append(inAuth1.getNonceOdd().getEncoded());
		inBlob.append(blobBOOL(inAuth1.getContAuthSession()));
		inBlob.append(inAuth1.getHmac().getEncoded());

		// all parameters filled in - set the length of the blob
		setParamSize(inBlob);

		// send byte stream
		TcBlobData tpmOutBlob = dest.transmitData(inBlob);
		TcTpmGenericReturnBlob outBlob = new TcTpmGenericReturnBlob(tpmOutBlob);

		// check TPM return code: if call was not successful, an exception is thrown
		try {
			handleRetCode(outBlob);
		} catch (TcTpmException e) {
			invalidataAuthSession(inAuth1);
			throw e;
		}

		// decode output values
		long outDataSize = outBlob.decodeUINT32();
		TcBlobData outData = outBlob.decodeBytes(outDataSize);

		// decode 1st output auth
		TcTcsAuth outAuth1 = new TcTcsAuth();
		outAuth1.setAuthHandle(inAuth1.getAuthHandle());
		outAuth1.setNonceOdd(inAuth1.getNonceOdd());
		outAuth1.setNonceEven(new TcTpmNonce(outBlob)); // new nonce even from TPM
		outAuth1.setContAuthSession(outBlob.decodeBoolean());
		outAuth1.setHmac(new TcTpmAuthdata(outBlob));
		trackAuthSession(inAuth1, outAuth1);

		return new Object[] { outBlob.getRetCodeAsLong(), outAuth1, outData };
	}


	/*************************************************************************************************
	 * 
	 * 
	 * @param dest The destination where the byte stream is written to.
	 * @param inAuth1 Authorization values for first authorization session.
	 * @param migrationScheme Type of migration operation that is to be permitted for this key.
	 * @param migrationKey The public key to be authorized.
	 * 
	 * @return The returned Object[] holds the following elements:
	 *         <ul>
	 *         <li> 0 ... TPM return code (Long)
	 *         <li> 1 ... outgoing authorization for session containing new nonceEven (TcTpmAuth)
	 *         <li> 2 ... Returned public key and authorization session digest.
	 *         (TcTpmMigrationkeyAuth)
	 *         </ul>
	 * 
	 * @throws  TcTpmException This exception indicates that a TPM error has occurred. The specific
	 *           error code id held by the exception.
	 * 
	 * @TPM_V2_R101 88
	 */
	public static Object[] TpmAuthorizeMigrationKey(TcIStreamDest dest, int migrationScheme,
			TcTpmPubkey migrationKey, TcTcsAuth inAuth1) throws TcTddlException, TcTpmException
	{

		TcBlobData inBlob = blobUINT16(TcTpmConstants.TPM_TAG_RQU_AUTH1_COMMAND);
		inBlob.append(blobUINT32(0)); // paramSize is set later
		inBlob.append(blobUINT32(TcTpmOrdinals.TPM_ORD_AuthorizeMigrationKey));
		inBlob.append(blobUINT16(migrationScheme));
		inBlob.append(migrationKey.getEncoded());
		inBlob.append(blobUINT32(inAuth1.getAuthHandle()));
		inBlob.append(inAuth1.getNonceOdd().getEncoded());
		inBlob.append(blobBOOL(inAuth1.getContAuthSession()));
		inBlob.append(inAuth1.getHmac().getEncoded());

		// all parameters filled in - set the length of the blob
		setParamSize(inBlob);

		// send byte stream
		TcBlobData tpmOutBlob = dest.transmitData(inBlob);
		TcTpmGenericReturnBlob outBlob = new TcTpmGenericReturnBlob(tpmOutBlob);

		// check TPM return code: if call was not successful, an exception is thrown
		try {
			handleRetCode(outBlob);
		} catch (TcTpmException e) {
			invalidataAuthSession(inAuth1);
			throw e;
		}

		// decode output values
		TcTpmMigrationkeyAuth outData = new TcTpmMigrationkeyAuth(outBlob);

		// decode 1st output auth
		TcTcsAuth outAuth1 = new TcTcsAuth();
		outAuth1.setAuthHandle(inAuth1.getAuthHandle());
		outAuth1.setNonceOdd(inAuth1.getNonceOdd());
		outAuth1.setNonceEven(new TcTpmNonce(outBlob)); // new nonce even from TPM
		outAuth1.setContAuthSession(outBlob.decodeBoolean());
		outAuth1.setHmac(new TcTpmAuthdata(outBlob));
		trackAuthSession(inAuth1, outAuth1);

		return new Object[] { outBlob.getRetCodeAsLong(), outAuth1, outData };
	}


	/*************************************************************************************************
	 * 
	 * 
	 * @param dest The destination where the byte stream is written to.
	 * @param inAuth1 Authorization values for first authorization session.
	 * @param maKeyHandle Handle of the key to be used to migrate the key.
	 * @param pubKey Public key to which the blob is to be migrated
	 * @param inData The input blob
	 * 
	 * @return The returned Object[] holds the following elements:
	 *         <ul>
	 *         <li> 0 ... TPM return code (Long)
	 *         <li> 1 ... outgoing authorization for session containing new nonceEven (TcTpmAuth)
	 *         <li> 2 ... The re-encrypted blob (TcBlobData)
	 *         </ul>
	 * 
	 * @throws  TcTpmException This exception indicates that a TPM error has occurred. The specific
	 *           error code id held by the exception.
	 * 
	 * @TPM_V2_R101 90
	 */
	public static Object[] TpmMigrateKey(TcIStreamDest dest, long maKeyHandle, TcTpmPubkey pubKey,
			TcBlobData inData, TcTcsAuth inAuth1) throws TcTddlException, TcTpmException
	{

		TcBlobData inBlob = blobUINT16(TcTpmConstants.TPM_TAG_RQU_AUTH1_COMMAND);
		inBlob.append(blobUINT32(0)); // paramSize is set later
		inBlob.append(blobUINT32(TcTpmOrdinals.TPM_ORD_MigrateKey));
		inBlob.append(blobUINT32(maKeyHandle));
		inBlob.append(pubKey.getEncoded());
		inBlob.append(blobUINT32(inData.getLengthAsLong()));
		inBlob.append(inData);
		inBlob.append(blobUINT32(inAuth1.getAuthHandle()));
		inBlob.append(inAuth1.getNonceOdd().getEncoded());
		inBlob.append(blobBOOL(inAuth1.getContAuthSession()));
		inBlob.append(inAuth1.getHmac().getEncoded());

		// all parameters filled in - set the length of the blob
		setParamSize(inBlob);

		// send byte stream
		TcBlobData tpmOutBlob = dest.transmitData(inBlob);
		TcTpmGenericReturnBlob outBlob = new TcTpmGenericReturnBlob(tpmOutBlob);

		// check TPM return code: if call was not successful, an exception is thrown
		try {
			handleRetCode(outBlob);
		} catch (TcTpmException e) {
			invalidataAuthSession(inAuth1);
			throw e;
		}

		// decode output values
		long outDataSize = outBlob.decodeUINT32();
		TcBlobData outData = outBlob.decodeBytes(outDataSize);

		// decode 1st output auth
		TcTcsAuth outAuth1 = new TcTcsAuth();
		outAuth1.setAuthHandle(inAuth1.getAuthHandle());
		outAuth1.setNonceOdd(inAuth1.getNonceOdd());
		outAuth1.setNonceEven(new TcTpmNonce(outBlob)); // new nonce even from TPM
		outAuth1.setContAuthSession(outBlob.decodeBoolean());
		outAuth1.setHmac(new TcTpmAuthdata(outBlob));
		trackAuthSession(inAuth1, outAuth1);

		return new Object[] { outBlob.getRetCodeAsLong(), outAuth1, outData };
	}


	/*************************************************************************************************
	 * 
	 * 
	 * @param dest The destination where the byte stream is written to.
	 * @param inAuth1 Authorization values for first authorization session.
	 * @param restriction The bit mask of how to set the restrictions on CMK keys
	 * 
	 * @return The returned Object[] holds the following elements:
	 *         <ul>
	 *         <li> 0 ... TPM return code (Long)
	 *         <li> 1 ... outgoing authorization for session containing new nonceEven (TcTpmAuth)
	 *         </ul>
	 * 
	 * @throws  TcTpmException This exception indicates that a TPM error has occurred. The specific
	 *           error code id held by the exception.
	 * 
	 * @TPM_V2_R101 92
	 */
	public static Object[] TpmCmkSetRestrictions(TcIStreamDest dest, long restriction,
			TcTcsAuth inAuth1) throws TcTddlException, TcTpmException
	{

		TcBlobData inBlob = blobUINT16(TcTpmConstants.TPM_TAG_RQU_AUTH1_COMMAND);
		inBlob.append(blobUINT32(0)); // paramSize is set later
		inBlob.append(blobUINT32(TcTpmOrdinals.TPM_ORD_CMK_SetRestrictions));
		inBlob.append(blobUINT32(restriction));
		inBlob.append(blobUINT32(inAuth1.getAuthHandle()));
		inBlob.append(inAuth1.getNonceOdd().getEncoded());
		inBlob.append(blobBOOL(inAuth1.getContAuthSession()));
		inBlob.append(inAuth1.getHmac().getEncoded());

		// all parameters filled in - set the length of the blob
		setParamSize(inBlob);

		// send byte stream
		TcBlobData tpmOutBlob = dest.transmitData(inBlob);
		TcTpmGenericReturnBlob outBlob = new TcTpmGenericReturnBlob(tpmOutBlob);

		// check TPM return code: if call was not successful, an exception is thrown
		try {
			handleRetCode(outBlob);
		} catch (TcTpmException e) {
			invalidataAuthSession(inAuth1);
			throw e;
		}

		// decode 1st output auth
		TcTcsAuth outAuth1 = new TcTcsAuth();
		outAuth1.setAuthHandle(inAuth1.getAuthHandle());
		outAuth1.setNonceOdd(inAuth1.getNonceOdd());
		outAuth1.setNonceEven(new TcTpmNonce(outBlob)); // new nonce even from TPM
		outAuth1.setContAuthSession(outBlob.decodeBoolean());
		outAuth1.setHmac(new TcTpmAuthdata(outBlob));
		trackAuthSession(inAuth1, outAuth1);

		return new Object[] { outBlob.getRetCodeAsLong(), outAuth1, };
	}


	/*************************************************************************************************
	 * 
	 * 
	 * @param dest The destination where the byte stream is written to.
	 * @param inAuth1 Authorization values for first authorization session.
	 * @param migrationAuthorityDigest A digest of a TcTpmMsaComposite structure (itself one or more
	 *          digests of public keys belonging to migration authorities)
	 * 
	 * @return The returned Object[] holds the following elements:
	 *         <ul>
	 *         <li> 0 ... TPM return code (Long)
	 *         <li> 1 ... outgoing authorization for session containing new nonceEven (TcTpmAuth)
	 *         <li> 2 ... HMAC of migrationAuthorityDigest (TcTpmDigest)
	 *         </ul>
	 * 
	 * @throws  TcTpmException This exception indicates that a TPM error has occurred. The specific
	 *           error code id held by the exception.
	 * 
	 * @TPM_V2_R101 94
	 */
	public static Object[] TpmCmkApproveMA(TcIStreamDest dest, TcTpmDigest migrationAuthorityDigest,
			TcTcsAuth inAuth1) throws TcTddlException, TcTpmException
	{

		TcBlobData inBlob = blobUINT16(TcTpmConstants.TPM_TAG_RQU_AUTH1_COMMAND);
		inBlob.append(blobUINT32(0)); // paramSize is set later
		inBlob.append(blobUINT32(TcTpmOrdinals.TPM_ORD_CMK_ApproveMA));
		inBlob.append(migrationAuthorityDigest.getEncoded());
		inBlob.append(blobUINT32(inAuth1.getAuthHandle()));
		inBlob.append(inAuth1.getNonceOdd().getEncoded());
		inBlob.append(blobBOOL(inAuth1.getContAuthSession()));
		inBlob.append(inAuth1.getHmac().getEncoded());

		// all parameters filled in - set the length of the blob
		setParamSize(inBlob);

		// send byte stream
		TcBlobData tpmOutBlob = dest.transmitData(inBlob);
		TcTpmGenericReturnBlob outBlob = new TcTpmGenericReturnBlob(tpmOutBlob);

		// check TPM return code: if call was not successful, an exception is thrown
		try {
			handleRetCode(outBlob);
		} catch (TcTpmException e) {
			invalidataAuthSession(inAuth1);
			throw e;
		}

		// decode output values
		TcTpmDigest outData = new TcTpmDigest(outBlob);

		// decode 1st output auth
		TcTcsAuth outAuth1 = new TcTcsAuth();
		outAuth1.setAuthHandle(inAuth1.getAuthHandle());
		outAuth1.setNonceOdd(inAuth1.getNonceOdd());
		outAuth1.setNonceEven(new TcTpmNonce(outBlob)); // new nonce even from TPM
		outAuth1.setContAuthSession(outBlob.decodeBoolean());
		outAuth1.setHmac(new TcTpmAuthdata(outBlob));
		trackAuthSession(inAuth1, outAuth1);

		return new Object[] { outBlob.getRetCodeAsLong(), outAuth1, outData };
	}


	/*************************************************************************************************
	 * 
	 * 
	 * @param dest The destination where the byte stream is written to.
	 * @param inAuth1 Authorization values for first authorization session.
	 * @param parentHandle Handle of a loaded key that can perform key wrapping.
	 * @param dataUsageAuth Encrypted usage AuthData for thesealed data.
	 * @param keyInfo Information about key to be created, pubkey.keyLength and keyInfo.encData
	 *          elements are 0. MUST be TcTpmKey12
	 * @param migrationAuthorityApproval A ticket, created by the TPM Owner using TPM_CMK_ApproveMA,
	 *          approving a TcTpmMsaComposite structure
	 * @param migrationAuthorityDigest The digest of a TcTpmMsaComposite structure
	 * 
	 * @return The returned Object[] holds the following elements:
	 *         <ul>
	 *         <li> 0 ... TPM return code (Long)
	 *         <li> 1 ... outgoing authorization for session containing new nonceEven (TcTpmAuth)
	 *         <li> 2 ... The TcTpmKey structure which includes the public and encrypted private key.
	 *         MUST be TcTpmKey12 (TcTpmKey12)
	 *         </ul>
	 * 
	 * @throws  TcTpmException This exception indicates that a TPM error has occurred. The specific
	 *           error code id held by the exception.
	 * 
	 * @TPM_V2_R101 96
	 */
	public static Object[] TpmCmkCreateKey(TcIStreamDest dest, long parentHandle,
			TcTpmEncauth dataUsageAuth, TcTpmKey12 keyInfo, TcTpmDigest migrationAuthorityApproval,
			TcTpmDigest migrationAuthorityDigest, TcTcsAuth inAuth1) throws TcTddlException, TcTpmException
	{

		TcBlobData inBlob = blobUINT16(TcTpmConstants.TPM_TAG_RQU_AUTH1_COMMAND);
		inBlob.append(blobUINT32(0)); // paramSize is set later
		inBlob.append(blobUINT32(TcTpmOrdinals.TPM_ORD_CMK_CreateKey));
		inBlob.append(blobUINT32(parentHandle));
		inBlob.append(dataUsageAuth.getEncoded());
		inBlob.append(keyInfo.getEncoded());
		inBlob.append(migrationAuthorityApproval.getEncoded());
		inBlob.append(migrationAuthorityDigest.getEncoded());
		inBlob.append(blobUINT32(inAuth1.getAuthHandle()));
		inBlob.append(inAuth1.getNonceOdd().getEncoded());
		inBlob.append(blobBOOL(inAuth1.getContAuthSession()));
		inBlob.append(inAuth1.getHmac().getEncoded());

		// all parameters filled in - set the length of the blob
		setParamSize(inBlob);

		// send byte stream
		TcBlobData tpmOutBlob = dest.transmitData(inBlob);
		TcTpmGenericReturnBlob outBlob = new TcTpmGenericReturnBlob(tpmOutBlob);

		// check TPM return code: if call was not successful, an exception is thrown
		try {
			handleRetCode(outBlob);
		} catch (TcTpmException e) {
			invalidataAuthSession(inAuth1);
			throw e;
		}

		// decode output values
		TcTpmKey12 wrappedKey = new TcTpmKey12(outBlob);

		// decode 1st output auth
		TcTcsAuth outAuth1 = new TcTcsAuth();
		outAuth1.setAuthHandle(inAuth1.getAuthHandle());
		outAuth1.setNonceOdd(inAuth1.getNonceOdd());
		outAuth1.setNonceEven(new TcTpmNonce(outBlob)); // new nonce even from TPM
		outAuth1.setContAuthSession(outBlob.decodeBoolean());
		outAuth1.setHmac(new TcTpmAuthdata(outBlob));
		trackAuthSession(inAuth1, outAuth1);

		return new Object[] { outBlob.getRetCodeAsLong(), outAuth1, wrappedKey };
	}


	/*************************************************************************************************
	 * 
	 * 
	 * @param dest The destination where the byte stream is written to.
	 * @param inAuth1 Authorization values for first authorization session.
	 * @param verificationKey The public key to be used to check signatureValue
	 * @param signedData The data to be verified
	 * @param signatureValue The signatureValue to be verified
	 * 
	 * @return The returned Object[] holds the following elements:
	 *         <ul>
	 *         <li> 0 ... TPM return code (Long)
	 *         <li> 1 ... outgoing authorization for session containing new nonceEven (TcTpmAuth)
	 *         <li> 2 ... Ticket that proves digest created on this TPM (TcTpmDigest)
	 *         </ul>
	 * 
	 * @throws  TcTpmException This exception indicates that a TPM error has occurred. The specific
	 *           error code id held by the exception.
	 * 
	 * @TPM_V2_R101 99
	 */
	public static Object[] TpmCmkCreateTicket(TcIStreamDest dest, TcTpmPubkey verificationKey,
			TcTpmDigest signedData, TcBlobData signatureValue, TcTcsAuth inAuth1)
		throws TcTddlException, TcTpmException
	{

		TcBlobData inBlob = blobUINT16(TcTpmConstants.TPM_TAG_RQU_AUTH1_COMMAND);
		inBlob.append(blobUINT32(0)); // paramSize is set later
		inBlob.append(blobUINT32(TcTpmOrdinals.TPM_ORD_CMK_CreateTicket));
		inBlob.append(verificationKey.getEncoded());
		inBlob.append(signedData.getEncoded());
		inBlob.append(blobUINT32(signatureValue.getLengthAsLong()));
		inBlob.append(signatureValue);
		inBlob.append(blobUINT32(inAuth1.getAuthHandle()));
		inBlob.append(inAuth1.getNonceOdd().getEncoded());
		inBlob.append(blobBOOL(inAuth1.getContAuthSession()));
		inBlob.append(inAuth1.getHmac().getEncoded());

		// all parameters filled in - set the length of the blob
		setParamSize(inBlob);

		// send byte stream
		TcBlobData tpmOutBlob = dest.transmitData(inBlob);
		TcTpmGenericReturnBlob outBlob = new TcTpmGenericReturnBlob(tpmOutBlob);

		// check TPM return code: if call was not successful, an exception is thrown
		try {
			handleRetCode(outBlob);
		} catch (TcTpmException e) {
			invalidataAuthSession(inAuth1);
			throw e;
		}

		// decode output values
		TcTpmDigest sigTicket = new TcTpmDigest(outBlob);

		// decode 1st output auth
		TcTcsAuth outAuth1 = new TcTcsAuth();
		outAuth1.setAuthHandle(inAuth1.getAuthHandle());
		outAuth1.setNonceOdd(inAuth1.getNonceOdd());
		outAuth1.setNonceEven(new TcTpmNonce(outBlob)); // new nonce even from TPM
		outAuth1.setContAuthSession(outBlob.decodeBoolean());
		outAuth1.setHmac(new TcTpmAuthdata(outBlob));
		trackAuthSession(inAuth1, outAuth1);

		return new Object[] { outBlob.getRetCodeAsLong(), outAuth1, sigTicket };
	}


	/*************************************************************************************************
	 * 
	 * 
	 * @param dest The destination where the byte stream is written to.
	 * @param inAuth1 Authorization values for first authorization session.
	 * @param parentHandle Handle of the parent key that can decrypt encData.
	 * @param migrationType The migration type, either TPM_MS_RESTRICT_MIGRATE or
	 *          TPM_MS_RESTRICT_APPROVE_DOUBLE
	 * @param migrationKeyAuth Migration public key and its authorization session digest.
	 * @param pubSourceKeyDigest The digest of the TcTpmPubkey of the entity to be migrated
	 * @param msaList One or more digests of public keysbelonging to migration authorities
	 * @param restrictTicket Either a NULL parameter or a TcTpmCmkAuth structure, containingthe
	 *          digests of the public keys belonging to the Migration Authority, the destination
	 *          parent key and the key-to-be-migrated.
	 * @param sigTicket Either a NULL parameter or a TcTpmDigest structure, generated by the TPM,
	 *          signaling a valid signature over restrictTicket
	 * @param encData The encrypted entity that is to bemodified.
	 * 
	 * @return The returned Object[] holds the following elements:
	 *         <ul>
	 *         <li> 0 ... TPM return code (Long)
	 *         <li> 1 ... outgoing authorization for session containing new nonceEven (TcTpmAuth)
	 *         <li> 2 ... String used for xor encryption (TcBlobData)
	 *         <li> 3 ... The modified, encrypted entity. (TcBlobData)
	 *         </ul>
	 * 
	 * @throws  TcTpmException This exception indicates that a TPM error has occurred. The specific
	 *           error code id held by the exception.
	 * 
	 * @TPM_V2_R101 101
	 */
	public static Object[] TpmCmkCreateBlob(TcIStreamDest dest, long parentHandle, int migrationType,
			TcTpmMigrationkeyAuth migrationKeyAuth, TcTpmDigest pubSourceKeyDigest,
			TcTpmMsaComposite msaList, TcBlobData restrictTicket, TcBlobData sigTicket,
			TcBlobData encData, TcTcsAuth inAuth1) throws TcTddlException, TcTpmException
	{

		TcBlobData inBlob = blobUINT16(TcTpmConstants.TPM_TAG_RQU_AUTH1_COMMAND);
		inBlob.append(blobUINT32(0)); // paramSize is set later
		inBlob.append(blobUINT32(TcTpmOrdinals.TPM_ORD_CMK_CreateBlob));
		inBlob.append(blobUINT32(parentHandle));
		inBlob.append(blobUINT16(migrationType));
		inBlob.append(migrationKeyAuth.getEncoded());
		inBlob.append(pubSourceKeyDigest.getEncoded());
		inBlob.append(blobUINT32(msaList.getEncoded().getLengthAsLong()));
		inBlob.append(msaList.getEncoded());
		if (restrictTicket == null) {
			inBlob.append(blobUINT32(0));
		} else {
			inBlob.append(blobUINT32(restrictTicket.getLengthAsLong()));
			inBlob.append(restrictTicket);
		}
		if (sigTicket == null) {
			inBlob.append(blobUINT32(0));
		} else {
			inBlob.append(blobUINT32(sigTicket.getLengthAsLong()));
			inBlob.append(sigTicket);
		}
		inBlob.append(blobUINT32(encData.getLengthAsLong()));
		inBlob.append(encData);
		inBlob.append(blobUINT32(inAuth1.getAuthHandle()));
		inBlob.append(inAuth1.getNonceOdd().getEncoded());
		inBlob.append(blobBOOL(inAuth1.getContAuthSession()));
		inBlob.append(inAuth1.getHmac().getEncoded());

		// all parameters filled in - set the length of the blob
		setParamSize(inBlob);

		// send byte stream
		TcBlobData tpmOutBlob = dest.transmitData(inBlob);
		TcTpmGenericReturnBlob outBlob = new TcTpmGenericReturnBlob(tpmOutBlob);

		// check TPM return code: if call was not successful, an exception is thrown
		try {
			handleRetCode(outBlob);
		} catch (TcTpmException e) {
			invalidataAuthSession(inAuth1);
			throw e;
		}

		// decode output values
		long randomSize = outBlob.decodeUINT32();
		TcBlobData random = outBlob.decodeBytes(randomSize);
		long outDataSize = outBlob.decodeUINT32();
		TcBlobData outData = outBlob.decodeBytes(outDataSize);

		// decode 1st output auth
		TcTcsAuth outAuth1 = new TcTcsAuth();
		outAuth1.setAuthHandle(inAuth1.getAuthHandle());
		outAuth1.setNonceOdd(inAuth1.getNonceOdd());
		outAuth1.setNonceEven(new TcTpmNonce(outBlob)); // new nonce even from TPM
		outAuth1.setContAuthSession(outBlob.decodeBoolean());
		outAuth1.setHmac(new TcTpmAuthdata(outBlob));
		trackAuthSession(inAuth1, outAuth1);

		return new Object[] { outBlob.getRetCodeAsLong(), outAuth1, random, outData };
	}


	/*************************************************************************************************
	 * 
	 * 
	 * @param dest The destination where the byte stream is written to.
	 * @param inAuth1 Authorization values for first authorization session.
	 * @param parentHandle Handle of a loaded key that can decrypt keys.
	 * @param restrictTicket The digests of public keys belonging to the Migration Authority, the
	 *          destination parentkey and the key-to-be-migrated.
	 * @param sigTicket A signature ticket, generated by the TPM, signaling a valid signature over
	 *          restrictTicket
	 * @param migratedKey The public key of the key-to-be-migrated. The private portion MUST be
	 *          TcTpmMigrateAsymkey properly XOR'd
	 * @param msaList One or more digests of public keys belonging to migration authorities
	 * @param random Random value used to hide key data.
	 * 
	 * @return The returned Object[] holds the following elements:
	 *         <ul>
	 *         <li> 0 ... TPM return code (Long)
	 *         <li> 1 ... outgoing authorization for session containing new nonceEven (TcTpmAuth)
	 *         <li> 2 ... The encrypted private key that canbe loaded with TPM_LoadKey (TcBlobData)
	 *         </ul>
	 * 
	 * @throws  TcTpmException This exception indicates that a TPM error has occurred. The specific
	 *           error code id held by the exception.
	 * 
	 * @TPM_V2_R101 106
	 */
	public static Object[] TpmCmkConvertMigration(TcIStreamDest dest, long parentHandle,
			TcTpmCmkAuth restrictTicket, TcTpmDigest sigTicket, TcTpmKey12 migratedKey,
			TcTpmMsaComposite msaList, TcBlobData random, TcTcsAuth inAuth1) throws TcTddlException, TcTpmException
	{

		TcBlobData inBlob = blobUINT16(TcTpmConstants.TPM_TAG_RQU_AUTH1_COMMAND);
		inBlob.append(blobUINT32(0)); // paramSize is set later
		inBlob.append(blobUINT32(TcTpmOrdinals.TPM_ORD_CMK_ConvertMigration));
		inBlob.append(blobUINT32(parentHandle));
		inBlob.append(restrictTicket.getEncoded());
		inBlob.append(sigTicket.getEncoded());
		inBlob.append(migratedKey.getEncoded());
		inBlob.append(blobUINT32(msaList.getEncoded().getLengthAsLong()));
		inBlob.append(msaList.getEncoded());
		inBlob.append(blobUINT32(random.getLengthAsLong()));
		inBlob.append(random);
		inBlob.append(blobUINT32(inAuth1.getAuthHandle()));
		inBlob.append(inAuth1.getNonceOdd().getEncoded());
		inBlob.append(blobBOOL(inAuth1.getContAuthSession()));
		inBlob.append(inAuth1.getHmac().getEncoded());

		// all parameters filled in - set the length of the blob
		setParamSize(inBlob);

		// send byte stream
		TcBlobData tpmOutBlob = dest.transmitData(inBlob);
		TcTpmGenericReturnBlob outBlob = new TcTpmGenericReturnBlob(tpmOutBlob);

		// check TPM return code: if call was not successful, an exception is thrown
		try {
			handleRetCode(outBlob);
		} catch (TcTpmException e) {
			invalidataAuthSession(inAuth1);
			throw e;
		}

		// decode output values
		long outDataSize = outBlob.decodeUINT32();
		TcBlobData outData = outBlob.decodeBytes(outDataSize);

		// decode 1st output auth
		TcTcsAuth outAuth1 = new TcTcsAuth();
		outAuth1.setAuthHandle(inAuth1.getAuthHandle());
		outAuth1.setNonceOdd(inAuth1.getNonceOdd());
		outAuth1.setNonceEven(new TcTpmNonce(outBlob)); // new nonce even from TPM
		outAuth1.setContAuthSession(outBlob.decodeBoolean());
		outAuth1.setHmac(new TcTpmAuthdata(outBlob));
		trackAuthSession(inAuth1, outAuth1);

		return new Object[] { outBlob.getRetCodeAsLong(), outAuth1, outData };
	}
}
