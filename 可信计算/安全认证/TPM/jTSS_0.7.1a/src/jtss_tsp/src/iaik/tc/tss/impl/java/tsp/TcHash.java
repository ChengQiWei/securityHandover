/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.impl.java.tsp;


import iaik.tc.tss.api.constants.tpm.TcTpmConstants;
import iaik.tc.tss.api.constants.tsp.TcTssConstants;
import iaik.tc.tss.api.constants.tsp.TcTssErrors;
import iaik.tc.tss.api.exceptions.common.TcTssException;
import iaik.tc.tss.api.exceptions.tcs.TcTcsException;
import iaik.tc.tss.api.exceptions.tsp.TcTspException;
import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.tss.api.structs.tcs.TcTcsAuth;
import iaik.tc.tss.api.structs.tpm.TcTpmCurrentTicks;
import iaik.tc.tss.api.structs.tpm.TcTpmDigest;
import iaik.tc.tss.api.structs.tpm.TcTpmNonce;
import iaik.tc.tss.api.structs.tpm.TcTpmPubkey;
import iaik.tc.tss.api.structs.tpm.TcTpmSecret;
import iaik.tc.tss.api.structs.tsp.TcTssValidation;
import iaik.tc.tss.api.tspi.TcIHash;
import iaik.tc.tss.api.tspi.TcIRsaKey;
import iaik.tc.tss.impl.csp.TcCrypto;
import iaik.tc.tss.impl.java.tsp.internal.TcTspInternal;
import iaik.tc.utils.misc.CheckPrecondition;

public class TcHash extends TcWorkingObject implements TcIHash {

	/**
	 * This field holds the TSS algorithm identifier (e.g TSS_HASH_SHA1).
	 */
	protected long tssHashAlgId_ = 0;

	/**
	 * This field holds the PKCS#1 hash algorithm identifier.
	 */
	protected TcBlobData pkcs1HashAlgId_ = null;

	/**
	 * This field holds the current hash value.
	 */
	protected TcBlobData hashValue_ = null;

	/**
	 * This field holds the current plain data as accumulated via update method calls.
	 */
	protected TcBlobData plainData_ = null;

	/**
	 * This field determines if calls to hashUpdate are allowed or not. HashUpdate calls are not
	 * allowed after SetHash, GetHash, HashSign or HashVerify have been called.
	 */
	protected boolean allowHashUpdate_ = true;

	/**
	 * PKCS#1 AlgorithmIdentifier for SHA1.
	 * 
	 * @TSS_1_2_EA 351
	 */
	public static final TcBlobData PKCS1_SHA1_IDENTIFIER = TcBlobData.newByteArray(new byte[] { 0x30,
			0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00 });

	/**
	 * PKCS#1 AlgorithmIdentifier for MD5.
	 * 
	 * @TSS_1_2_EA 351
	 */
	public static final TcBlobData PKCS1_MD5_IDENTIFIER = TcBlobData.newByteArray(new byte[] { 0x30,
			0x0c, 0x06, 0x08, 0x2a, (byte) 0x86, 0x48, (byte) 0x86, (byte) 0xf7, 0x0d, 0x02, 0x05, 0x05,
			0x00 });

	/**
	 * PKCS#1 AlgorithmIdentifier for MD4.
	 * 
	 * @TSS_1_2_EA 351
	 */
	public static final TcBlobData PKCS1_MD4_IDENTIFIER = TcBlobData.newByteArray(new byte[] { 0x30,
			0x0c, 0x06, 0x08, 0x2a, (byte) 0x86, 0x48, (byte) 0x86, (byte) 0xf7, 0x0d, 0x02, 0x04, 0x05,
			0x00 });

	/**
	 * PKCS#1 AlgorithmIdentifier for MD2.
	 * 
	 * @TSS_1_2_EA 351
	 */
	public static final TcBlobData PKCS1_MD2_IDENTIFIER = TcBlobData.newByteArray(new byte[] { 0x30,
			0x0c, 0x06, 0x08, 0x2a, (byte) 0x86, 0x48, (byte) 0x86, (byte) 0xf7, 0x0d, 0x02, 0x02, 0x05,
			0x00 });


	/*************************************************************************************************
	 * Hidden constructor (factory pattern).
	 */
	protected TcHash(TcContext context) throws TcTssException
	{
		super(context);
	}


	/*************************************************************************************************
	 * This method is used to decode a set of init flags.
	 * 
	 * @TSS_1_1_EA 55
	 * 
	 * @param flags The init flags.
	 */
	protected synchronized void setInitFlags(long flags) throws TcTssException
	{
		if (flags == TcTssConstants.TSS_HASH_DEFAULT || flags == TcTssConstants.TSS_HASH_SHA1) {
			tssHashAlgId_ = TcTssConstants.TSS_HASH_SHA1;
			pkcs1HashAlgId_ = PKCS1_SHA1_IDENTIFIER;

		} else if (flags == TcTssConstants.TSS_HASH_OTHER) {
			tssHashAlgId_ = TcTssConstants.TSS_HASH_OTHER;

		} else {
			throw new TcTspException(TcTssErrors.TSS_E_NOTIMPL, "Unknown hash algorithm selection.");
		}
	}


	/*
	 * (non-Javadoc)
	 * 
	 * @see iaik.tss.api.tspi.TcIHash#getHashValue()
	 */
	public synchronized TcBlobData getHashValue() throws TcTssException
	{
		checkContextOpen();

		if (hashValue_ == null) {
			throw new TcTspException(TcTssErrors.TSS_E_HASH_NO_DATA, "No hash value set.");
		}

		allowHashUpdate_ = false;

		return (TcBlobData) hashValue_.clone();
	}


	/*
	 * (non-Javadoc)
	 * 
	 * @see iaik.tss.api.tspi.TcIHash#setHashValue(iaik.tss.api.structs.TcBlobData)
	 */
	public synchronized void setHashValue(TcBlobData hashValue) throws TcTssException
	{
		CheckPrecondition.notNull(hashValue, "hashValue");

		if (tssHashAlgId_ == TcTssConstants.TSS_HASH_SHA1
				&& hashValue.getLength() != TcTpmConstants.TPM_SHA1_160_HASH_LEN) {
			throw new TcTspException(TcTssErrors.TSS_E_HASH_INVALID_LENGTH,
					"Illegal hash length for SHA1 hash.");
		}

		hashValue_ = hashValue;
		plainData_ = null;
		allowHashUpdate_ = false;
	}


	/*
	 * (non-Javadoc)
	 * 
	 * @see iaik.tss.api.tspi.TcIHash#sign(iaik.tss.api.tspi.TcIRsaKey)
	 */
	public synchronized TcBlobData sign(TcIRsaKey key) throws TcTssException
	{
		checkContextOpenAndConnected();
		CheckPrecondition.notNullAndInstanceOf(key, "key", TcRsaKey.class);
		context_.checkAssociation(key, "key");
		checkKeyHandleNotNull(((TcRsaKey) key).getTcsKeyHandle(), "key");

		if (hashValue_ == null) {
			throw new TcTspException(TcTssErrors.TSS_E_HASH_NO_DATA, "No hash value set.");
		}

		allowHashUpdate_ = false;

		// Construct digest depending on the selected signature scheme of the key (see TSS_1_2_EA 352).
		TcBlobData algInfo = null;
		long keySigScheme = ((TcRsaKey) key)
				.getAttribKeyInfoUINT32(TcTssConstants.TSS_TSPATTRIB_KEYINFO_SIGSCHEME);

		// case 1: keySigScheme = SHA1
		if (keySigScheme == TcTssConstants.TSS_SS_RSASSAPKCS1V15_SHA1) {
			if (tssHashAlgId_ != TcTssConstants.TSS_HASH_SHA1) {
				throw new TcTspException(TcTssErrors.TSS_E_BAD_PARAMETER,
						"Key signature scheme (SS_SHA1) does not match hash type.");
			}
			// TPM constructs DER encoded T and does PKCS#1 padding
			algInfo = null;

			// case 2: keySigScheme = DER
		} else if (keySigScheme == TcTssConstants.TSS_SS_RSASSAPKCS1V15_DER) {

			// case 2a: HASH_SHA1
			if (tssHashAlgId_ == TcTssConstants.TSS_HASH_SHA1) {
				// TSS constructs DigestInfo T (== AlgoId || hashValue_), TPM performs PKCS#1 padding
				algInfo = (TcBlobData) PKCS1_SHA1_IDENTIFIER.clone();

				// case 2b: HASH_OTHER
			} else if (tssHashAlgId_ == TcTssConstants.TSS_HASH_OTHER) {

				// case 2b_1: PKCS#1 ID not set
				if (pkcs1HashAlgId_ == null) {
					// hashValue_ is assumed to be T and is passed to the TPM; TPM performs PKCS#1 padding
					algInfo = null;

					// case 2b_2: PKCS#1 ID set
				} else {
					// TSS constructs DigestInfo T (== AlgoId || hashValue_), TPM performs PKCS#1 padding
					algInfo = (TcBlobData) pkcs1HashAlgId_.clone();
				}

				// case 2c: unknown TSS_HASH
			} else {
				throw new TcTspException(TcTssErrors.TSS_E_INTERNAL_ERROR,
						"Hash object is using an unknown hash algorithm.");
			}

			// case 3: key not usable for signing
		} else if (keySigScheme == TcTssConstants.TSS_SS_NONE) {
			throw new TcTspException(TcTssErrors.TSS_E_BAD_PARAMETER,
					"Provided key is not usable for signing operations.");

			
			// case 4: unknown signature scheme
		} else if (keySigScheme == TcTssConstants.TSS_SS_RSASSAPKCS1V15_INFO) {
			
			//TODO: implement this sig scheme
			
			throw new TcTspException(TcTssErrors.TSS_E_BAD_PARAMETER,
			"Signature scheme RSASSAPKCS1V15_INFO is not supported yet.");
		
					
			// case 5: unknown signature scheme
		} else {
			throw new TcTspException(TcTssErrors.TSS_E_INTERNAL_ERROR,
					"The provided key is using an unknown signature scheme.");
		}

		long keyHandle = ((TcRsaKey) key).getTcsKeyHandle();
		TcTpmSecret privAuth = new TcTpmSecret(((TcPolicy) key.getUsagePolicyObject()).getSecret());

		// setup digest info
		TcBlobData inDigest = null;
		if (algInfo != null) {
			inDigest = createDigestInfoDER(algInfo, hashValue_);
		} else {
			inDigest = hashValue_;
		}

		// start OIAP session
		TcTcsAuth inAuth1 = TcTspInternal.TspOIAP_Internal(context_);

		// call to TPM
		Object[] tpmOutData = TcTspInternal.TspSign_Internal(context_, keyHandle, inDigest, inAuth1,
				privAuth);

		// get return values
		TcBlobData signature = (TcBlobData) tpmOutData[1];

		return signature;
	}


	/*
	 * (non-Javadoc)
	 * 
	 * @see iaik.tss.api.tspi.TcIHash#updateHashValue(iaik.tss.api.structs.TcBlobData)
	 */
	public synchronized void updateHashValue(TcBlobData data) throws TcTssException
	{
		checkContextOpen();
		CheckPrecondition.notNull(data, "data");

		if (!allowHashUpdate_) {
			throw new TcTspException(
					TcTssErrors.TSS_E_INVALID_OBJ_ACCESS,
					"Calls to HashUpdate are no longer allowed when Set/GetHashValue, HashSigh " +
					"or HashVerify have already been called.");
		}

		if (tssHashAlgId_ == TcTssConstants.TSS_HASH_OTHER) {
			throw new TcTspException(TcTssErrors.TSS_E_BAD_PARAMETER,
					"Update operation is not supported for non-SHA1 hashes.");
		}

		if (plainData_ == null) {
			plainData_ = (TcBlobData) data.clone();
		} else {
			plainData_.append(data);
		}

		hashValue_ = plainData_.sha1();
	}


	/*
	 * (non-Javadoc)
	 * 
	 * @see iaik.tss.api.tspi.TcIHash#verifySignature(iaik.tss.api.structs.TcBlobData,
	 *      iaik.tss.api.tspi.TcIRsaKey)
	 */
	public synchronized void verifySignature(TcBlobData signature, TcIRsaKey key)
		throws TcTssException
	{
		checkContextOpen();
		CheckPrecondition.notNull(signature, "signature");
		CheckPrecondition.notNullAndInstanceOf(key, "key", TcRsaKey.class);
		context_.checkAssociation(key, "key");

		if (hashValue_ == null) {
			throw new TcTspException(TcTssErrors.TSS_E_HASH_NO_DATA, "No hash value set.");
		}

		allowHashUpdate_ = false;
		
		long keySigScheme = ((TcRsaKey) key)
				.getAttribKeyInfoUINT32(TcTssConstants.TSS_TSPATTRIB_KEYINFO_SIGSCHEME);

		TcBlobData algInfo = null;

		// case 1: keySigScheme = SHA1
		if (keySigScheme == TcTssConstants.TSS_SS_RSASSAPKCS1V15_SHA1) {
			if (tssHashAlgId_ != TcTssConstants.TSS_HASH_SHA1) {
				throw new TcTspException(TcTssErrors.TSS_E_BAD_PARAMETER,
						"Key signature scheme (SS_SHA1) does not match hash type.");
			}
			algInfo = (TcBlobData) PKCS1_SHA1_IDENTIFIER.clone();

			// case 2: keySigScheme = DER
		} else if (keySigScheme == TcTssConstants.TSS_SS_RSASSAPKCS1V15_DER) {

			// case 2a: HASH_SHA1
			if (tssHashAlgId_ == TcTssConstants.TSS_HASH_SHA1) {
				algInfo = (TcBlobData) PKCS1_SHA1_IDENTIFIER.clone();

				// case 2b: HASH_OTHER
			} else if (tssHashAlgId_ == TcTssConstants.TSS_HASH_OTHER) {

				// case 2b_1: PKCS#1 ID not set
				if (pkcs1HashAlgId_ == null) {
					// hashValue_ is assumed to be the DER encoded DigestInfo
					algInfo = null;

					// case 2b_2: PKCS#1 ID set
				} else {
					// TSS constructs DigestInfo T (== AlgoId || hashValue_), TPM performs PKCS#1 padding
					algInfo = (TcBlobData) pkcs1HashAlgId_.clone();
				}

				// case 2c: unknown TSS_HASH
			} else {
				throw new TcTspException(TcTssErrors.TSS_E_INTERNAL_ERROR,
						"Hash object is using an unknown hash algorithm.");
			}

			// case 3: key not usable for signing
		} else if (keySigScheme == TcTssConstants.TSS_SS_NONE) {
			throw new TcTspException(TcTssErrors.TSS_E_BAD_PARAMETER,
					"Provided key is not usable for signing operations.");

			// case 4: unimplemented signature scheme
		} else if (keySigScheme == TcTssConstants.TSS_SS_RSASSAPKCS1V15_INFO) {
			//TODO: implement this sig scheme
			
			throw new TcTspException(TcTssErrors.TSS_E_BAD_PARAMETER,
			"Signature scheme RSASSAPKCS1V15_INFO is not supported yet.");
			
			// case 5: unknown signature scheme
		} else {
			throw new TcTspException(TcTssErrors.TSS_E_INTERNAL_ERROR,
					"The provided key is using an unknown signature scheme.");
		}

		// get public key
		TcBlobData pubKeyBlob = ((TcRsaKey) key)
				.getAttribKeyBlob(TcTssConstants.TSS_TSPATTRIB_KEYBLOB_PUBLIC_KEY);
		TcTpmPubkey pubKey = new TcTpmPubkey(pubKeyBlob);

		// decrypt the signature blob
		TcBlobData plainData = null;
		try {
			plainData = TcCrypto.decryptRsaEcbPkcs1Padding(pubKey, signature);
		} catch (TcTcsException e) {
			throw new TcTspException(TcTssErrors.TSS_E_INTERNAL_ERROR, e.getMessage());
		}

		// setup digest info
		TcBlobData digestInfo = null;
		if (algInfo != null) {
			digestInfo = createDigestInfoDER(algInfo, hashValue_);
		} else {
			digestInfo = hashValue_;
		}

		if (!plainData.equals(digestInfo)) {
			throw new TcTspException(TcTssErrors.TSS_E_FAIL, "Signature verification failed.");
		}
	}


	/*************************************************************************************************
	 * This internal method assembles a DER encoded DigestInfo ASN1 structure (see TSS_1_2_EA 352).
	 */
	private TcBlobData createDigestInfoDER(TcBlobData algInfo, TcBlobData digest)
	{
		CheckPrecondition.notNull(algInfo, "algInfo");
		CheckPrecondition.notNull(digest, "digest");

		// Currently only short length octets are supported (i.e. lengths from 0 to 127 that
		// can be encoded using 7 bits)
		CheckPrecondition.ltOrEq(algInfo.getLengthAsLong(), "algInfo.length", 127);
		CheckPrecondition.ltOrEq(digest.getLengthAsLong(), "digest.length", 127);

		// TODO: add support for 'long definite' length octets or swith to IAIK JCE for
		// full DER encoding support.

		// note on 'long definite' length octets: There are 2 to 127 octets. Bit 8 of the
		// first octet is set to 1, bits 7 to 1 specify the number of additional length
		// octets. The second octet (and the following ones) define the actual length
		// (base is 256, highest order digit comes first).

		TcBlobData retVal = null;

		retVal = algInfo;
		// append the OCTET STRING tag: 0x04 (tag = 4 (bits 1 to 5), constructed = 0 (bit 6))
		// next byte is the OCTET STRING length
		retVal.append(TcBlobData.newByteArray( //
				new byte[] { 0x04, (byte) digest.getLength() }));
		retVal.append(digest);
		// prepend the sequence header: 0x30 (tag = 16 (bits 1 to 5), constructed = 1 (bit 6))
		// 2nd byte is the sequence length
		retVal.prepend(TcBlobData.newByteArray( //
				new byte[] { 0x30, (byte) retVal.getLength() }));

		return retVal;
	}


	// ----------------------------------------------------------------------------------------------
	// TSS attribute getters and setter
	// ----------------------------------------------------------------------------------------------

	/*************************************************************************************************
	 * This method defines the mapping of attribute flags to getter methods.
	 */
	protected void initAttribGetters()
	{
		// not getter methods defined in the TSS spec
	}


	/*************************************************************************************************
	 * This method defines the mapping of attribute flags to setter methods.
	 */
	protected void initAttribSetters()
	{
		addSetterData(TcTssConstants.TSS_TSPATTRIB_ALG_IDENTIFIER, "setAttribAlgIdentifier");
	}


	/*************************************************************************************************
	 * This method sets the hash algorithm identifier if the init flags
	 * {@link TcTssConstants#TSS_HASH_OTHER} was provided upon object creation.
	 * 
	 * @param subFlag Ignored.
	 * @param data The hash DER encoded AlgorithmIdentifier as defined by the PKCS#1 specification.
	 * 
	 * @throws {@link TcTssException}
	 */
	public synchronized void setAttribAlgIdentifier(long subFlag, TcBlobData data)
		throws TcTssException
	{
		CheckPrecondition.notNull(data, "data");

		if (tssHashAlgId_ == TcTssConstants.TSS_HASH_SHA1) {
			if (data.equals(PKCS1_SHA1_IDENTIFIER)) {
				pkcs1HashAlgId_ = PKCS1_SHA1_IDENTIFIER;
			} else {
				throw new TcTspException(TcTssErrors.TSS_E_INVALID_ATTRIB_DATA,
						"Invalid attribute data for SHA1 hash object.");
			}

		} else if (tssHashAlgId_ == TcTssConstants.TSS_HASH_OTHER) {
			if (data.equals(PKCS1_SHA1_IDENTIFIER)) {
				throw new TcTspException(TcTssErrors.TSS_E_INVALID_ATTRIB_DATA,
						"Invalid attribute data for OTHER hash object.");
			} else {
				if (pkcs1HashAlgId_ != null && !pkcs1HashAlgId_.equals(data)) {
					throw new TcTspException(TcTssErrors.TSS_E_INVALID_ATTRIB_DATA,
							"The algorithm can not be changed once it has been set.");
				}
				pkcs1HashAlgId_ = data;
			}

		} else {
			throw new TcTspException(TcTssErrors.TSS_E_INTERNAL_ERROR, "Hash type is not SHA1 or OTHER");
		}
	}

	/**
	 * Time stamps a hash blog
	 */
	public Object[] tickStampBlob(TcIRsaKey key, TcTssValidation validationData) throws TcTssException {
	
		checkContextOpenAndConnected();
		CheckPrecondition.notNullAndInstanceOf(key, "key", TcRsaKey.class);
		context_.checkAssociation(key, "key");
		checkKeyHandleNotNull(((TcRsaKey) key).getTcsKeyHandle(), "key");
		CheckPrecondition.notNull(hashValue_, "digestToStamp");
		
		long keyHandle = ((TcRsaKey) key).getTcsKeyHandle();
		TcTpmSecret privAuth = new TcTpmSecret(((TcPolicy) key.getUsagePolicyObject()).getSecret());
		
		// start OIAP session
		TcTcsAuth inAuth1 = TcTspInternal.TspOIAP_Internal(context_);
				
		TcTpmNonce antiReplay = new TcTpmNonce(validationData.getExternalData());
		
		TcTpmDigest digestToStamp = new TcTpmDigest(hashValue_);
		Object[] tpmOutData = TcTspInternal.TspTickStampBlob_Internal(context_, keyHandle,
				 antiReplay, digestToStamp, inAuth1, privAuth);
		
		TcTcsAuth outAuth1 = (TcTcsAuth) tpmOutData[0];
		TcTpmCurrentTicks currentTicks = (TcTpmCurrentTicks) tpmOutData[1];
		TcBlobData sig = (TcBlobData) tpmOutData[2];
		
		validationData.setValidationData(sig);
		
		return new Object[] {validationData, currentTicks};
	}

}
