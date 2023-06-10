/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.api.tspi;


import iaik.tc.tss.api.constants.tsp.TcTssConstants;
import iaik.tc.tss.api.constants.tsp.TcTssErrors;
import iaik.tc.tss.api.exceptions.common.TcTssException;
import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.tss.api.structs.tpm.TcTpmCertifyInfo;
import iaik.tc.tss.api.structs.tpm.TcTpmCertifyInfo2;
import iaik.tc.tss.api.structs.tpm.TcTpmMigrationkeyAuth;
import iaik.tc.tss.api.structs.tpm.TcTpmPubkey;
import iaik.tc.tss.api.structs.tsp.TcTssUuid;
import iaik.tc.tss.api.structs.tsp.TcTssValidation;
import iaik.tc.tss.api.structs.tsp.TcTssVersion;

/**
 * The key class defined by the TSS service provider represents an entry into the TCG key handling
 * functionality. Each instance of the key class represents a specific key node, that is part of the
 * TSS key path (hierarchy). A key object, which needs authentication, can be assigned to a policy
 * object that controls the secret management.
 */
public interface TcIRsaKey extends TcIWorkingObject, TcIAttributes, TcIAuthObject {

	/*************************************************************************************************
	 * This method creates a key pair within the TPM and wraps it with the key addressed by
	 * wrappingKey.<br>
	 * If the internal key structure is a 1.1 TPM key, the provided PcrComposite must be a
	 * {@link TcTssConstants#TSS_PCRS_STRUCT_INFO}. If the key is a 1.2 TPM key, the PcrComposite
	 * must be a {@link TcTssConstants#TSS_PCRS_STRUCT_INFO_LONG}. If a wrong combination is used, a
	 * {@link TcTssException} with error code {@link TcTssErrors#TSS_E_INVALID_OBJ_ACCESS} is thrown.<br>
	 * The key must already be properly set up via the key init flags or
	 * {@link TcIAttributes#setAttribData(long, long, TcBlobData)} and
	 * {@link TcIAttributes#setAttribUint32(long, long, long)}.
	 * 
	 * @TSS_V1 154
	 * 
	 * @TSS_1_2_EA 323
	 * 
	 * @param wrappingKey The key used to wrap the newly created key.
	 * @param pcrComposite If this parameter is not omitted (i.e. set to null), the newly created key
	 *          will be bound to the PCR values described within this object.
	 * 
	 * 
	 */
	public void createKey(final TcIRsaKey wrappingKey, final TcIPcrComposite pcrComposite)
		throws TcTssException;


	/*************************************************************************************************
	 * This method loads the key blob into the TPM. The TPM will unwrap the key when it is loaded.
	 * 
	 * @TSS_V1 150
	 * 
	 * @TSS_1_2_EA 318
	 * 
	 * @param unwrappingKey The key which should be used for unwrapping.
	 * 
	 * 
	 */
	public void loadKey(final TcIRsaKey unwrappingKey) throws TcTssException;


	/*************************************************************************************************
	 * This method unloads the key from the TPM.
	 * 
	 * @TSS_V1 151
	 * 
	 * @TSS_1_2_EA 319
	 * 
	 * 
	 */
	public void unloadKey() throws TcTssException;


	/*************************************************************************************************
	 * This method returns the UUID of the key.
	 * 
	 * @TSS_V1 149
	 * 
	 * @return UUID of the key.
	 * 
	 * 
	 */
	public TcTssUuid getAttribUuid() throws TcTssException;

	
	/*************************************************************************************************
	 * This method sets the UUID of the key.
	 */
	public void setAttribUuid(TcTssUuid uuid) throws TcTssException;

	
	

	/*************************************************************************************************
	 * This method returns the version of the key.
	 * 
	 * @TSS_V1 149
	 * 
	 * @return Version of the key.
	 * 
	 * 
	 */
	public TcTssVersion getAttribKeyInfoVersion() throws TcTssException;


	/*************************************************************************************************
	 * This method returns the public key of the key object.
	 * 
	 * @TSS_V1 152
	 * 
	 * @TSS_1_2_EA 320
	 * 
	 * @return Memory block containing the public key blob retrieved for the key. The returned blob is
	 *         of type {@link TcTpmPubkey}.
	 * 
	 * 
	 */
	public TcBlobData getPubKey() throws TcTssException;


	/*************************************************************************************************
	 * This method signs a public key inside the TPM using
	 * {@link TcTssConstants#TSS_SS_RSASSAPKCS1V15_SHA1}).
	 * 
	 * @TSS_V1 153
	 * 
	 * @TSS_1_2_EA 320
	 * 
	 * @param certifyingKey Certifying key used to sign the key.
	 * @param validation Structure of the type {@link TcTssValidation}. After successful completion
	 *          of the call the validationData field of this structure contains the signature data of
	 *          the command. The data field of the structure contains an instance of
	 *          {@link TcTpmCertifyInfo} or {@link TcTpmCertifyInfo2}.
	 * @return The filled validation object.
	 */
	public TcTssValidation certifyKey(final TcIRsaKey certifyingKey, final TcTssValidation validation)
		throws TcTssException;


	/*************************************************************************************************
	 * This method wraps a key (created externally) with the key addressed by wrappingKey.
	 * 
	 * @TSS_V1 155
	 * 
	 * @param wrappingKey kKey used for wrapping.
	 * @param pcrComposite object of the type PcrComposite. If the value of the handle doesn't equal
	 *          to NULL, the key addressed by hKey will be bound to the PCR values described with this
	 *          object.
	 */
	public void wrapKey(final TcIRsaKey wrappingKey, final TcIPcrComposite pcrComposite)
		throws TcTssException;


	/*************************************************************************************************
	 * This method creates a migration blob of the key.
	 * 
	 * @TSS_V1 156
	 * 
	 * @param parent Parent key related to the key.
	 * @param migTicket Migration ticket (migration public key and its authorization digest). This
	 *          data previously has been returned by the method TPM.authorizeMigrationTicket()
	 * @return An array with 2 elements: Element[0]: random data Element[1]: migration blob
	 */
	public TcBlobData[] createMigrationBlob(final TcIRsaKey parent, final TcTpmMigrationkeyAuth migTicket)
		throws TcTssException;


	/*************************************************************************************************
	 * This method takes the migration blob built by Tspi_Key_CreateMigrationBlob using the migration
	 * scheme TSS_MS_MIGRATE and creates a normal wrapped key. The resulting normal wrapped key. It
	 * may be retrieved from that instance by Tspi_GetAttribData().
	 * 
	 * @TSS_V1 158
	 * 
	 * @param parent Parent key related to the key.
	 * @param random Random data as returned together with the migration blob by the method
	 *          CreateMigrationBlob.
	 * @param migrationBlob Migration blob data as returned by a previously called method
	 *          CreateMigrationBlob.
	 */
	public void convertMigrationBlob(final TcIRsaKey parent, final TcBlobData random,
			final TcBlobData migrationBlob) throws TcTssException;

	
	/*************************************************************************************************
	 * This method decrypts with assistance of the TPM the input package (e.g. Key) and then 
	 * re-encrypts it with the input public key.
	 * 
	 * This command exists to allow the TPM to be a migration authority
	 * 
	 * @TSS_1_2_EA 346
	 * 
	 * @param publicKey Public key to which the blob is to be migrated
	 * @param migData Migration data key object to transfer the input and output data blob during the
	 *          migration process. The input data blob is from the previous call of the function 
	 *          Tspi_CreateMigrationBlob() or Tspi_CMK_CreateBlob(). 
	 */
	public void migrateKey(final TcIRsaKey publicKey, final TcIRsaKey migData) throws TcTssException;


	/*************************************************************************************************
	 * This method implements the first step in the process of moving a certified-migrateable-key to 
	 * a new parent platform.
	 * 
	 * @TSS_1_2_EA 347
	 * 
	 * @param parentKey The parent key related to this key object.
	 * @param migrationData Migration data key object to transfer the input and output data blob during the
	 *          migration process.  
	 * @return the random data
	 */
	public TcBlobData CMKCreateBlob(final TcIRsaKey parentKey, final TcIMigData migrationData) throws TcTssException;


	/*************************************************************************************************
	 * This method completes the migration of a certified migration process. This function takes a 
	 * certified migration blob and creates a normal wrapped key blob which must be loaded into the
	 * TPM using the normal LoadKey operation.
	 * 
	 * @TSS_1_2_EA 349
	 * 
	 * @param parentKey The parent key related to this key object.
	 * @param migrationData Migration data key object to transfer the input and output data blob during the
	 *          migration process.  
	 * @param random The random data as returned together with the migration blob by the method 
	 * 		    Tspi_CMKCreateBlob().
	 */
	public void CMKConvertMigration(final TcIRsaKey parentKey, final TcIMigData migrationData, final TcBlobData random)
		throws TcTssException;


	/*************************************************************************************************
	 * This method returns a policy object representing the migration policy currently assigned to the
	 * object. It is based on the getPolicy method of the TSS with TSS_POLICY_MIGRATION as parameter.
	 * 
	 * @TSS_V1 73
	 * 
	 * @TSS_1_2_EA 182
	 * 
	 * @return Migration policy object.
	 */
	public TcIPolicy getMigrationPolicyObject() throws TcTssException;

}