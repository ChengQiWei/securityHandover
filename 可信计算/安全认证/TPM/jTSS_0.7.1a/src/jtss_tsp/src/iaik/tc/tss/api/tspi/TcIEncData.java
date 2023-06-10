/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.api.tspi;


import iaik.tc.tss.api.constants.tsp.TcTssConstants;
import iaik.tc.tss.api.exceptions.common.TcTssException;
import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.tss.api.structs.tpm.TcTpmBoundData;
import iaik.tc.tss.api.structs.tpm.TcTpmSealedData;

/**
 * This class can be used to join externally (e. g. user, application) generated data to a TCG-aware
 * system (bound to PCR or Platform). For the authentication process this class can be assigned to a
 * policy object.
 */
public interface TcIEncData extends TcIWorkingObject, TcIAttributes, TcIAuthObject {

	/*************************************************************************************************
	 * This method encrypts a data blob in a manner that can only be decrypted by
	 * {@link TcIEncData#unbind(TcIRsaKey)}. The data blob is encrypted using a public key operation
	 * with the key addressed by the given encryption key object. To bind data larger than the RSA
	 * public key modulus it is the responsibility of the caller to perform the blocking and
	 * subsequent combination of data. The bound blob can be obtained using
	 * {@link TcIAttributes#getAttribData(long, long)}.
	 * 
	 * Note that the bind operation is performed entirely in software. It therefore is not restricted
	 * to a key generated by the resident TPM. It may be used with any appropriate public key. In such
	 * a case the TSS might however not be able to provide the unbind service.
	 * 
	 * Note that the maximum data size for bind operations actually is smaller then the public modulus
	 * of the RSA key. For the {@link TcTssConstants#TSS_ES_RSAESPKCSV15} encryption scheme with
	 * {@link TcTssConstants#TSS_KEY_TYPE_BIND} keys the max size is keySize - 11 - (4 + 1). With
	 * {@link TcTssConstants#TSS_KEY_TYPE_LEGACY} keys the max size is keySize - 11. For the
	 * {@link TcTssConstants#TSS_ES_RSAESOAEP_SHA1_MGF1} encryption scheme with
	 * {@link TcTssConstants#TSS_KEY_TYPE_BIND} or {@link TcTssConstants#TSS_KEY_TYPE_LEGACY} keys the
	 * max size is keySize - (2 * 20) - 2 - (4 + 1). The (4 + 1) accounts for the size of the
	 * {@link TcTpmBoundData} structure.
	 * 
	 * @TSS_V1 172
	 * 
	 * @TSS_1_2_EA 362
	 * 
	 * @param encKey The key used for encryption.
	 * @param data The data to encrypt.
	 * 
	 * 
	 */
	public void bind(final TcIRsaKey encKey, final TcBlobData data) throws TcTssException;


	/*************************************************************************************************
	 * This method unbinds (decrypts) a previously bound (encrypted) data blob. Before calling the
	 * unbind operation, the encrypted blob has to be set using the
	 * {@link TcIAttributes#setAttribData(long, long, TcBlobData)} method. It the key used for binding
	 * is not available in the TPM or is of wrong type, the TPM may not be able to perform the unbind
	 * operation.
	 * 
	 * Note that this method operates on a block-by-block basis and has no notion of any relation
	 * between blocks. See also {@link TcIEncData#unbind(TcIRsaKey)} for more information on data
	 * blocking.
	 * 
	 * @TSS_V1 173
	 * 
	 * @TSS_1_2_EA 364
	 * 
	 * @param key The Key used for decryption.
	 * 
	 * @return decrypted The decrypted data blob.
	 * 
	 * 
	 */
	public TcBlobData unbind(final TcIRsaKey key) throws TcTssException;


	/*************************************************************************************************
	 * This method encrypts a data blob in a manner that can only be decrypted by unseal on the same
	 * system. The data blob is encrypted using a public key operation with the non-migratable key
	 * addressed by the given encryption key object.
	 * 
	 * Additionally the seal operation allows software to explicitly state the future trusted
	 * configuration that the platform must be in for the encrypted data to be revealed and implicitly
	 * includes the relevant Platform Configuration Register (PCR) values when the seal operation was
	 * performed. Which PCR registers are going to be part of the seal operation is specified by the
	 * PCR composite object.
	 * 
	 * Beginning with the 1.2 TPM specification, the PCR object can also contain the locality at
	 * release and two sets of PCR values: The PCRs which are recorded at the time the sealing takes
	 * place (i.e. digest at creation) and those specifying the valid PCR state for the unseal
	 * operation. To create such a PCR composite object use the
	 * {@link TcTssConstants#TSS_PCRS_STRUCT_INFO_LONG} init flag when creating the PCR composite
	 * object on systems with a 1.2. TPM.
	 * 
	 * The maximum input size for seal operations is keySize - (40 - 2) - 65 where 65 accounts for the
	 * size of the {@link TcTpmSealedData} structure. It is left to the caller to properly block it
	 * input data according to this maximum size.
	 * 
	 * @TSS_V1 174
	 * 
	 * @TSS_1_2_EA 299
	 * 
	 * @param encKey The non-migratable key which is used to encrypt the data.
	 * @param data The data to be encrypted.
	 * @param pcrComposite The PCR values the encrypted data should be sealed to. Set to null to omit
	 *          sealing to PCR values.
	 * 
	 * 
	 */
	public void seal(final TcIRsaKey encKey, final TcBlobData data, final TcIPcrComposite pcrComposite)
		throws TcTssException;


	/*************************************************************************************************
	 * This method reveals data encrypted by Tspi_Data_Seal only if it was encrypted on the same
	 * platform and the current configuration (as defined by the named PCR contents of the encrypted
	 * data blob) is the one named as qualified to decrypt it. This is internally proofed and
	 * guaranteed by the TPM.
	 * 
	 * @TSS_V1 176
	 * 
	 * @TSS_1_2_EA 266
	 * 
	 * @param key non-migratable key which is used to decrypt the data
	 * @return decrypted data
	 * 
	 * 
	 */
	public TcBlobData unseal(final TcIRsaKey key) throws TcTssException;

}