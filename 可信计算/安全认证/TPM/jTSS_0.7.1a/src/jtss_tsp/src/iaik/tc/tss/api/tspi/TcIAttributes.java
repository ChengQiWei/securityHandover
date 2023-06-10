/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.api.tspi;


import iaik.tc.tss.api.constants.tpm.TcTpmConstants;
import iaik.tc.tss.api.constants.tsp.TcTssConstants;
import iaik.tc.tss.api.exceptions.common.TcTssException;
import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.tss.api.structs.tsp.TcTssUuid;
import iaik.tc.tss.api.structs.tsp.TcTssVersion;

/**
 * This interface defines methods that are in common for all objects that support setting or getting
 * UINT32 and data attributes.
 */
public interface TcIAttributes {

	// TODO: replace javadoc with more generic version

	/*************************************************************************************************
	 * This method gets a non UINT32 attribute of the object (i.e. a binary data blob). The structure
	 * and size of the returned data depends on the attribute.
	 * 
	 * @TSS_V1 70
	 * 
	 * @TSS_1_2_EA 177
	 * 
	 * @param attribFlag Flag indicating the attribute to get. Attribute Flags are prefixed with
	 *          TSS_TSPATTRIB_ and are defined in {@link TcTssConstants}. Valid attributes depend on
	 *          the actual type of the object this method is called for. <br>
	 *          <br>
	 *          Valid <b>attribFlags for Context objects</b> are:
	 *          <ul>
	 *          <li>{@link TcTssConstants#TSS_TSPATTRIB_CONTEXT_MACHINE_NAME}</li>
	 *          </ul>
	 *          Valid <b>attribFlags for Policy objects</b> are:
	 *          <ul>
	 *          <li>{@link TcTssConstants#TSS_TSPATTRIB_POLICY_POPUPSTRING}</li>
	 *          </ul>
	 *          Valid <b>attribFlags for EncData objects</b> are:
	 *          <ul>
	 *          <li>{@link TcTssConstants#TSS_TSPATTRIB_ENCDATA_BLOB}</li>
	 *          <li>{@link TcTssConstants#TSS_TSPATTRIB_ENCDATA_PCR}</li>
	 *          </ul>
	 *          </ul>
	 *          Valid <b>attribFlags for Key objects</b> are:
	 *          <ul>
	 *          <li>{@link TcTssConstants#TSS_TSPATTRIB_KEY_BLOB}</li>
	 *          <li>{@link TcTssConstants#TSS_TSPATTRIB_KEY_INFO}</li>
	 *          <li>{@link TcTssConstants#TSS_TSPATTRIB_RSAKEY_INFO}</li>
	 *          <li>{@link TcTssConstants#TSS_TSPATTRIB_KEY_UUID}. To get this attribute as an
	 *          {@link TcTssUuid} instead of a blob use
	 *          {@link TcIRsaKey#getAttribUuid()}</li>
	 *          <li>{@link TcTssConstants#TSS_TSPATTRIB_KEY_PCR}</li>
	 *          </ul>
	 * 
	 * @param subFlag Sub flag indicating the attribute to get. <br>
	 *          <br>
	 *          Valid <b>subFlags for EncData objects</b> are:
	 *          <ul>
	 *          <li>{@link TcTssConstants#TSS_TSPATTRIB_ENCDATABLOB_BLOB}</li>
	 *          <li>{@link TcTssConstants#TSS_TSPATTRIB_ENCDATAPCR_DIGEST_ATCREATION}</li>
	 *          <li>{@link TcTssConstants#TSS_TSPATTRIB_ENCDATAPCR_DIGEST_RELEASE}</li>
	 *          <li>{@link TcTssConstants#TSS_TSPATTRIB_ENCDATAPCR_SELECTION}</li>
	 *          </ul>
	 *          Valid <b>subFlags for Key objects</b> are:
	 *          <ul>
	 *          <li>{@link TcTssConstants#TSS_TSPATTRIB_KEYBLOB_BLOB}</li>
	 *          <li>{@link TcTssConstants#TSS_TSPATTRIB_KEYBLOB_PRIVATE_KEY}</li>
	 *          <li>{@link TcTssConstants#TSS_TSPATTRIB_KEYBLOB_PUBLIC_KEY}</li>
	 *          <li>{@link TcTssConstants#TSS_TSPATTRIB_KEYINFO_VERSION}. To get this attribute as
	 *          an {@link TcTssVersion} instead of a blob use
	 *          {@link TcIRsaKey#getAttribKeyInfoVersion()}</li>
	 *          </li>
	 *          <li>{@link TcTssConstants#TSS_TSPATTRIB_KEYINFO_RSA_EXPONENT}</li>
	 *          <li>{@link TcTssConstants#TSS_TSPATTRIB_KEYINFO_RSA_MODULUS}</li>
	 *          <li>{@link TcTssConstants#TSS_TSPATTRIB_KEYPCR_DIGEST_ATCREATION}</li>
	 *          <li>{@link TcTssConstants#TSS_TSPATTRIB_KEYPCR_DIGEST_ATRELEASE}</li>
	 *          <li>{@link TcTssConstants#TSS_TSPATTRIB_KEYPCR_SELECTION}</li>
	 *          </ul>
	 * 
	 * Note: If an attribFlag does not take a subFlag, the subFlag might be set to 0.
	 * @return Buffer containing to the actual data of the specified attribute.
	 */
	public TcBlobData getAttribData(final long attribFlag, final long subFlag) throws TcTssException;


	/*************************************************************************************************
	 * This method sets a non UINT32 attribute (i.e. a binary data blob) of the object. The structure
	 * and size of the data data depends on the attribute.
	 * 
	 * @TSS_V1 69
	 * 
	 * @TSS_1_2_EA 175
	 * 
	 * @param attribFlag Flag indicating the attribute to set. Attribute Flags are prefixed with
	 *          TSS_TSPATTRIB_ and are defined in {@link TcTssConstants}. Valid attributes depend on
	 *          the actual type of the object this method is called for. <br>
	 *          <br>
	 *          Valid <b>attribFlags for Policy objects</b> are:
	 *          <ul>
	 *          <li>{@link TcTssConstants#TSS_TSPATTRIB_POLICY_POPUPSTRING}</li>
	 *          </ul>
	 *          Valid <b>attribFlags for EncData objects</b> are:
	 *          <ul>
	 *          <li>{@link TcTssConstants#TSS_TSPATTRIB_ENCDATA_BLOB}</li>
	 *          </ul>
	 *          Valid <b>attribFlags for Hash objects</b> are:
	 *          <ul>
	 *          <li>{@link TcTssConstants#TSS_TSPATTRIB_HASH_IDENTIFIER}</li>
	 *          </ul>
	 *          Valid <b>attribFlags for Key objects</b> are:
	 *          <ul>
	 *          <li>{@link TcTssConstants#TSS_TSPATTRIB_KEY_BLOB}</li>
	 *          </ul>
	 * 
	 * @param subFlag Sub flag indicating the attribute to set. <br>
	 *          <br>
	 *          Valid <b>subFlags for EncData objects</b> are:
	 *          <ul>
	 *          <li>{@link TcTssConstants#TSS_TSPATTRIB_ENCDATABLOB_BLOB}</li>
	 *          </ul>
	 *          Valid <b>subFlags for Key objects</b> are:
	 *          <ul>
	 *          <li>{@link TcTssConstants#TSS_TSPATTRIB_KEYBLOB_BLOB}</li>
	 *          <li>{@link TcTssConstants#TSS_TSPATTRIB_KEYBLOB_PRIVATE_KEY}</li>
	 *          <li>{@link TcTssConstants#TSS_TSPATTRIB_KEYBLOB_PUBLIC_KEY}</li>
	 *          </ul>
	 *          Note: If an attribFlag does not take a subFlag, the subFlag might be set to 0.
	 * @param attrib the actual data which is to be set for the specified attribute
	 * 
	 * 
	 */
	public void setAttribData(final long attribFlag, final long subFlag, final TcBlobData attrib)
		throws TcTssException;


	/*************************************************************************************************
	 * This method gets an UINT32 attribute of the object.
	 * 
	 * @TSS_V1 77
	 * 
	 * @TSS_1_2_EA 174
	 * 
	 * @param attribFlag Flag indicating the attribute to query. Attribute Flags are prefixed with
	 *          TSS_TSPATTRIB_ and are defined in {@link TcTssConstants}. Valid attributes depend on
	 *          the actual type of the object this method is called for. <br>
	 *          <br>
	 *          Valid <b>attribFlags for Context objects</b> are:
	 *          <ul>
	 *          <li>{@link TcTssConstants#TSS_TSPATTRIB_CONTEXT_SILENT_MODE}</li>
	 *          </ul>
	 *          <br>
	 *          Valid <b>attribFlags for Policy objects</b> are:
	 *          <ul>
	 *          <li>{@link TcTssConstants#TSS_TSPATTRIB_POLICY_CALLBACK_HMAC}</li>
	 *          <li>{@link TcTssConstants#TSS_TSPATTRIB_POLICY_CALLBACK_XOR_ENC}</li>
	 *          <li>{@link TcTssConstants#TSS_TSPATTRIB_POLICY_CALLBACK_TAKEOWNERSHIP}</li>
	 *          <li>{@link TcTssConstants#TSS_TSPATTRIB_POLICY_CALLBACK_CHANGEAUTHASYM}</li>
	 *          <li>{@link TcTssConstants#TSS_TSPATTRIB_POLICY_SECRET_LIFETIME}</li>
	 *          </ul>
	 *          Valid <b>attribFlags for Key objects</b> are:
	 *          <ul>
	 *          <li>{@link TcTssConstants#TSS_TSPATTRIB_KEY_REGISTER}</li>
	 *          <li>{@link TcTssConstants#TSS_TSPATTRIB_KEY_INFO}</li>
	 *          <li>{@link TcTssConstants#TSS_TSPATTRIB_RSAKEY_INFO}</li>
	 *          </ul>
	 * 
	 * @param subFlag Sub flag indicating the attribute to query. Sub-Flags are prefixed with
	 *          TSS_TSPATTRIB_ and are defined in {@link TcTssConstants}. <br>
	 *          <br>
	 *          Valid <b>subFlags for Policy objects</b> are:
	 *          <ul>
	 *          <li>{@link TcTssConstants#TSS_TSPATTRIB_POLICYSECRET_LIFETIME_ALWAYS}</li>
	 *          <li>{@link TcTssConstants#TSS_TSPATTRIB_POLICYSECRET_LIFETIME_COUNTER}</li>
	 *          <li>{@link TcTssConstants#TSS_TSPATTRIB_POLICYSECRET_LIFETIME_TIMER}</li>
	 *          </ul>
	 *          Valid <b>subFlags for Key objects</b> are:
	 *          <ul>
	 *          <li>{@link TcTssConstants#TSS_TSPATTRIB_KEYINFO_USAGE}</li>
	 *          <li>{@link TcTssConstants#TSS_TSPATTRIB_KEYINFO_MIGRATABLE}</li>
	 *          <li>{@link TcTssConstants#TSS_TSPATTRIB_KEYINFO_REDIRECTED}</li>
	 *          <li>{@link TcTssConstants#TSS_TSPATTRIB_KEYINFO_VOLATILE}</li>
	 *          <li>{@link TcTssConstants#TSS_TSPATTRIB_KEYINFO_AUTHDATAUSAGE}</li>
	 *          <li>{@link TcTssConstants#TSS_TSPATTRIB_KEYINFO_ALGORITHM}</li>
	 *          <li>{@link TcTssConstants#TSS_TSPATTRIB_KEYINFO_ENCSCHEME}</li>
	 *          <li>{@link TcTssConstants#TSS_TSPATTRIB_KEYINFO_SIGSCHEME}</li>
	 *          <li>{@link TcTssConstants#TSS_TSPATTRIB_KEYINFO_KEYFLAGS}</li>
	 *          <li>{@link TcTssConstants#TSS_TSPATTRIB_KEYINFO_AUTHUSAGE}</li>
	 *          <li>{@link TcTssConstants#TSS_TSPATTRIB_KEYINFO_RSA_KEYSIZE}</li>
	 *          <li>{@link TcTssConstants#TSS_TSPATTRIB_KEYINFO_RSA_PRIMES}</li>
	 *          </ul>
	 *          Note: If an attribFlag does not take a subFlag, the subFlag might be set to 0.
	 * 
	 * @return The value of the specified attribute Note: The returned UINT32 is represented by a Java
	 *         long data type to avoid problems when converting from unsigned C types to singed Java
	 *         types.
	 * 
	 * 
	 */
	public long getAttribUint32(final long attribFlag, final long subFlag) throws TcTssException;


	/*************************************************************************************************
	 * This method sets an UINT32 attribute of the object. If the data being set is smaller than an
	 * UINT32, casting must be used to get the data to the right size.
	 * 
	 * @TSS_V1 76
	 * 
	 * @TSS_1_2_EA 172
	 * 
	 * @param attribFlag Flag indicating the attribute to set. Attribute Flags are prefixed with
	 *          TSS_TSPATTRIB_ and are defined in {@link TcTpmConstants}.
	 *          Valid attributes depend on the actual type of the object this method is called for.
	 *          <br>
	 *          <br>
	 *          Valid <b>attribFlags for Context objects</b> are:
	 *          <ul>
	 *          <li>{@link TcTssConstants#TSS_TSPATTRIB_CONTEXT_SILENT_MODE}</li>
	 *          </ul>
	 *          Valid <b>attribFlags for Policy objects</b> are:
	 *          <ul>
	 *          <li>{@link TcTssConstants#TSS_TSPATTRIB_POLICY_CALLBACK_HMAC}</li>
	 *          <li>{@link TcTssConstants#TSS_TSPATTRIB_POLICY_CALLBACK_XOR_ENC}</li>
	 *          <li>{@link TcTssConstants#TSS_TSPATTRIB_POLICY_CALLBACK_TAKEOWNERSHIP}</li>
	 *          <li>{@link TcTssConstants#TSS_TSPATTRIB_POLICY_CALLBACK_CHANGEAUTHASYM}</li>
	 *          <li>{@link TcTssConstants#TSS_TSPATTRIB_POLICY_SECRET_LIFETIME}</li>
	 *          </ul>
	 *          Valid <b>attribFlags for Key objects</b> are:
	 *          <ul>
	 *          <li>{@link TcTssConstants#TSS_TSPATTRIB_KEY_BLOB}</li>
	 *          <li>{@link TcTssConstants#TSS_TSPATTRIB_KEY_INFO}</li>
	 *          <li>{@link TcTssConstants#TSS_TSPATTRIB_RSAKEY_INFO}</li>
	 *          </ul>
	 * 
	 * @param subFlag Sub flag indicating the attribute to set. Sub-Flags are prefixed with
	 *          TSS_TSPATTRIB_ and are defined in {@link TcTssConstants}. <br>
	 *          <br>
	 *          Valid <b>subFlags for Policy objects</b> are:
	 *          <ul>
	 *          <li>{@link TcTssConstants#TSS_TSPATTRIB_POLICYSECRET_LIFETIME_ALWAYS}</li>
	 *          <li>{@link TcTssConstants#TSS_TSPATTRIB_POLICYSECRET_LIFETIME_COUNTER}</li>
	 *          <li>{@link TcTssConstants#TSS_TSPATTRIB_POLICYSECRET_LIFETIME_TIMER}</li>
	 *          </ul>
	 *          Valid <b>subFlags for Key objects</b> are:
	 *          <ul>
	 *          <li>{@link TcTssConstants#TSS_TSPATTRIB_KEYINFO_USAGE}</li>
	 *          <li>{@link TcTssConstants#TSS_TSPATTRIB_KEYINFO_MIGRATABLE}</li>
	 *          <li>{@link TcTssConstants#TSS_TSPATTRIB_KEYINFO_REDIRECTED}</li>
	 *          <li>{@link TcTssConstants#TSS_TSPATTRIB_KEYINFO_VOLATILE}</li>
	 *          <li>{@link TcTssConstants#TSS_TSPATTRIB_KEYINFO_AUTHDATAUSAGE}</li>
	 *          <li>{@link TcTssConstants#TSS_TSPATTRIB_KEYINFO_ALGORITHM}</li>
	 *          <li>{@link TcTssConstants#TSS_TSPATTRIB_KEYINFO_ENCSCHEME}</li>
	 *          <li>{@link TcTssConstants#TSS_TSPATTRIB_KEYINFO_SIGSCHEME}</li>
	 *          <li>{@link TcTssConstants#TSS_TSPATTRIB_KEYINFO_SIZE}</li>
	 *          <li>{@link TcTssConstants#TSS_TSPATTRIB_KEYINFO_KEYFLAGS}</li>
	 *          <li>{@link TcTssConstants#TSS_TSPATTRIB_KEYINFO_AUTHUSAGE}</li>
	 *          <li>{@link TcTssConstants#TSS_TSPATTRIB_KEYINFO_RSA_PRIMES}</li>
	 *          </ul>
	 *          Note: If an attribFlag does not take a subFlag, the subFlag might be set to 0.
	 * 
	 * @param attrib Value which is to be set for the specified attribute. Only non-negative arguments
	 *          are allowed. Note: The UINT32 is represented by a Java long data type to avoid
	 *          problems when converting from singed Java types to unsigned C types.
	 * 
	 * 
	 */
	public void setAttribUint32(final long attribFlag, final long subFlag, final long attrib)
		throws TcTssException;

}
