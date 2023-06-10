/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.api.tspi;

import iaik.tc.tss.api.exceptions.common.TcTssException;
import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.tss.api.structs.tpm.TcTpmNvDataPublic;

/**
 * This class is used to store the attributes of a region of non volatile RAM
 * inside the TPM, for use when defining, releasing, reading or writing such a
 * region. This class establishes the size of the data space, the index, the
 * various authorizations required to either read or write that area. Those
 * authorizations can be based on PCR values or authorization data, but not
 * locality. The various attributes of the class are used to establish what is
 * requested before defineSpace is called (similar to the way a key is created).
 */
public interface TcINvRam extends TcIAttributes, TcIAuthObject {

	/*************************************************************************************************
	 * This method establishes the space necessary for the NV store. Note that
	 * this command requires owner authorization which can be set via the usage
	 * policy of the TPM object.
	 *
	 * <p>Be careful when defining indices with set <b>D-bit</b>. Indices which
	 * have this bit set might be unerasable on some TPMs. Some
	 * <b>TPM_NV_INDEX_*</b> constants have this bit set for compatibility
	 * reasons.
	 *
	 * @TSS_1_2_EA 381
	 *
	 * @param pubData
	 *            Complete {@link TcTpmNvDataPublic} object containing access
	 *            information for the newly created NV storage area.
	 *
	 */
	public void defineSpace(final TcTpmNvDataPublic pubData) throws TcTssException;

	/*************************************************************************************************
	 * This method releases the space associated with the NV store instance.
	 * Note that this command requires owner authorization which can be set via
	 * the usage policy of the TPM object.
	 *
	 * @TSS_1_2_EA 383
	 *
	 *
	 */
	public void releaseSpace() throws TcTssException;

	/*************************************************************************************************
	 * This method writes a given value to a previously defined area. If a
	 * policy object is assigned to this object, the authData within the policy
	 * object will be used to authorize this operation. If there is no policy
	 * object associated with this object, an unauthenticated write will be
	 * performed.
	 *
	 * @TSS_1_2_EA 384
	 *
	 * @param offset
	 *            The offset within the NV area to begin writing.
	 * @param dataToWrite
	 *            The data to be written.
	 *
	 *
	 */
	public void writeValue(final long offset, final TcBlobData dataToWrite)
			throws TcTssException;

	/*************************************************************************************************
	 * This method reads the data from the defined area. If a policy object is
	 * assigned to this object, the authData within the policy object will be
	 * used to authorize this operation. If there is no policy object associated
	 * with this object, an unauthenticated write will be performed. If the data
	 * is larger than the TPM input buffer size, it needs to be read in chunks.
	 * *
	 *
	 * @param offset
	 *            The offset within the NV area to begin reading.
	 * @param dataLength
	 *            The number of bytes to be read. The special value
	 *            <code>0xFFFFFFFF</code> activates Smart Read: the TSS will
	 *            determine the size of data automatically and assemble it
	 *            internally from its parts.
	 *
	 * @return The data read from the NV area.
	 *
	 *
	 */
	public TcBlobData readValue(final long offset, final long dataLength)
			throws TcTssException;

}
