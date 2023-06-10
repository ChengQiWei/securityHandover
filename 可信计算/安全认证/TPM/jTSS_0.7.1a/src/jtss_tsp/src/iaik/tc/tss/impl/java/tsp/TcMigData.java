/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Christian Pointner
 */

package iaik.tc.tss.impl.java.tsp;

import iaik.tc.tss.api.constants.tpm.TcTpmConstants;
import iaik.tc.tss.api.constants.tsp.TcTssConstants;
import iaik.tc.tss.api.constants.tsp.TcTssErrors;
import iaik.tc.tss.api.exceptions.common.TcTssException;
import iaik.tc.tss.api.exceptions.tsp.TcTspException;
import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.tss.api.structs.tpm.TcTpmDigest;
import iaik.tc.tss.api.structs.tpm.TcTpmMsaComposite;
import iaik.tc.tss.api.tspi.TcIAttributes;
import iaik.tc.tss.api.tspi.TcIMigData;

public class TcMigData extends TcWorkingObject implements TcIMigData {

	
	/**
	 * This blob contains the migration ticket computed by Tspi_AuthorizeMigrationTicket(). This
	 * blob can be set using the {@link TcTssConstants#TSS_MIGATTRIB_MIGRATIONTICKET} attribute.
	 */
	protected TcBlobData migTicket_ = null;
	
	/**
	 * This field contains an arbitrary number of digests of public keys belonging to 
	 * Migration Authorities. The list can be directly set or retrieved using the 
	 * {@link TcTssConstants#TSS_MIGATTRIB_AUTHORITY_MSALIST} attribute or manipulated by 
	 * adding a public key using the  {@link TcTssConstants#TSS_MIGATTRIB_MIG_MSALIST_PUBKEY_BLOB} 
	 * attribute.
	 */	
	protected TcTpmMsaComposite msaList_ = null;

	/**
	 * This field contains the msa list digest. It can be set or retrieved using the 
	 * {@link TcTssConstants#TSS_MIGATTRIB_AUTHORITY_DIGEST} attribute.
	 */	
	protected TcTpmDigest msaDigest_ = null;
	
	/**
	 * This field contains the authority HMAC. It can be set or retrieved using the 
	 * {@link TcTssConstants#TSS_MIGATTRIB_AUTHORITY_APPROVAL_HMAC} attribute.
 	 */	
	protected TcTpmDigest msaHmac_ = null;
	
	/**
	 * This field contains the digest of the authority public key. It can be directly set
	 * or retrieved by using the {@link TcTssConstants#TSS_MIGATTRIB_MIG_AUTH_AUTHORITY_DIGEST} 
	 * attribute or indirectly by using the {@link TcTssConstants#TSS_MIGATTRIB_MIG_AUTHORITY_PUBKEY_BLOB}
	 * attribute. In the later case a digest get computed form the public key and stored in the
	 * field. The key itself is not stored.
	 */	
	protected TcTpmDigest maDigest_ = null;
	
	/**
	 * This field contains the digest of the destination public key. It can be directly set
	 * or retrieved by using the {@link TcTssConstants#TSS_MIGATTRIB_MIG_AUTH_DESTINATION_DIGEST} 
	 * attribute or indirectly by using the {@link TcTssConstants#TSS_MIGATTRIB_MIG_DESTINATION_PUBKEY_BLOB}
	 * attribute. In the later case a digest get computed form the public key and stored in the
	 * field. The key itself is not stored.
	 */	
	protected TcTpmDigest destDigest_ = null;
	
	/**
	 * This field contains the digest of the source public key. It can be directly set
	 * or retrieved by using the {@link TcTssConstants#TSS_MIGATTRIB_MIG_AUTH_SOURCE_DIGEST} 
	 * attribute or indirectly by using the {@link TcTssConstants#TSS_MIGATTRIB_MIG_SOURCE_PUBKEY_BLOB}
	 * attribute. In the later case a digest get computed form the public key and stored in the
	 * field. The key itself is not stored.
	 */	
	protected TcTpmDigest srcDigest_ = null;
	
	/**
	 * This field contains the signature digest. It can be set or retrieved using the 
	 * {@link TcTssConstants#TSS_MIGATTRIB_TICKET_SIG_DIGEST} attribute. 
	 */	
	protected TcTpmDigest sigData_ = null;
	
	/**
	 * This blob contains the signature value. It can be set or retrieved using the 
	 * {@link TcTssConstants#TSS_MIGATTRIB_TICKET_SIG_VALUE} attribute. 
	 */	
	protected TcBlobData sigValue_ = null; 
	
	/**
	 * This field contains the signature ticket. It can be set or retrieved using the 
	 * {@link TcTssConstants#TSS_MIGATTRIB_TICKET_SIG_TICKET} attribute.
 	 */	
	protected TcTpmDigest sigTicket_ = null;

	/**
 	 * This blob contains the migration XOR blob. It can be retrieved using the 
	 * {@link TcTssConstants#TSS_MIGATTRIB_MIGRATION_XOR_BLOB} attribute. 
	 */	
	protected TcBlobData blob_ = null;

	
	
	/*************************************************************************************************
	 * Hidden constructor (factory pattern).
	 */
	protected TcMigData(TcContext context) throws TcTssException
	{
		super(context);
	}
	
	// ----------------------------------------------------------------------------------------------
	// TSS attribute getters and setter
	// ----------------------------------------------------------------------------------------------

	/*************************************************************************************************
	 * This method defines the mapping of attribute flags to getter methods.
	 */
	protected void initAttribGetters() 
	{
		addGetterData(TcTssConstants.TSS_MIGATTRIB_MIGRATIONBLOB, "getAttribMigrationBlob");
		addGetterData(TcTssConstants.TSS_MIGATTRIB_AUTHORITY_DATA, "getAttribAuthorityData");
		addGetterData(TcTssConstants.TSS_MIGATTRIB_TICKET_DATA, "getAttribTicketData");
		addGetterData(TcTssConstants.TSS_MIGATTRIB_MIG_AUTH_DATA, "getAttribMigAuthData");
	}


	/*************************************************************************************************
	 * This method defines the mapping of attribute flags to setter methods.
	 */
	protected void initAttribSetters() 
	{
		addSetterData(TcTssConstants.TSS_MIGATTRIB_MIGRATIONBLOB, "setAttribMigrationBlob");
		addSetterData(TcTssConstants.TSS_MIGATTRIB_AUTHORITY_DATA, "setAttribAuthorityData");
		addSetterData(TcTssConstants.TSS_MIGATTRIB_TICKET_DATA, "setAttribTicketData");
		addSetterData(TcTssConstants.TSS_MIGATTRIB_MIGRATIONTICKET, "setAttribMigrationTicket");
		addSetterData(TcTssConstants.TSS_MIGATTRIB_MIG_AUTH_DATA, "setAttribMigAuthData");
	}

	/*************************************************************************************************
	 * Internal method to recalculate the signature digest 
	 */
	private void calcSigDataDigest()
	{
		if(maDigest_ == null || destDigest_ == null || srcDigest_ == null)
			return;
		
		TcBlobData blob = TcBlobData.newBlobData(maDigest_.getDigest());
		blob.append(destDigest_.getDigest());
		blob.append(srcDigest_.getDigest());
		if(sigData_ == null)
			sigData_ = new TcTpmDigest();
		sigData_.setDigest(blob.sha1());
	}
	
	/*************************************************************************************************
	 * This method allows to set the public key blob. This method is an alternative to using 
	 * {@link TcIAttributes#setAttribData(long, long, TcBlobData)} with 
	 * {@link TcTssConstants#TSS_MIGATTRIB_MIGRATIONBLOB} as flag.
	 * 
	 * @param subFlag Valid subFlags are:
	 *          {@link TcTssConstants#TSS_MIGATTRIB_MIG_MSALIST_PUBKEY_BLOB}.
     *			{@link TcTssConstants#TSS_MIGATTRIB_MIG_AUTHORITY_PUBKEY_BLOB}.
     *			{@link TcTssConstants#TSS_MIGATTRIB_MIG_DESTINATION_PUBKEY_BLOB}.
     *			{@link TcTssConstants#TSS_MIGATTRIB_MIG_SOURCE_PUBKEY_BLOB}.
	 * @param data The data to set.
	 */
	public synchronized void setAttribMigrationBlob(long subFlag, TcBlobData data) throws TcTspException
	{
		if (subFlag == TcTssConstants.TSS_MIGATTRIB_MIG_MSALIST_PUBKEY_BLOB) {
			if(msaList_ == null)
				msaList_ = new TcTpmMsaComposite();
			int oldLength = 0;
			if(msaList_.getMigAuthDigest() != null)
				oldLength = msaList_.getMigAuthDigest().length;
			TcTpmDigest[] newList = new TcTpmDigest[oldLength + 1];
			if(msaList_.getMigAuthDigest() != null)
				System.arraycopy(msaList_.getMigAuthDigest(), 0, newList, 0, oldLength);
			newList[oldLength] = new TcTpmDigest(data.sha1());
			msaList_.setMigAuthDigest(newList);
			msaList_.setMsaList(oldLength+1);
			if(msaDigest_ == null)
				msaDigest_ = new TcTpmDigest();
			msaDigest_.setDigest(msaList_.getEncoded().sha1());
		} else if (subFlag == TcTssConstants.TSS_MIGATTRIB_MIG_AUTHORITY_PUBKEY_BLOB) {
			if(maDigest_ == null)
				maDigest_ = new TcTpmDigest();
			maDigest_.setDigest(data.sha1()); 
			calcSigDataDigest();
		} else if (subFlag == TcTssConstants.TSS_MIGATTRIB_MIG_DESTINATION_PUBKEY_BLOB) {
			if(destDigest_ == null)
				destDigest_ = new TcTpmDigest();
			destDigest_.setDigest(data.sha1());
			calcSigDataDigest();
		} else if (subFlag == TcTssConstants.TSS_MIGATTRIB_MIG_SOURCE_PUBKEY_BLOB) {
			if(srcDigest_ == null)
				srcDigest_ = new TcTpmDigest();
			srcDigest_.setDigest(data.sha1());
			calcSigDataDigest();
		} else {
			throw new TcTspException(TcTssErrors.TSS_E_INVALID_ATTRIB_SUBFLAG);
		}
	}

	/*************************************************************************************************
	 * This method allows to set data belonging to the authority. This method is an alternative 
	 * to using {@link TcIAttributes#setAttribData(long, long, TcBlobData)} with 
	 * {@link TcTssConstants#TSS_MIGATTRIB_AUTHORITY_DATA} as flag.
	 * 
	 * @param subFlag Valid subFlags are:
	 *          {@link TcTssConstants#TSS_MIGATTRIB_AUTHORITY_DIGEST}.
	 *          {@link TcTssConstants#TSS_MIGATTRIB_AUTHORITY_APPROVAL_HMAC}.
	 *          {@link TcTssConstants#TSS_MIGATTRIB_AUTHORITY_MSALIST}.
	 * @param data The data to set.
	 */
	public synchronized void setAttribAuthorityData(long subFlag, TcBlobData data) throws TcTspException
	{
		if (subFlag == TcTssConstants.TSS_MIGATTRIB_AUTHORITY_DIGEST) {
			if(msaDigest_ == null)
				msaDigest_ = new TcTpmDigest();
			msaDigest_.setDigest(data);
		} else if (subFlag == TcTssConstants.TSS_MIGATTRIB_AUTHORITY_APPROVAL_HMAC) {
			if(msaHmac_ == null)
				msaHmac_ = new TcTpmDigest();
			msaHmac_.setDigest(data);
		} else if (subFlag == TcTssConstants.TSS_MIGATTRIB_AUTHORITY_MSALIST) {
			long size = (long)data.getLength() / TcTpmConstants.TPM_SHA1_160_HASH_LEN;
			TcBlobData listData = TcBlobData.newUINT32(size);
			listData.append(data);
			msaList_ = new TcTpmMsaComposite(listData);
			msaList_.setMsaList(size);
			if(msaDigest_ == null)
				msaDigest_ = new TcTpmDigest();
			msaDigest_.setDigest(msaList_.getEncoded().sha1());
		} else {
			throw new TcTspException(TcTssErrors.TSS_E_INVALID_ATTRIB_SUBFLAG);
		}
	}

	/*************************************************************************************************
	 * This method allows to set data belonging to the migration ticket. This method is an alternative 
	 * to using {@link TcIAttributes#setAttribData(long, long, TcBlobData)} with 
	 * {@link TcTssConstants#TSS_MIGATTRIB_TICKET_DATA} as flag.
	 * 
	 * @param subFlag Valid subFlags are:
	 *          {@link TcTssConstants#TSS_MIGATTRIB_TICKET_SIG_DIGEST}.
	 *          {@link TcTssConstants#TSS_MIGATTRIB_TICKET_SIG_VALUE}.
	 *          {@link TcTssConstants#TSS_MIGATTRIB_TICKET_SIG_TICKET}.
	 *          {@link TcTssConstants#TSS_MIGATTRIB_TICKET_RESTRICT_TICKET}.
	 * @param data The data to set.
	 */
	public synchronized void setAttribTicketData(long subFlag, TcBlobData data) throws TcTspException
	{
		if (subFlag == TcTssConstants.TSS_MIGATTRIB_TICKET_SIG_DIGEST) {
			if(sigData_ == null)
				sigData_ = new TcTpmDigest();
			sigData_.setDigest(data);
		} else if (subFlag == TcTssConstants.TSS_MIGATTRIB_TICKET_SIG_VALUE) {
			sigValue_ = data;
		} else if (subFlag == TcTssConstants.TSS_MIGATTRIB_TICKET_SIG_TICKET) {
			if(sigTicket_ == null)
				sigTicket_ = new TcTpmDigest();
			sigTicket_.setDigest(data);
		} else if (subFlag == TcTssConstants.TSS_MIGATTRIB_TICKET_RESTRICT_TICKET) {
			if(maDigest_ == null)
				maDigest_ = new TcTpmDigest();
			if(destDigest_ == null)
				destDigest_ = new TcTpmDigest();
			if(srcDigest_ == null)
				srcDigest_ = new TcTpmDigest();
			maDigest_.setDigest(TcBlobData.newByteArray(data.getRange(0, (int)TcTpmConstants.TPM_SHA1_160_HASH_LEN)));
			destDigest_.setDigest(TcBlobData.newByteArray(data.getRange((int)TcTpmConstants.TPM_SHA1_160_HASH_LEN, (int)TcTpmConstants.TPM_SHA1_160_HASH_LEN)));
			srcDigest_.setDigest(TcBlobData.newByteArray(data.getRange(2*(int)TcTpmConstants.TPM_SHA1_160_HASH_LEN, (int)TcTpmConstants.TPM_SHA1_160_HASH_LEN)));
			calcSigDataDigest();
		} else {
			throw new TcTspException(TcTssErrors.TSS_E_INVALID_ATTRIB_SUBFLAG);
		}
	}

	/*************************************************************************************************
	 * This method allows to set the migration ticket data from the authorize migration key proceess. 
	 * This method is an alternative to using {@link TcIAttributes#setAttribData(long, long, TcBlobData)} 
	 * with {@link TcTssConstants#TSS_MIGATTRIB_MIGRATIONTICKET} as flag.
	 * 
	 * @param subFlag Valid subFlags are 0
	 * @param data The data to set.
	 */
	public synchronized void setAttribMigrationTicket(long subFlag, TcBlobData data) throws TcTspException
	{
		if(subFlag != 0)
			throw new TcTspException(TcTssErrors.TSS_E_INVALID_ATTRIB_SUBFLAG);

		migTicket_ = data;
	}

	/*************************************************************************************************
	 * This method allows to set authenticating data. This method is an alternative to using 
	 * {@link TcIAttributes#setAttribData(long, long, TcBlobData)} with 
	 * {@link TcTssConstants#TSS_MIGATTRIB_MIG_AUTH_DATA} as flag.
	 * 
	 * @param subFlag Valid subFlags are:
	 *          {@link TcTssConstants#TSS_MIGATTRIB_MIG_AUTH_AUTHORITY_DIGEST}.
	 *          {@link TcTssConstants#TSS_MIGATTRIB_MIG_AUTH_DESTINATION_DIGEST}.
	 *          {@link TcTssConstants#TSS_MIGATTRIB_MIG_AUTH_SOURCE_DIGEST}.
	 * @param data The data to set.
	 */
	public synchronized void setAttribMigAuthData(long subFlag, TcBlobData data) throws TcTspException
	{
		if (subFlag == TcTssConstants.TSS_MIGATTRIB_MIG_AUTH_AUTHORITY_DIGEST) {
			if(maDigest_ == null)
				maDigest_ = new TcTpmDigest();
			maDigest_.setDigest(data); 
			calcSigDataDigest();
		} else if (subFlag == TcTssConstants.TSS_MIGATTRIB_MIG_AUTH_DESTINATION_DIGEST) {
			if(destDigest_ == null)
				destDigest_ = new TcTpmDigest();
			destDigest_.setDigest(data);
			calcSigDataDigest();
		} else if (subFlag == TcTssConstants.TSS_MIGATTRIB_MIG_AUTH_SOURCE_DIGEST) {
			if(srcDigest_ == null)
				srcDigest_ = new TcTpmDigest();
			srcDigest_.setDigest(data);
			calcSigDataDigest();
		} else {
			throw new TcTspException(TcTssErrors.TSS_E_INVALID_ATTRIB_SUBFLAG);
		}
	}

	/*************************************************************************************************
	 * This method is used to retrieve the migration xor blob. This method is an alternative
	 * to using {@link TcIAttributes#getAttribData(long, long)} with
	 * {@link TcTssConstants#TSS_MIGATTRIB_MIGRATIONBLOB} as flag.
	 * 
	 * @param subFlag Valid subFlags are {@link TcTssConstants#TSS_MIGATTRIB_MIGRATION_XOR_BLOB}
	 * @return The requested information.
	 */
	public synchronized TcBlobData getAttribMigrationBlob(long subFlag) throws TcTspException
	{
		if (subFlag != TcTssConstants.TSS_MIGATTRIB_MIGRATION_XOR_BLOB)
			throw new TcTspException(TcTssErrors.TSS_E_INVALID_ATTRIB_SUBFLAG);	

		if(blob_ == null)
			throw new TcTspException(TcTssErrors.TSS_E_FAIL, "xor blob not set.");
		
		return blob_;
	}

	/*************************************************************************************************
	 * This method is used to retrieve authority data. This method is an alternative
	 * to using {@link TcIAttributes#getAttribData(long, long)} with
	 * {@link TcTssConstants#TSS_MIGATTRIB_AUTHORITY_DATA} as flag.
	 * 
	 * @param subFlag Valid subFlags are:
	 * 			 {@link TcTssConstants#TSS_MIGATTRIB_AUTHORITY_DIGEST}
	 * 			 {@link TcTssConstants#TSS_MIGATTRIB_AUTHORITY_APPROVAL_HMAC}
	 * 			 {@link TcTssConstants#TSS_MIGATTRIB_AUTHORITY_MSALIST}
	 * @return The requested information.
	 */
	public synchronized TcBlobData getAttribAuthorityData(long subFlag) throws TcTspException
	{
		if (subFlag == TcTssConstants.TSS_MIGATTRIB_AUTHORITY_DIGEST) {
			if(msaDigest_ == null)
				throw new TcTspException(TcTssErrors.TSS_E_FAIL, "msa digest not set.");
			return msaDigest_.getDigest();
		} else if (subFlag == TcTssConstants.TSS_MIGATTRIB_AUTHORITY_APPROVAL_HMAC) {
			if(msaHmac_ == null)
				throw new TcTspException(TcTssErrors.TSS_E_FAIL, "msa hmac not set."); 
			return msaHmac_.getDigest();
		} else if (subFlag == TcTssConstants.TSS_MIGATTRIB_AUTHORITY_MSALIST) {
			if(msaList_ == null)
				throw new TcTspException(TcTssErrors.TSS_E_FAIL, "msa list not set.");
			if(msaList_.getMsaList() <= 0)
				throw new TcTspException(TcTssErrors.TSS_E_FAIL, "msa list is empty.");
			TcBlobData list = msaList_.getMigAuthDigest()[0].getEncoded();
			for (int i = 1; i < msaList_.getMsaList(); i++) {
				list.append(msaList_.getMigAuthDigest()[i].getEncoded());
			}
			return list;
		} else {
			throw new TcTspException(TcTssErrors.TSS_E_INVALID_ATTRIB_SUBFLAG);
		}
	}


	/*************************************************************************************************
	 * This method is used to retrieve ticket data. This method is an alternative
	 * to using {@link TcIAttributes#getAttribData(long, long)} with
	 * {@link TcTssConstants#TSS_MIGATTRIB_TICKET_DATA} as flag.
	 * 
	 * @param subFlag Valid subFlags are {@link TcTssConstants#TSS_MIGATTRIB_TICKET_SIG_TICKET}
	 * @return The requested information.
	 */
	public synchronized TcBlobData getAttribTicketData(long subFlag) throws TcTspException
	{
		if (subFlag != TcTssConstants.TSS_MIGATTRIB_TICKET_SIG_TICKET) 
			throw new TcTspException(TcTssErrors.TSS_E_INVALID_ATTRIB_SUBFLAG);

		if(sigTicket_ == null)
			throw new TcTspException(TcTssErrors.TSS_E_FAIL, "sig ticket is not set.");
		return sigTicket_.getEncoded();
	}


	/*************************************************************************************************
	 * This method is used to retrieve authenticating data. This method is an alternative
	 * to using {@link TcIAttributes#getAttribData(long, long)} with
	 * {@link TcTssConstants#TSS_MIGATTRIB_MIG_AUTH_DATA} as flag.
	 * 
	 * @param subFlag Valid subFlags are:
	 * 			 {@link TcTssConstants#TSS_MIGATTRIB_MIG_AUTH_AUTHORITY_DIGEST}
	 * 			 {@link TcTssConstants#TSS_MIGATTRIB_MIG_AUTH_DESTINATION_DIGEST}
	 * 			 {@link TcTssConstants#TSS_MIGATTRIB_MIG_AUTH_SOURCE_DIGEST}
	 * @return The requested information.
	 */
	public synchronized TcBlobData getAttribMigAuthData(long subFlag) throws TcTspException
	{
		if (subFlag == TcTssConstants.TSS_MIGATTRIB_MIG_AUTH_AUTHORITY_DIGEST) {
			if(maDigest_ == null)
				throw new TcTspException(TcTssErrors.TSS_E_FAIL, "ma digest not set.");
			return maDigest_.getDigest(); 
		} else if (subFlag == TcTssConstants.TSS_MIGATTRIB_MIG_AUTH_DESTINATION_DIGEST) {
			if(destDigest_ == null)
				throw new TcTspException(TcTssErrors.TSS_E_FAIL, "destination digest not set."); 
			return destDigest_.getDigest();
		} else if (subFlag == TcTssConstants.TSS_MIGATTRIB_MIG_AUTH_SOURCE_DIGEST) {
			if(srcDigest_ == null)
				throw new TcTspException(TcTssErrors.TSS_E_FAIL, "source digest not set."); 
			return srcDigest_.getDigest();
		} else {
			throw new TcTspException(TcTssErrors.TSS_E_INVALID_ATTRIB_SUBFLAG);
		}
	}

	/**
	 * This method is intended to be used by jTSS internal only
	 * 
	 * @param blob the xor blob
	 */
	public void setBlob(TcBlobData blob) {
		blob_ = blob;
	}
	
	/**
	 * This method is intended to be used by jTSS internal only
	 * 
	 * @return the migTicket_
	 */
	public TcBlobData getMigrationTicket() {
		return migTicket_;
	}

	/**
	 * This method is intended to be used by jTSS internal only
	 * 
	 * @return the msaList_
	 */
	public TcTpmMsaComposite getMsaList() {
		return msaList_;
	}

	/**
	 * This method is intended to be used by jTSS internal only
	 * 
	 * @return the sigData_
	 */
	public TcTpmDigest getSigData() {
		return sigData_;
	}

	/**
	 * This method is intended to be used by jTSS internal only
	 * 
	 * @return the sigValue_
	 */
	public TcBlobData getSigValue() {
		return sigValue_;
	}

	/**
	 * This method is intended to be used by jTSS internal only
	 * 
	 * @return the restrictTicket
	 */
	public TcBlobData getRestrictTicket() {
		TcBlobData retVal = maDigest_.getEncoded();
		retVal.append(destDigest_.getEncoded());
		retVal.append(srcDigest_.getEncoded());
		return retVal;
	}
}
