/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.api.structs.pcclient;

import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder;
import iaik.tc.utils.misc.Utils;

/**
 * This class holds an actual TCG certificate as stored in NV TPM storage.
 * 
 * @PCCLIENT_v12_r1 55
 */
public class TcTcgFullCert extends TcCompositeTypeDecoder {

	/**
	 * The tag must be TCG_TAG_PCCLIENT_STORED_CERT.
	 */
	int tag_; // TPM_STRUCTURE_TAG (UINT16)
	

	/**
	 * The size of the certificate.
	 */
	int certSize_;  // not part of the actual struct

	
	/**
	 * The actual certificate.
	 */
	TcBlobData cert_;  // min size: 2 bytes

	
	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder()
	 */
	public TcTcgFullCert()
	{
		super();
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcBlobData)
	 */
	public TcTcgFullCert(TcBlobData data)
	{
		super(data);
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcBlobData,
	 *      int)
	 */
	public TcTcgFullCert(TcBlobData data, int offset)
	{
		super(data, offset);
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder)
	 */
	public TcTcgFullCert(TcCompositeTypeDecoder composite)
	{
		super(composite);
	}

	
	/*************************************************************************************************
	 * This method decodes the TCG_FULL_CERT from the byte blob.
	 */
	protected void decode()
	{
		checkBoundaryPreconditions(4); // minimum size
		
		tag_ = decodeUINT16();
		// note: This struct has no certSize element. Therefore the rest of the blob is considered to
		// be the certificate.
		int certSize_ = blob_.getLength() - 2;
		if (certSize_ > 0) {
			cert_ = decodeBytes(certSize_);
		}
	}


	/*************************************************************************************************
	 * This method encodes the TCG_FULL_CERT as a byte blob.
	 */
	public TcBlobData getEncoded()
	{
		TcBlobData retVal = TcBlobData.newUINT16(tag_);
		if (cert_ != null) {
			retVal.append((TcBlobData)cert_.clone());
		}

		return retVal;
	}

	
	/*************************************************************************************************
	 * This method returns a String representation of the object.
	 */
	public String toString()
	{
		StringBuffer retVal = new StringBuffer();

		retVal.append("tag: ");
		retVal.append(tag_);
		retVal.append(Utils.getNL());
		if (cert_ != null) {
			retVal.append("cert: ");
			retVal.append(cert_.toHexString());
			retVal.append(Utils.getNL());
		}

		return retVal.toString();
	}
	

	/*************************************************************************************************
	 * Returns contents of the cert field.
	 */
	public TcBlobData getCert()
	{
		return cert_;
	}


	/*************************************************************************************************
	 * Sets the cert field.
	 */
	public void setCert(TcBlobData cert)
	{
		cert_ = cert;
	}


	/*************************************************************************************************
	 * Returns contents of the tag field.
	 */
	public int getTag()
	{
		return tag_;
	}


	/*************************************************************************************************
	 * Sets the tag field.
	 */
	public void setTag(int tag)
	{
		tag_ = tag;
	}

	
	/*************************************************************************************************
	 * Returns contents of the certSize field.
	 */
	public int getCertSize()
	{
		return certSize_;
	}

}
