/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

/**
 * On the PC platform, certficates such as the EK or platform certificate can be stored in non
 * volatile (NV) TPM storage. When reading such a certificate from NV, one obtains a 
 * TCG_PCCLIENT_STORED_CERT struct which is represented by this class.
 * 
 * @PCCLIENT_v12_r1 55
 */
package iaik.tc.tss.api.structs.pcclient;

import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder;
import iaik.tc.utils.misc.Utils;

public class TcTcgPcclientStoredCert extends TcCompositeTypeDecoder {

	/**
	 * The tag must be TCG_TAG_PCCLIENT_STORED_CERT.
	 */
	int tag_; // TPM_STRUCTURE_TAG (UINT16)
	
	/**
	 * This field determines the type of the certificate. This can be TCG_FULL_CERT or TCG_PARTIAL_SMALL_CERT.
	 */
	short certType_;
	
	/**
	 * The size of the certificate.
	 */
	int certSize_;
	
	
	/**
	 * The actual certificate.
	 */
	TcBlobData cert_;
	
	
	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder()
	 */
	public TcTcgPcclientStoredCert()
	{
		super();
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcBlobData)
	 */
	public TcTcgPcclientStoredCert(TcBlobData data)
	{
		super(data);
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcBlobData,
	 *      int)
	 */
	public TcTcgPcclientStoredCert(TcBlobData data, int offset)
	{
		super(data, offset);
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder)
	 */
	public TcTcgPcclientStoredCert(TcCompositeTypeDecoder composite)
	{
		super(composite);
	}


	/*************************************************************************************************
	 * This method decodes the TCG_PCCLIENT_STORED_CERT from the byte blob.
	 */
	protected void decode()
	{
		checkBoundaryPreconditions(5); // minimum size
		
		tag_ = decodeUINT16();
		certType_ = decodeByte();
		certSize_ = decodeUINT16();
		cert_ = null;
		if (certSize_ > 0) {
			cert_ = decodeBytes(certSize_);
		}
	}


	/*************************************************************************************************
	 * This method encodes the TCG_PCCLIENT_STORED_CERT as a byte blob.
	 */
	public TcBlobData getEncoded()
	{
		TcBlobData retVal = TcBlobData.newUINT16(tag_);
		retVal.append(TcBlobData.newBYTE(certType_));
		retVal.append(TcBlobData.newUINT16(certSize_));
		if (certSize_ > 0) {
			retVal.append(cert_);
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
		retVal.append("certType: ");
		retVal.append(certType_);
		retVal.append(Utils.getNL());
		retVal.append("certSize: ");
		retVal.append(certSize_);
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
	 * Returns contents of the certSize field.
	 */
	public int getCertSize()
	{
		return certSize_;
	}


	/*************************************************************************************************
	 * Sets the certSize field.
	 */
	public void setCertSize(int certSize)
	{
		certSize_ = certSize;
	}


	/*************************************************************************************************
	 * Returns contents of the certType field.
	 */
	public short getCertType()
	{
		return certType_;
	}


	/*************************************************************************************************
	 * Sets the tag field.
	 */
	public void setCertType(byte certType)
	{
		certType_ = certType;
	}


	/*************************************************************************************************
	 * Returns contents of the tag field.
	 */
	public int getTag()
	{
		return tag_;
	}


	/**
	 * @param tag the tag to set
	 */
	public void setTag(int tag)
	{
		tag_ = tag;
	}
}
