/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.api.structs.tcs;


import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder;
import iaik.tc.tss.api.structs.tpm.TcTpmDigest;
import iaik.tc.tss.api.structs.tsp.TcTssUuid;
import iaik.tc.utils.logging.Log;
import iaik.tc.utils.misc.Utils;

public class TcTcsLoadkeyInfo extends TcCompositeTypeDecoder {

	/**
	 * Key UUID.
	 */
	protected TcTssUuid keyUuid_;

	
	/**
	 * Parent key UUID.
	 */
	protected TcTssUuid parentKeyUuid_;

	
	/**
	 * Parameter digest.
	 */
	protected TcTpmDigest paramDigest_ = null;


	/**
	 * Authorization data.
	 */
	protected TcTcsAuth authData_;
	

	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder()
	 */
	public TcTcsLoadkeyInfo()
	{
		super();
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcBlobData)
	 */
	public TcTcsLoadkeyInfo(TcBlobData data)
	{
		super(data);
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcBlobData,
	 *      int)
	 */
	public TcTcsLoadkeyInfo(TcBlobData data, int offset)
	{
		super(data, offset);
	}


	/*************************************************************************************************
	 * Constructor - see superclass for details
	 * 
	 * @see iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder#TcCompositeTypeDecoder(iaik.tc.tss.api.structs.common.TcCompositeTypeDecoder)
	 */
	public TcTcsLoadkeyInfo(TcCompositeTypeDecoder composite)
	{
		super(composite);
	}


	/*************************************************************************************************
	 * This method decodes the TCS_LOADKEY_INFO from the byte blob.
	 */
	protected void decode()
	{
		String msg = "decode method not implemented";
		Log.warn(msg);
		throw new RuntimeException(msg);
	}


	/*************************************************************************************************
	 * This method encodes the TCS_LOADKEY_INFO as a byte blob.
	 */
	public TcBlobData getEncoded()
	{
		String msg = "getEncoded method not implemented";
		Log.warn(msg);
		throw new RuntimeException(msg);
	}


	/*************************************************************************************************
	 * This method returns a String representation of the object.
	 */
	public String toString()
	{
		StringBuffer retVal = new StringBuffer();

		retVal.append("keyUuid: ");
		retVal.append(keyUuid_.toString());
		retVal.append(Utils.getNL());
		retVal.append("parentKeyUuid: ");
		retVal.append(parentKeyUuid_.toString());
		retVal.append(Utils.getNL());
		retVal.append("paramDigest: ");
		retVal.append(paramDigest_.toString());
		retVal.append(Utils.getNL());
		retVal.append("authData: ");
		retVal.append(authData_.toString());
		retVal.append(Utils.getNL());

		return retVal.toString();
	}


	/*************************************************************************************************
	 * This method returns the content of the authData field.
	 */
	public TcTcsAuth getAuthData()
	{
		return authData_;
	}


	/*************************************************************************************************
	 * This method sets the content of the authData field.
	 */
	public void setAuthData(TcTcsAuth authData)
	{
		authData_ = authData;
	}


	/*************************************************************************************************
	 * This method returns the content of the keyUuid field.
	 */
	public TcTssUuid getKeyUuid()
	{
		return keyUuid_;
	}


	/*************************************************************************************************
	 * This method sets the content of the keyUuid field.
	 */
	public void setKeyUuid(TcTssUuid keyUuid)
	{
		keyUuid_ = keyUuid;
	}


	/*************************************************************************************************
	 * This method returns the content of the paramDigest field.
	 */
	public TcTpmDigest getParamDigest()
	{
		return paramDigest_;
	}


	/*************************************************************************************************
	 * This method sets the content of the paramDigest field.
	 */
	public void setParamDigest(TcTpmDigest paramDigest)
	{
		paramDigest_ = paramDigest;
	}


	/*************************************************************************************************
	 * This method returns the content of the parentKeyUuid field.
	 */
	public TcTssUuid getParentKeyUuid()
	{
		return parentKeyUuid_;
	}


	/*************************************************************************************************
	 * This method sets the content of the parentKeyUuid field.
	 */
	public void setParentKeyUuid(TcTssUuid parentKeyUuid)
	{
		parentKeyUuid_ = parentKeyUuid;
	}


}
