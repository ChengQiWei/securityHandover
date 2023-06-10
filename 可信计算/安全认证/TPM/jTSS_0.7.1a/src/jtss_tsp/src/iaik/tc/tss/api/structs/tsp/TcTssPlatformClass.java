/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.api.structs.tsp;


import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.utils.misc.Utils;

/**
 * This structure identifies the class of a platform. The classes are defined by the TCG. The first
 * value is an unsigned integer which is a reference number that identifies the platform class. The
 * second value is an URI pointing to additional information on the platform maintained by the
 * platform manufacturer or the TCG. If this value is null, no additional information is available.
 * 
 * @TSS_1_2_EA 114
 */
public class TcTssPlatformClass {

	/**
	 * The value defining the platform as defined by an registered with the TCG administration.
	 */
	protected long platformClassIdentifier_ = 0;

	/**
	 * The reference to either the platform manufacturer or if the TCS provider can not or does not
	 * want to disclose the specific platform manufacturer, this is either null or contains a reference
	 * to the platform specific specification on the TCG website.
	 */
	protected TcBlobData uri_ = null;

	
	/*************************************************************************************************
	 * This method returns the content of the platformClassIdentifier field.
	 */
	public long getPlatformClassIdentifier()
	{
		return platformClassIdentifier_;
	}

	
	/*************************************************************************************************
	 * This method sets the content of the platformClassIdentifier field.
	 */
	public void setPlatformClassIdentifier(long platformClassIdentifier)
	{
		platformClassIdentifier_ = platformClassIdentifier;
	}

	
	/*************************************************************************************************
	 * This method returns the content of the uri field.
	 */
	public TcBlobData getUri()
	{
		return uri_;
	}

	
	/*************************************************************************************************
	 * This method sets the content of the uri field.
	 */
	public void setUri(TcBlobData uri)
	{
		uri_ = uri;
	}

	
	/*************************************************************************************************
	 * This method returns a string representation of the object.
	 */
	public String toString()
	{
		StringBuffer sb = new StringBuffer();
		
		sb.append("Platform Class Identifier: ");
		sb.append(platformClassIdentifier_);
		sb.append(Utils.getNL());
		sb.append("URI: ");
		if (uri_ != null) {
			sb.append(uri_.toString());
		} else {
			sb.append("not set");
		}
		sb.append(Utils.getNL());
		
		return sb.toString();
	}
}
