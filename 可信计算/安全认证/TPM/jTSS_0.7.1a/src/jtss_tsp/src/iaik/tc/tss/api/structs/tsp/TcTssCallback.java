/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.api.structs.tsp;

import iaik.tc.tss.api.structs.common.TcBlobData;

/**
 * This class implements the TSS callback functionality conforming with the TSS 1.2 specification. 
 * 
 * @TSS_1_2_EA 113
 */
public abstract class TcTssCallback {

	/**
	 * Application data.
	 */
	protected TcBlobData appData_ = null;
	
	
	/**
	 * The symmetric algorithm to be used for masking data if that is chosen. 
	 */
	protected long alg_ = 0;
	
	
	/*************************************************************************************************
	 * When extending this class, this method has to be implemented. It has to implement the actual 
	 * callback functionality and is called by the TSP. 
	 */
	public abstract void callback();
	

	/*************************************************************************************************
	 * Clone method.
	 */
	public abstract Object clone();

	
	/*************************************************************************************************
	 * Default constructor.
	 */
	public TcTssCallback()
	{
	}


	/*************************************************************************************************
	 * This method returns the content of the alg field.
	 */
	public long getAlg()
	{
		return alg_;
	}


	/*************************************************************************************************
	 * This method sets the content of the alg field.
	 */
	public void setAlg(long alg)
	{
		alg_ = alg;
	}


	/*************************************************************************************************
	 * This method returns the content of the appData field.
	 */
	public TcBlobData getAppData()
	{
		return appData_;
	}


	/*************************************************************************************************
	 * This method sets the content of the appData field.
	 */
	public void setAppData(TcBlobData appData)
	{
		appData_ = appData;
	}
	
}
