/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.impl.java.tcs.kcmgr;

/**
 * This class holds all information about a key that is cached in the key cache.  
 */
public class TcTcsCachedKey {
	
	/**
	 * The type of the key is undefined/unknown.
	 */
	public final static byte CT_UNKNOWN = 0x00;
	
	/**
	 * The key has been saved using TPM 1.2 methods (TPM_SaveContext).
	 */
	public final static byte CT_SAVE_CONTEXT = 0x01;

	/**
	 * The key has been saved using TPM 1.1 methods (TPM_SaveKeyContext).
	 */
	public final static byte CT_SAVE_KEY_CONTEXT = 0x02;

	
	/**
	 * This field holds the type of the saved key.
	 */
	protected byte cachedKeyType_ = CT_UNKNOWN;
	
	
	/**
	 * The saved key blob.
	 */
	protected Object keyBlob_ = null;
	
	
	/**
	 * Constructor.
	 * 
	 * @param cachedKeyType The type of the key blob.
	 * @param keyBlob The key blob to be saved.
	 */
	public TcTcsCachedKey(byte cachedKeyType, Object keyBlob)
	{
		cachedKeyType_ = cachedKeyType;
		keyBlob_ = keyBlob;
	}
	
	
	/**
	 * This method returns the type of the key to be saved. 
	 */
	public byte getKeyType()
	{
		return cachedKeyType_;
	}
	

	/**
	 * This method returns the saved key blob. 
	 */
	public Object getKeyBlob()
	{
		return keyBlob_;
	}
}
