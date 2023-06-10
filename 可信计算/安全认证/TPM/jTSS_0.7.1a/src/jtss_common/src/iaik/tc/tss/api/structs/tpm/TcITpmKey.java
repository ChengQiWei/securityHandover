/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.api.structs.tpm;

import iaik.tc.tss.api.structs.common.TcBlobData;


/**
 * This class is a common interface for TcTpmKey (1.1 TPM Spec) and TcTpmKey12 (1.2 TPM Spec).
 * This interface has no functionality. It's only purpose is that it is used in TSS functions
 * where both, TcTpmKey and TcTpmKey12 can be passed as arguments.
 */
public interface TcITpmKey {
	public TcBlobData getEncoded();
	public int getKeyUsage();
	public void setKeyUsage(int keyUsage);
	public long getKeyFlags();
	public void setKeyFlags(long keyFlags);
	public short getAuthDataUsage();
	public void setAuthDataUsage(short authDataUsage);
	public TcTpmKeyParms getAlgorithmParms();
	public void setAlgorithmParms(TcTpmKeyParms algorithmParms);
	public long getPcrInfoSize();
	public TcBlobData getPcrInfo();
	public void setPcrInfo(TcBlobData pcrInfo);
	public TcTpmStorePubkey getPubKey();
	public void setPubKey(TcTpmStorePubkey pubKey);
	public long getEncSize();
	public TcBlobData getEncData();
	public void setEncData(TcBlobData encData);
	public String toString();
}