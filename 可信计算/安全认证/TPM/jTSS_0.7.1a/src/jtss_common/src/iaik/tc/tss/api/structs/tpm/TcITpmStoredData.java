/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.api.structs.tpm;

import iaik.tc.tss.api.structs.common.TcBlobData;

/**
 * This class is a common interface for TcTpmStoredData (1.1 TPM Spec) and TcTpmStoredData12 (1.2 TPM Spec).
 * It combines the methods that the 1.1 and the 1.2 structure have in common into one interface. This
 * interface can then be used where either a 1.1 or a 1.2 structure can be used.
 */
public interface TcITpmStoredData {
	public TcBlobData getSealInfo();
	public void setSealInfo(TcBlobData sealInfo);
	public long getSealInfoSize();
	public TcBlobData getEncData();
	public void setEncData(TcBlobData encData);
	public long getEncDataSize();
	public TcBlobData getEncoded();
}
