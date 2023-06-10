/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.api.structs.tpm;

import iaik.tc.tss.api.structs.common.TcBlobData;

/**
 * This class is a common interface for TcTpmPcrInfo (1.1 TPM Spec) and TcTpmPcrInfoLong (1.2 TPM Spec).
 * It combines the methods that the 1.1 and the 1.2 structure have in common into one interface. This
 * interface can then be used where either a 1.1 or a 1.2 structure can be used.
 */
public interface TcITpmPcrInfo {
	public TcTpmCompositeHash getDigestAtCreation();
	public void setDigestAtCreation(TcTpmCompositeHash digestAtCreation);
	public TcTpmCompositeHash getDigestAtRelease();
	public void setDigestAtRelease(TcTpmCompositeHash digestAtRelease);
	public TcBlobData getEncoded();
}
