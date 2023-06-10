/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.api.structs.tpm;

/**
 * This class is a common interface for TcTpmKeyNew (1.1 TPM Spec) and TcTpmKey12New (1.2 TPM Spec).
 * This interface has no functionality. It's only purpose is that it is used in PBG functions
 * where both, TcTpmKeyNew and TcTpmKey12New can be passed as arguments (e.g. CreateWrapKey).
 */
public interface TcITpmKeyNew extends TcITpmKey {

}
