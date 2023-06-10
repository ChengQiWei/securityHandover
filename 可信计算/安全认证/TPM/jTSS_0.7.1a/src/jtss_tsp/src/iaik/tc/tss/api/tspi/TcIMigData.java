/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Christian Pointner
 */

package iaik.tc.tss.api.tspi;

/**
 * This class is used with Certified Migratable Keys (CMKs) to hold properties and migratable data blobs
 * when passing them between APIs. 
 * This class just has attributes which can be set and retrieved using Tspi_SetAttribData() and 
 * Tspi_GetAttribData(). There are no further function defined for this class.
 */
public interface TcIMigData extends TcIWorkingObject, TcIAttributes {

}
