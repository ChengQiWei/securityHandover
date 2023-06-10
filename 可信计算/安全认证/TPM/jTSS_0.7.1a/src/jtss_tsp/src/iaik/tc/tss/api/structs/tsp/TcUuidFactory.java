/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.api.structs.tsp;


import java.util.UUID;

/**
 * This factory returns TcUuid objects for well known UUIDs (as specified by the TCG).
 */
public class TcUuidFactory {

	/** the instance (singleton pattern) */
	protected static TcUuidFactory instance_ = null;


	/*************************************************************************************************
	 * Default constructor made unavailable (singleton pattern).
	 */
	private TcUuidFactory()
	{
	}


	/*************************************************************************************************
	 * This method returns the instance of the class (singleton pattern).
	 */
	public static TcUuidFactory getInstance()
	{
		if (instance_ == null) {
			instance_ = new TcUuidFactory();
		}
		return instance_;
	}


	/*************************************************************************************************
	 * This method returns the UUID of the SRK (PS-system, no-auth, non-migratable).
	 * 
	 * @return TCG fixed UUID of SRK.
	 */
	public TcTssUuid getUuidSRK()
	{
		return new TcTssUuid().init(0L, 0, 0, (short) 0, (short) 0, new short[] { 0, 0, 0, 0, 0, 1 });
	}


	/*************************************************************************************************
	 * This method returns the UUID of the system specific storage key SK (PS-system, no-auth,
	 * non-migratable).
	 * 
	 * @return TCG fixed UUID of SK
	 */
	public TcTssUuid getUuidSK()
	{
		return new TcTssUuid().init(0L, 0, 0, (short) 0, (short) 0, new short[] { 0, 0, 0, 0, 0, 2 });
	}


	/*************************************************************************************************
	 * This method returns the UUID of the roaming key RK (PS-system, no-auth, migratable).
	 * 
	 * @return TCG fixed UUID of RK
	 */
	public TcTssUuid getUuidRK()
	{
		return new TcTssUuid().init(0L, 0, 0, (short) 0, (short) 0, new short[] { 0, 0, 0, 0, 0, 3 });
	}


	/*************************************************************************************************
	 * This method returns the UUID of the certified roaming key CRK (PS-system, no-auth, migratable
	 * (CMK)).
	 * 
	 * @return TCG fixed UUID of CRK.
	 */
	public TcTssUuid getUuidCRK()
	{
		return new TcTssUuid().init(0L, 0, 0, (short) 0, (short) 0, new short[] { 0, 0, 0, 0, 0, 8 });
	}


	/*************************************************************************************************
	 * This method returns the UUID of storage key #1 for user #1 U1SK1 (PS-user, no-auth,
	 * non-migratable).
	 * 
	 * @return TCG fixed UUID of U1SK1.
	 */
	public TcTssUuid getUuidU1SK1()
	{
		return new TcTssUuid().init(0L, 0, 0, (short) 0, (short) 0, new short[] { 0, 0, 0, 0, 0, 4 });
	}


	/*************************************************************************************************
	 * This method returns the UUID of storage key #2 for user #1 U1SK2 (PS-user, auth,
	 * non-migratable).
	 * 
	 * @return TCG fixed UUID of U1SK2.
	 */
	public TcTssUuid getUuidU1SK2()
	{
		return new TcTssUuid().init(0L, 0, 0, (short) 0, (short) 0, new short[] { 0, 0, 0, 0, 0, 5 });
	}


	/*************************************************************************************************
	 * This method returns the UUID of storage key #2 for user #1 U1SK3 (PS-user, no-auth,
	 * migratable).
	 * 
	 * @return TCG fixed UUID of U1SK3
	 */
	public TcTssUuid getUuidU1SK3()
	{
		return new TcTssUuid().init(0L, 0, 0, (short) 0, (short) 0, new short[] { 0, 0, 0, 0, 0, 6 });
	}


	/*************************************************************************************************
	 * This method returns the UUID of storage key #2 for user #1 U1SK4 (PS-user, auth, migratable).
	 * 
	 * @return TCG fixed UUID of U1SK4
	 */
	public TcTssUuid getUuidU1SK4()
	{
		return new TcTssUuid().init(0L, 0, 0, (short) 0, (short) 0, new short[] { 0, 0, 0, 0, 0, 7 });
	}


	/*************************************************************************************************
	 * This method returns the UUID of storage key #2 for user #1 U1SK5 (PS-user, no-auth, migratable
	 * (CMK)).
	 * 
	 * @return TCG fixed UUID of U1SK5
	 */
	public TcTssUuid getUuidU1SK5()
	{
		return new TcTssUuid().init(0L, 0, 0, (short) 0, (short) 0, new short[] { 0, 0, 0, 0, 0, 9 });
	}


	/*************************************************************************************************
	 * This method returns the UUID of storage key #2 for user #1 U1SK6 (PS-user, auth, migratable
	 * (CMK)).
	 * 
	 * @return TCG fixed UUID of U1SK6
	 */
	public TcTssUuid getUuidU1SK6()
	{
		return new TcTssUuid().init(0L, 0, 0, (short) 0, (short) 0, new short[] { 0, 0, 0, 0, 0, 10 });
	}


	
	/*************************************************************************************************
	 * This method generates a random universally unique identifier UUID that is used to identify
	 * keys stored in the persistent storage of the TSS.
	 */
	public TcTssUuid generateRandomUuid()
	{
		UUID uuid = UUID.randomUUID();
		return convertUuidJavaToTss(uuid);
	}


	/*************************************************************************************************
	 * This method converts a Java UUID (available in Java 1.5 onwards) into a TSS UUID.
	 */
	public TcTssUuid convertUuidJavaToTss(UUID uuid)
	{
		TcTssUuid tssUuid = new TcTssUuid();
		tssUuid.initString(uuid.toString());
		return tssUuid;
	}


	/*************************************************************************************************
	 * This method converts a TSS UUID into a Java UUID (available in Java 1.5 onwards).
	 */
	public UUID convertUuidTssToJava(TcTssUuid tssUuid)
	{
		UUID uuid = UUID.fromString(tssUuid.toStringNoPrefix());
		return uuid;
	}
}
