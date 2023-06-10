/*
 * Copyright (C) 2008 IAIK, Graz University of Technology
 * authors: Thomas Holzmann
 */

package iaik.tc.tss.tools.ps;

import iaik.tc.tss.api.constants.tcs.TcTcsErrors;
import iaik.tc.tss.api.exceptions.common.TcTssException;
import iaik.tc.tss.api.exceptions.tcs.TcTcsException;
import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.tss.api.structs.tsp.TcTssKmKeyinfo;
import iaik.tc.tss.api.tspi.TcIContext;
import iaik.tc.tss.impl.java.tcs.TcTcsProperties;
import iaik.tc.tss.impl.java.tsp.internal.TcTspProperties;
import iaik.tc.tss.impl.ps.TcITssPersistentStorage;
import iaik.tc.tss.impl.ps.TcTssSystemPsDatabase;
import iaik.tc.tss.impl.ps.TcTssSystemPsFileSystem;
import iaik.tc.tss.impl.ps.TcTssSystemPsTrousers;
import iaik.tc.tss.impl.ps.TcTssUserPsDatabase;
import iaik.tc.tss.impl.ps.TcTssUserPsFileSystem;
import iaik.tc.tss.impl.ps.TcTssUserPsTrousers;
import iaik.tc.utils.properties.Properties;

public class TcTssGetTrousersPs {
	TcIContext context_ = null;

	public static void main(String argv[]) {
		TcTssGetTrousersPs getPs = new TcTssGetTrousersPs();
		getPs.main0(argv);
	}

	public void main0(String argv[]) {
		try {
			System.out
					.println("* IAIK jTSS Import Tool for TrouSerS Persistent Storage *\n");
			System.out.println();
			System.out
					.println("Copyright (c) IAIK, Graz University of Technology, 2008. All rights reserved.");
			System.out.println();
			System.out
					.println("This tool will import existing TPM keys from the persistent storage (PS) of the TrouSerS stack into the PS of IAIK jTSS. Use it to have access to your existing keys with your Java applications.\n");
			System.out.println();

			if (argv.length == 0)
				System.out
						.println("Please specify arguments:\n"
								+ "system - copy system persistent storage\n"
								+ "user - copy user persistent storage\n"
								+ "Options:\n"
								+ "-d - delete all entries in the specified persistent storage before copying\n");
			Properties userProperties = TcTspProperties.getInstance();
			Properties systemProperties = TcTcsProperties.getInstance();

			boolean user = false;
			boolean system = false;
			boolean delete = false;

			for (int i = 0; i < argv.length; i++) {
				if (argv[i].equals("user"))
					user = true;
				else if (argv[i].equals("system"))
					system = true;
				else if (argv[i].equals("-d"))
					delete = true;
			}

			if (user)
				copyUserPs(userProperties, delete);
			if (system)
				copySystemPs(systemProperties, delete);

		} catch (TcTssException e) {
			e.printStackTrace();
		}

	}

	/**
	 * Copies the user persistent storage from TrouSerS.
	 * 
	 * @param properties
	 *            the properties containing the location of the TrouSerS PS.
	 * @param delete
	 *            if true, the content of jTSS persistent storage will be
	 *            deleted before copying the TrouSerS PS
	 * @throws TcTssException
	 */
	private void copyUserPs(Properties properties, boolean delete)
			throws TcTssException {
		try {
			TcITssPersistentStorage trousersPs = new TcTssUserPsTrousers(
					properties);
			TcITssPersistentStorage jtssPs = null;
			String psType = properties.getProperty("PersistentStorage", "type");
			String[] array = psType.split("\\.");
			String psClass = array[array.length - 1];
			if (psClass.equals("TcTssUserPsFileSystem")) {
				jtssPs = new TcTssUserPsFileSystem(properties);
			} else if (psClass.equals("TcTssUserPsDatabase")) {
				jtssPs = new TcTssUserPsDatabase(properties);
			} else
				throw new TcTcsException(TcTcsErrors.TCS_E_INTERNAL_ERROR,
						"The configuration " + "file seems to be invalid.");

			TcTssKmKeyinfo[] trousersKeys = trousersPs.enumRegisteredKeys(null);
			if (delete) {
				// delete all keys in this persistent storage
				System.out
						.println("Deleting existing user persistent storage keys...");
				TcTssKmKeyinfo[] jtssKeys = jtssPs.enumRegisteredKeys(null);
				for (int i = 0; i < jtssKeys.length; i++)
					jtssPs.unregisterKey(jtssKeys[i].getKeyUuid());
			}
			System.out.println("Copying user persistent storage...");
			int counter = 0;
			for (int i = 0; i < trousersKeys.length; i++) {
				try {
					TcBlobData key = trousersPs
							.getRegisteredKeyBlob(trousersKeys[i].getKeyUuid());
					jtssPs.registerKey(trousersKeys[i].getParentKeyUuid(),
							trousersKeys[i].getKeyUuid(), key);
				} catch (Exception e) {
					e.printStackTrace();
					counter++;
				}
			}
			if (counter > 0)
				System.out
						.println("I could not register "
								+ counter
								+ " keys.\n"
								+ "Maybe it works with the delete option -d, but then all your current keys are lost...");

		} catch (TcTssException e) {
			throw e;
		}
	}

	/**
	 * Copies the system persistent storage from TrouSerS.
	 * 
	 * @param properties
	 *            the properties containing the location of the TrouSerS PS.
	 * @param delete
	 *            if true, the content of jTSS persistent storage will be
	 *            deleted before copying the TrouSerS PS
	 * @throws TcTssException
	 */
	private void copySystemPs(Properties properties, boolean delete)
			throws TcTssException {
		try {
			TcITssPersistentStorage trousersPs = new TcTssSystemPsTrousers(
					properties);
			TcITssPersistentStorage jtssPs = null;
			String psType = properties.getProperty("PersistentStorage", "type");
			String[] array = psType.split("\\.");
			String psClass = array[array.length - 1];
			if (psClass.equals("TcTssSystemPsFileSystem")) {
				jtssPs = new TcTssSystemPsFileSystem(properties);
			} else if (psClass.equals("TcTssSystemPsDatabase")) {
				jtssPs = new TcTssSystemPsDatabase(properties);
			} else
				throw new TcTcsException(TcTcsErrors.TCS_E_INTERNAL_ERROR,
						"The configuration " + "file seems to be invalid.");

			TcTssKmKeyinfo[] trousersKeys = trousersPs.enumRegisteredKeys(null);
			if (delete) {
				// delete all keys in this persistent storage
				System.out
						.println("Deleting existing system persistent storage keys...");
				TcTssKmKeyinfo[] jtssKeys = jtssPs.enumRegisteredKeys(null);
				for (int i = 0; i < jtssKeys.length; i++)
					jtssPs.unregisterKey(jtssKeys[i].getKeyUuid());
			}
			System.out.println("Copying system persistent storage...");
			int counter = 0;
			for (int i = 0; i < trousersKeys.length; i++) {
				try {
					TcBlobData key = trousersPs
							.getRegisteredKeyBlob(trousersKeys[i].getKeyUuid());
					jtssPs.registerKey(trousersKeys[i].getParentKeyUuid(),
							trousersKeys[i].getKeyUuid(), key);
				} catch (Exception e) {
					e.printStackTrace();
					counter++;
				}
			}
			if (counter > 0)
				System.out
						.println("I could not register "
								+ counter
								+ " keys.\n"
								+ "Maybe it works with the delete option -d, but then all your current keys are lost...");

		} catch (TcTssException e) {
			throw e;
		}
	}
}
