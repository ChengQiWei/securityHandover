/**
 * Copyright (C) 2008 IAIK, Graz University of Technology
 * authors: Thomas Holzmann
 */

package iaik.tc.tss.test.tsp.java.persistentstorage;

import iaik.tc.tss.api.exceptions.common.TcTssException;
import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.tss.api.structs.tsp.TcTssKmKeyinfo;
import iaik.tc.tss.test.tsp.java.TestCommon;
import iaik.tc.utils.properties.Properties;
import iaik.tc.tss.impl.java.tcs.TcTcsProperties;
import iaik.tc.tss.impl.java.tsp.internal.TcTspProperties;
import iaik.tc.tss.impl.ps.*;

public class TestPersistentStorageTrousersCompability extends TestCommon {

	/**
	 * This test loads the keys from the TrouSerS PS and stores it into the jTSS
	 * PS.
	 */
	public void testLoadFromTrousersAndStoreInDatabase() {
		try {
			Properties tcsProperties = TcTcsProperties.getInstance();
			Properties tspProperties = TcTspProperties.getInstance();
			TcITssPersistentStorage userDatabase = new TcTssUserPsDatabase(
					tspProperties);
			TcITssPersistentStorage systemDatabase = new TcTssSystemPsDatabase(
					tcsProperties);
			TcITssPersistentStorage userTrousers = new TcTssUserPsTrousers(
					tspProperties);
			TcITssPersistentStorage systemTrousers = new TcTssSystemPsTrousers(
					tcsProperties);

			TcTssKmKeyinfo[] trousersKeys = systemTrousers
					.enumRegisteredKeys(null);
			TcTssKmKeyinfo[] dbKeys = systemDatabase.enumRegisteredKeys(null);
			// system
			// unregister all keys
			if (dbKeys != null)
				for (int i = 0; i < dbKeys.length; i++) {
					systemDatabase.unregisterKey(dbKeys[i].getKeyUuid());
				}
			if (trousersKeys == null)
				throw new Exception("The TrouSerS storage file is empty.");
			// Now we have an empty database
			for (int i = 0; i < trousersKeys.length; i++) {
				TcBlobData key = systemTrousers
						.getRegisteredKeyBlob(trousersKeys[i].getKeyUuid());
				String keyString = key.toHexStringNoWrap();
				systemDatabase.registerKey(trousersKeys[i].getParentKeyUuid(),
						trousersKeys[i].getKeyUuid(), key);
			}
			dbKeys = systemDatabase.enumRegisteredKeys(null);
			// Now check if they have the same key
			for (int i = 0; i < trousersKeys.length; i++) {
				TcBlobData keyTrousers = systemTrousers
						.getRegisteredKeyBlob(trousersKeys[i].getKeyUuid());
				TcBlobData keyDatabase = systemDatabase
						.getRegisteredKeyBlob(trousersKeys[i].getKeyUuid());
				if (!keyTrousers.equals(keyDatabase)) {
					throw new Exception(
							"The keys from TrouSerS system PS and jTSS system PS do not match.");
				}
			}

			// user
			trousersKeys = userTrousers.enumRegisteredKeys(null);
			dbKeys = userDatabase.enumRegisteredKeys(null);
			// unregister all keys
			// NOTE: that will delete all your keys so it is commented out by
			// default.
			// You have to uncomment it.
			if (dbKeys != null)
				for (int i = 0; i < dbKeys.length; i++) {
					userDatabase.unregisterKey(dbKeys[i].getKeyUuid());
				}
			if (trousersKeys == null)
				throw new Exception("The TrouSerS storage file is empty.");
			// Now we have an empty database
			for (int i = 0; i < trousersKeys.length; i++) {
				TcBlobData key = userTrousers
						.getRegisteredKeyBlob(trousersKeys[i].getKeyUuid());
				userDatabase.registerKey(trousersKeys[i].getParentKeyUuid(),
						trousersKeys[i].getKeyUuid(), key);
			}
			dbKeys = userDatabase.enumRegisteredKeys(null);
			// Now check if they have the same key
			for (int i = 0; i < trousersKeys.length; i++) {
				TcBlobData keyTrousers = userTrousers
						.getRegisteredKeyBlob(trousersKeys[i].getKeyUuid());
				TcBlobData keyDatabase = userDatabase
						.getRegisteredKeyBlob(trousersKeys[i].getKeyUuid());
				if (!keyTrousers.equals(keyDatabase)) {
					throw new Exception(
							"The keys from TrouSerS user PS and jTSS user PS do not match.");
				}
			}

		} catch (TcTssException e) {
			e.printStackTrace();
			assertTrue(
					"Unable to load keys from trousers ps and save it in jTSS ps.",
					false);
		} catch (Exception e) {
			e.printStackTrace();
			assertTrue(e.getMessage(), false);
		}

	}

}