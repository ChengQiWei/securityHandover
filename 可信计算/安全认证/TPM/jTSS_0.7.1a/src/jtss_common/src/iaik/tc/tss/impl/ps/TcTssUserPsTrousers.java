/*
 * Copyright (C) 2008 IAIK, Graz University of Technology
 * authors: Thomas Holzmann
 */

package iaik.tc.tss.impl.ps;

import java.util.ArrayList;
import java.util.Collections;

import iaik.tc.tss.api.exceptions.common.TcTssException;
import iaik.tc.tss.api.structs.tsp.TcTssKmKeyinfo;
import iaik.tc.tss.api.structs.tsp.TcTssUuid;
import iaik.tc.utils.properties.Properties;

public class TcTssUserPsTrousers extends TcTssPsTrousers {

	public TcTssUserPsTrousers(Properties properties) {
		super(properties);
	}

	protected TcTssKmKeyinfo[] enumRegisteredKeysImpl(TcTssUuid keyUuid)
			throws TcTssException {
		ArrayList<String> keyUuids = new ArrayList<String>();

		if (keyUuid == null) {
			keyUuids = getAllRegisteredKeyUuids();
			Collections.sort(keyUuids);

			// TSS Spec. Errata A requires the "root key" to be first.
			// But no details on how the array should map the hierarchy to an
			// array is given.
			// So we just return all registered keys.
			// Additionally, the root key is not identified uniquely for the
			// user storage
			// It could be USK1 or USK2.
			// This implementation actually does not enforce using these key
			// UUIDs.
			// However, if of these keys is present, it will be first in the
			// returned list,
			// due to the alphabetic ordering of the UUID strings.

		} else {
			keyUuids = getHierarchyForRegisteredKey(keyUuid);
		}

		// create the key infos for the chosen key uuids

		TcTssKmKeyinfo[] keyInfos = new TcTssKmKeyinfo[keyUuids.size()];

		for (int i = 0; i != keyUuids.size(); i++) {

			TcTssUuid currentUuid = new TcTssUuid();
			currentUuid.initString(keyUuids.get(i));

			TcTssKmKeyinfo keyInfo = getRegisteredKeyImpl(currentUuid);

			keyInfos[i] = keyInfo;

		}

		return keyInfos;
		// return null;
	}
}