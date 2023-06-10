package iaik.tc.tss.impl.ps;


import java.util.ArrayList;
import iaik.tc.tss.api.exceptions.common.TcTssException;
import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.tss.api.structs.tsp.TcTssKmKeyinfo;
import iaik.tc.tss.api.structs.tsp.TcTssUuid;
import iaik.tc.utils.properties.Properties;


/**
 * Implements a System Persistent Storage File System.
 * Basically extends the TcTssPsFileSystem to deal with the SRK correctly. It is part of the 
 * system persistent key hierarchy and given a fixed UUID. However, it is stored  
 * in the TPM and not in the PS. Furthermore it is assumed to be always loaded.
 * 
 * @author rtoegl
 *
 */
public class TcTssSystemPsFileSystem extends TcTssPsFileSystem {

	public TcTssSystemPsFileSystem(Properties properties) {
		super(properties);
	}


	protected TcTssKmKeyinfo[] enumRegisteredKeysImpl(TcTssUuid keyUuid) throws TcTssException
	{

		if (isRepositoryEmpty()) 
		{
			return null;	//TCG TSS Spec 1.20 Errata A, p. 526
		}
		
		ArrayList<String> keyUuids=new ArrayList<String>();
		
		if (keyUuid==null) //get all registered keys
		{
		//	keyUuids.add((getUuidSRK().toStringNoPrefix()));
			// The 1.2 spec demands, that the SRK must be the first one.
			// The order of the other keys is not specified though..
			
			keyUuids.addAll(getAllRegisteredKeyUUIDs());

		} else //get all keys, that are parents in the key hierarchy 
		{
			keyUuids=getHierarchyForRegisteredKey(keyUuid);
			
		//	keyUuids.add((getUuidSRK().toStringNoPrefix()));
			//Here, the SRK must be the last key included in the hierarchy.
									
		}		

		//create the key infos for the chosen key uuids

		TcTssKmKeyinfo[] keyInfos=new TcTssKmKeyinfo[keyUuids.size()];

		for (int i = 0; i != keyUuids.size(); i++)
		{

			TcTssUuid currentUuid=new TcTssUuid();
			currentUuid.initString(keyUuids.get(i));

			TcTssKmKeyinfo keyInfo=getRegisteredKeyImpl(currentUuid);

			keyInfos[i]=keyInfo;

		}

		return keyInfos;
	}


	protected TcTssKmKeyinfo getRegisteredKeyImpl(TcTssUuid keyUuid) throws TcTssException
	{

		TcTssKmKeyinfo keyInfo=super.getRegisteredKeyImpl(keyUuid);

		//Special case SRK as root of system key hierarchy
		TcTssUuid srkUUID=getUuidSRK();

		if (srkUUID.equals(keyUuid))
		{
			//SRK is always loaded.
			//The returned parent UUID is invalid and must be removed.

			keyInfo.init(keyInfo.getVersionInfo(), srkUUID, null, keyInfo.getAuthDataUsage(), true, keyInfo.getVendorData());  
		}

		return keyInfo;

	}

	protected void registerKeyImpl(TcTssUuid parentUuid, TcTssUuid keyUuid, TcBlobData key)
	throws TcTssException
	{
		if (getUuidSRK().equals(keyUuid))
		{
			//If the SRK is registered (upon TakeOwenership), some parent uuid needs to be stored for a consistent storage structure.
			//This is an illegal all zero value.
			parentUuid = new TcTssUuid().init(0L, 0, 0, (short) 0, (short) 0, new short[] { 0, 0, 0, 0, 0, 0 });
		}
		
		super.registerKeyImpl(parentUuid, keyUuid, key);		
	}
	
}
