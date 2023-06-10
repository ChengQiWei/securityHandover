/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Michael Steurer
 */
package iaik.tc.tss.impl.java.tsp.tcsbinding.soapservice;

import java.rmi.RemoteException;

import javax.xml.rpc.ServiceException;

import org.apache.axis.types.UnsignedInt;
import org.apache.axis.types.UnsignedShort;

import iaik.tc.tss.api.constants.tpm.TcTpmConstants;
import iaik.tc.tss.api.constants.tsp.TcTssErrors;
import iaik.tc.tss.api.exceptions.common.TcTssException;
import iaik.tc.tss.api.exceptions.tcs.TcTcsException;
import iaik.tc.tss.api.exceptions.tcs.TcTddlException;
import iaik.tc.tss.api.exceptions.tcs.TcTpmException;
import iaik.tc.tss.api.exceptions.tsp.TcTspException;
import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.tss.api.structs.tcs.TcTcsAuth;
import iaik.tc.tss.api.structs.tcs.TcTcsLoadkeyInfo;
import iaik.tc.tss.api.structs.tpm.TcITpmKey;
import iaik.tc.tss.api.structs.tpm.TcITpmKeyNew;
import iaik.tc.tss.api.structs.tpm.TcITpmPcrInfo;
import iaik.tc.tss.api.structs.tpm.TcITpmStoredData;
import iaik.tc.tss.api.structs.tpm.TcTpmCapVersionInfo;
import iaik.tc.tss.api.structs.tpm.TcTpmCertifyInfo;
import iaik.tc.tss.api.structs.tpm.TcTpmCertifyInfo2;
import iaik.tc.tss.api.structs.tpm.TcTpmCmkAuth;
import iaik.tc.tss.api.structs.tpm.TcTpmCurrentTicks;
import iaik.tc.tss.api.structs.tpm.TcTpmDelegateOwnerBlob;
import iaik.tc.tss.api.structs.tpm.TcTpmDelegatePublic;
import iaik.tc.tss.api.structs.tpm.TcTpmDigest;
import iaik.tc.tss.api.structs.tpm.TcTpmEncauth;
import iaik.tc.tss.api.structs.tpm.TcTpmKey;
import iaik.tc.tss.api.structs.tpm.TcTpmKey12;
import iaik.tc.tss.api.structs.tpm.TcTpmKeyParms;
import iaik.tc.tss.api.structs.tpm.TcTpmMigrationkeyAuth;
import iaik.tc.tss.api.structs.tpm.TcTpmMsaComposite;
import iaik.tc.tss.api.structs.tpm.TcTpmNonce;
import iaik.tc.tss.api.structs.tpm.TcTpmNvDataPublic;
import iaik.tc.tss.api.structs.tpm.TcTpmPcrComposite;
import iaik.tc.tss.api.structs.tpm.TcTpmPcrInfoLong;
import iaik.tc.tss.api.structs.tpm.TcTpmPcrInfoShort;
import iaik.tc.tss.api.structs.tpm.TcTpmPcrSelection;
import iaik.tc.tss.api.structs.tpm.TcTpmPubkey;
import iaik.tc.tss.api.structs.tpm.TcTpmSecret;
import iaik.tc.tss.api.structs.tpm.TcTpmStoredData;
import iaik.tc.tss.api.structs.tpm.TcTpmSymmetricKey;
import iaik.tc.tss.api.structs.tpm.TcTpmTransportPublic;
import iaik.tc.tss.api.structs.tsp.TcTssKmKeyinfo;
import iaik.tc.tss.api.structs.tsp.TcTssPcrEvent;
import iaik.tc.tss.api.structs.tsp.TcTssUuid;
import iaik.tc.tss.impl.java.tsp.internal.TcTspProperties;
import iaik.tc.tss.impl.java.tsp.tcsbinding.TcITcsBinding;
import iaik.tc.tss.impl.java.tsp.tcsbinding.soapservice.clientstubs.*;
import iaik.tc.utils.logging.Log;

public class TcTcsBindingSoap implements TcITcsBinding {

  TSSCoreServicePort stub_;

  public TcTcsBindingSoap() {
  }

  public void connect(String hostname) throws TcTspException {
    TSSCoreService_Service service = new TSSCoreService_ServiceLocator();

    if (hostname == null || hostname=="") {
    
    	String portString = new String();
    	String hostString = new String();
    	String relativePath = new String();
	
	    try {
	      portString = TcTspProperties.getInstance().getProperty("SOAP", "portnumber");
	    } catch (Exception e) {
	      portString = "30004";
	    }
	
	    try {
	      relativePath = TcTspProperties.getInstance().getProperty("SOAP", "relativepath");
	    } catch (Exception e) {
	      relativePath = "/axis/services/TSSCoreServiceBindingImpl";
	    }
	
	    try {
	      String useRemoteHost = TcTspProperties.getInstance().getProperty("SOAP", "useremoterost");
	      if (useRemoteHost.equals("true")) {
	        hostString = TcTspProperties.getInstance().getProperty("SOAP", "remotehost");
	      } else {
	        throw new Exception("Use local host instead");
	      }
	    } catch (Exception e) {
	      hostString = "http://127.0.0.1";
	    }
	   
	    hostname = hostString + ":" + portString + relativePath;
	    
    }

    ((TSSCoreService_ServiceLocator) service).setTSSCoreServiceEndpointAddress(hostname);
    try {
      stub_ = service.getTSSCoreService();
    } catch (ServiceException e) {
      e.printStackTrace();
    }

    // Try to connect to the server. There seems no Server running if this
    // fails.
    try {
      stub_.openContext();
    } catch (RemoteException e) {
      Log.err("There seems no TCS running");
      throw new TcTspException(TcTssErrors.TSS_E_CONNECTION_FAILED);
    }
  }

  // --------- persistent storage --------
  public void TcsiRegisterKey(long hContext, TcTssUuid wrappingKeyUuid, TcTssUuid keyUuid, TcBlobData key, TcBlobData vendorData) throws TcTssException {
    try {
      RegisterKeyInParms inParms = new RegisterKeyInParms();

      inParms.setGbVendorData(vendorData == null ? null : vendorData.asByteArray());
      inParms.setHContext(new UnsignedInt(hContext));
      inParms.setKeyUUID(ConvertDataTypesClient.convertTssUuid(keyUuid));
      inParms.setRgbKey(key.asByteArray());
      inParms.setWrappingKeyUUID(ConvertDataTypesClient.convertTssUuid(wrappingKeyUuid));

      // void() function
      stub_.registerKey(inParms);
    } catch (RemoteException e) {
      ConvertRemoteExceptions.convertTcTcsException(e);
      ConvertRemoteExceptions.convertTcTddlException(e);
      ConvertRemoteExceptions.convertTcTpmException(e);
      throw new TcTcsException(TcTssErrors.TSS_E_INTERNAL_ERROR, "RemoteException: " + e.getMessage());
    }
  }

  public void TcsiUnregisterKey(long hContext, TcTssUuid keyUuid) throws TcTssException {
    try {
      UnregisterKeyInParms inParms = new UnregisterKeyInParms();
      inParms.setHContext(new UnsignedInt(hContext));
      inParms.setKeyUUID(ConvertDataTypesClient.convertTssUuid(keyUuid));

      // void() function
      stub_.unregisterKey(inParms);
    } catch (RemoteException e) {
      ConvertRemoteExceptions.convertTcTcsException(e);
      ConvertRemoteExceptions.convertTcTddlException(e);
      ConvertRemoteExceptions.convertTcTpmException(e);
      throw new TcTcsException(TcTssErrors.TSS_E_INTERNAL_ERROR, "RemoteException: " + e.getMessage());
    }
  }

  public void TcsipKeyControlOwner(long hContext, long tcsKeyHandle, long attribName, long attribValue, TcTcsAuth ownerAuth, TcTssUuid uuidData) throws TcTssException {
    try {
      KeyControlOwnerInParms inParms = new KeyControlOwnerInParms();
      inParms.setAttribName(new UnsignedInt(attribName));
      inParms.setAttribValue(((Long) attribValue).byteValue());
      inParms.setHContext(new UnsignedInt(hContext));
      inParms.setHKey(new UnsignedInt(tcsKeyHandle));
      inParms.setPOwnerAuth(ConvertDataTypesClient.convertTcsAuth(ownerAuth));
      // inParms.setPrgbPubKey();

      // void() function
      stub_.keyControlOwner(inParms);
    } catch (RemoteException e) {
      ConvertRemoteExceptions.convertTcTcsException(e);
      ConvertRemoteExceptions.convertTcTddlException(e);
      ConvertRemoteExceptions.convertTcTpmException(e);
      throw new TcTcsException(TcTssErrors.TSS_E_INTERNAL_ERROR, "RemoteException: " + e.getMessage());
    }
  }

  public TcTssKmKeyinfo[] TcsiEnumRegisteredKeys(long hContext, TcTssUuid keyUuid) throws TcTssException {
    try {

      EnumRegisteredKeysInParms inParms = new EnumRegisteredKeysInParms();
      inParms.setHContext(new UnsignedInt(hContext));
      inParms.setPKeyUUID(keyUuid == null ? null : ConvertDataTypesClient.convertTssUuid(keyUuid));

      EnumRegisteredKeysOutParms outParms;
      outParms = stub_.enumRegisteredKeys(inParms);

      if (outParms.getPpKeyHierarchy() == null) {
        return null;
      }

      TcTssKmKeyinfo[] retval = new TcTssKmKeyinfo[outParms.getPpKeyHierarchy().length];
      for (int i = 0; i < retval.length; i++) {
        retval[i] = outParms.getPpKeyHierarchy()[i] == null ? null : ConvertDataTypesClient.convertTssKmKeyinfo(outParms.getPpKeyHierarchy()[i]);
      }

      return retval;
    } catch (RemoteException e) {
      ConvertRemoteExceptions.convertTcTcsException(e);
      ConvertRemoteExceptions.convertTcTddlException(e);
      ConvertRemoteExceptions.convertTcTpmException(e);
      throw new TcTcsException(TcTssErrors.TSS_E_INTERNAL_ERROR, "RemoteException: " + e.getMessage());
    }
  }

  public TcTssKmKeyinfo TcsiGetRegisteredKey(long hContext, TcTssUuid keyUuid) throws TcTssException {
    try {

      GetRegisteredKeyInParms inParms = new GetRegisteredKeyInParms();
      inParms.setHContext(new UnsignedInt(hContext));
      inParms.setKeyUUID(ConvertDataTypesClient.convertTssUuid(keyUuid));

      GetRegisteredKeyOutParms outParms = stub_.getRegisteredKey(inParms);

      TcTssKmKeyinfo retval = new TcTssKmKeyinfo();
      retval = ConvertDataTypesClient.convertTssKmKeyinfo(outParms.getPpKeyInfo());

      return retval;
    } catch (RemoteException e) {
      ConvertRemoteExceptions.convertTcTcsException(e);
      ConvertRemoteExceptions.convertTcTddlException(e);
      ConvertRemoteExceptions.convertTcTpmException(e);
      throw new TcTcsException(TcTssErrors.TSS_E_INTERNAL_ERROR, "RemoteException: " + e.getMessage());
    }
  }

  public TcBlobData TcsiGetRegisteredKeyBlob(long hContext, TcTssUuid keyUuid) throws TcTssException {
    try {

      GetRegisteredKeyBlobInParms inParms = new GetRegisteredKeyBlobInParms();
      inParms.setHContext(new UnsignedInt(hContext));
      inParms.setKeyUUID(ConvertDataTypesClient.convertTssUuid(keyUuid));

      GetRegisteredKeyBlobOutParms outParms = stub_.getRegisteredKeyBlob(inParms);

      TcBlobData retval = outParms.getPrgbKey() == null ? null : TcBlobData.newByteArray(outParms.getPrgbKey());
      outParms.getResult();

      return retval;
    } catch (RemoteException e) {
      ConvertRemoteExceptions.convertTcTcsException(e);
      ConvertRemoteExceptions.convertTcTddlException(e);
      ConvertRemoteExceptions.convertTcTpmException(e);
      throw new TcTcsException(TcTssErrors.TSS_E_INTERNAL_ERROR, "RemoteException: " + e.getMessage());
    }
  }

  public TcBlobData TcsiGetRegisteredKeyByPublicInfo(long hContext, long algId, TcBlobData publicInfo) throws TcTssException {
    try {

      GetRegisteredKeyByPublicInfoInParms inParms = new GetRegisteredKeyByPublicInfoInParms();
      inParms.setAlgID(new UnsignedInt(algId));
      inParms.setHContext(new UnsignedInt(hContext));
      inParms.setRgbPublicInfo(publicInfo.asByteArray());

      GetRegisteredKeyByPublicInfoOutParms outParms = stub_.getRegisteredKeyByPublicInfo(inParms);

      TcBlobData retval = TcBlobData.newByteArray(outParms.getKeyBlob());

      return retval;
    } catch (RemoteException e) {
      ConvertRemoteExceptions.convertTcTcsException(e);
      ConvertRemoteExceptions.convertTcTddlException(e);
      ConvertRemoteExceptions.convertTcTpmException(e);
      
      throw new TcTcsException(TcTssErrors.TSS_E_INTERNAL_ERROR, "RemoteException: " + e.getMessage());
      
      //return null;
    }
  }

  public long TcsipLoadKeyByUuid(long hContext, TcTssUuid keyUuid, TcTcsLoadkeyInfo loadKeyInfo) throws TcTssException {
    try {
      LoadKeyByUUIDInParms inParms = new LoadKeyByUUIDInParms();
      inParms.setHContext(new UnsignedInt(hContext));
      inParms.setKeyUUID(ConvertDataTypesClient.convertTssUuid(keyUuid));
      inParms.setPLoadKeyInfo(ConvertDataTypesClient.convertTcsLoadkeyInfo(loadKeyInfo));

      LoadKeyByUUIDOutParms outParms = stub_.loadKeyByUUID(inParms);

      long retval;
      retval = outParms.getPhKeyTCSI().longValue();

      return retval;
    } catch (RemoteException e) {
      ConvertRemoteExceptions.convertTcTcsException(e);
      ConvertRemoteExceptions.convertTcTddlException(e);
      ConvertRemoteExceptions.convertTcTpmException(e);
      
      throw new TcTcsException(TcTssErrors.TSS_E_INTERNAL_ERROR, "RemoteException: " + e.getMessage());
    }
  }

  // --------- key management --------
  public Object[] TcsipLoadKeyByBlob(long hContext, long hUnwrappingKey, TcTpmKey wrappedKeyBlob, TcTcsAuth inAuth) throws TcTddlException, TcTpmException, TcTcsException {
    try {
      LoadKeyByBlobInParms inParms = new LoadKeyByBlobInParms();
      inParms.setHContext(new UnsignedInt(hContext));
      inParms.setHUnwrappingKey(new UnsignedInt(hUnwrappingKey));
      inParms.setPAuth(ConvertDataTypesClient.convertTcsAuth(inAuth));
      inParms.setRgbWrappedKeyBlob(wrappedKeyBlob.getEncoded().asByteArray());

      LoadKeyByBlobOutParms outParms = stub_.loadKeyByBlob(inParms);

      Object[] retval = new Object[4];
      retval[0] = outParms.getResult().longValue();
      retval[1] = ConvertDataTypesClient.convertTcsAuth(outParms.getPAuth());
      retval[2] = outParms.getPhKeyHMAC().longValue();
      retval[3] = outParms.getPhKeyTCSI().longValue();

      return retval;
    } catch (RemoteException e) {
      ConvertRemoteExceptions.convertTcTcsException(e);
      ConvertRemoteExceptions.convertTcTddlException(e);
      ConvertRemoteExceptions.convertTcTpmException(e);
      return null;
    }
  }

  public Object[] TcsipLoadKey2ByBlob(long hContext, long hUnwrappingKey, TcITpmKey wrappedKeyBlob, TcTcsAuth inAuth) throws TcTddlException, TcTpmException, TcTcsException {
    try {
      LoadKey2ByBlobInParms inParms = new LoadKey2ByBlobInParms();
      inParms.setHContext(new UnsignedInt(hContext));
      inParms.setHUnwrappingKey(new UnsignedInt(hUnwrappingKey));
      inParms.setPAuth(ConvertDataTypesClient.convertTcsAuth(inAuth));
      inParms.setRgbWrappedKeyBlob(wrappedKeyBlob.getEncoded().asByteArray());

      LoadKey2ByBlobOutParms outParms = stub_.loadKey2ByBlob(inParms);

      Object[] retval = new Object[3];
      retval[0] = outParms.getResult().longValue();
      retval[1] = ConvertDataTypesClient.convertTcsAuth(outParms.getPAuth());
      retval[2] = outParms.getPhKeyTCSI().longValue();
      return retval;
    } catch (RemoteException e) {
      e.printStackTrace();
      ConvertRemoteExceptions.convertTcTcsException(e);
      ConvertRemoteExceptions.convertTcTddlException(e);
      ConvertRemoteExceptions.convertTcTpmException(e);
      return null;
    }
  }

  public Object[] TcsipEvictKey(long hContext, long tcsKeyHandle) throws TcTddlException, TcTpmException, TcTcsException {
    try {

      EvictKeyInParms inParms = new EvictKeyInParms();
      inParms.setHContext(new UnsignedInt(hContext));
      inParms.setHKey(new UnsignedInt(tcsKeyHandle));

      EvictKeyOutParms outParms = stub_.evictKey(inParms);

      Object[] retval = new Object[1];
      retval[0] = outParms.getResult().longValue();

      return retval;
    } catch (RemoteException e) {
      e.printStackTrace();
      ConvertRemoteExceptions.convertTcTcsException(e);
      ConvertRemoteExceptions.convertTcTddlException(e);
      ConvertRemoteExceptions.convertTcTpmException(e);
      return null;
    }
  }

  public Object[] TcsipGetPubKey(long hContext, long keyHandle, TcTcsAuth inAuth1) throws TcTddlException, TcTpmException, TcTcsException {
    try {
      GetPubKeyInParms inParms = new GetPubKeyInParms();
      inParms.setHContext(new UnsignedInt(hContext));
      inParms.setHKey(new UnsignedInt(keyHandle));
      inParms.setPAuth(ConvertDataTypesClient.convertTcsAuth(inAuth1));

      GetPubKeyOutParms outParms = stub_.getPubKey(inParms);

      Object[] retval = new Object[3];
      retval[1] = ConvertDataTypesClient.convertTcsAuth(outParms.getPAuth());
      retval[0] = outParms.getResult().longValue();
      retval[2] = outParms.getPrgbPubKey() == null ? null : new TcTpmPubkey(TcBlobData.newByteArray(outParms.getPrgbPubKey()));

      return retval;
    } catch (RemoteException e) {
      ConvertRemoteExceptions.convertTcTcsException(e);
      ConvertRemoteExceptions.convertTcTddlException(e);
      ConvertRemoteExceptions.convertTcTpmException(e);
      return null;
    }
  }

  // --------- credential management ---------
  public Object[] TcsipMakeIdentity(long hContext, TcTpmEncauth identityAuth, TcTpmDigest labelPrivCADigest, TcITpmKeyNew idKeyParams, TcTcsAuth inAuth1, TcTcsAuth inAuth2) throws TcTddlException, TcTpmException, TcTcsException {

    try {
      MakeIdentityInParms inParms = new MakeIdentityInParms();
      inParms.setHContext(new UnsignedInt(hContext));
      inParms.setIdentityAuth(identityAuth.getEncoded().asByteArray());
      inParms.setIdIdentityKeyInfo(idKeyParams.getEncoded().asByteArray());
      inParms.setIDLabel_PrivCAHash(labelPrivCADigest.getEncoded().asByteArray());
      inParms.setPOwnerAuth(ConvertDataTypesClient.convertTcsAuth(inAuth1));
      inParms.setPSrkAuth(ConvertDataTypesClient.convertTcsAuth(inAuth2));

      MakeIdentityOutParms outParms = stub_.makeIdentity(inParms);

      Object[] retval = new Object[8];
      retval[0] = outParms.getResult().longValue();
      retval[1] = ConvertDataTypesClient.convertTcsAuth(outParms.getPOwnerAuth());
      retval[2] = ConvertDataTypesClient.convertTcsAuth(outParms.getPSrkAuth());
      retval[3] = outParms.getIdIdentityKey() == null ? null : new TcTpmKey(TcBlobData.newByteArray(outParms.getIdIdentityKey()));
      retval[4] = outParms.getPrgbIdentityBinding() == null ? null : TcBlobData.newByteArray(outParms.getPrgbIdentityBinding());
      retval[5] = outParms.getPrgbEndorsementCredential() == null ? null : TcBlobData.newByteArray(outParms.getPrgbEndorsementCredential());
      retval[6] = outParms.getPrgbPlatformCredential() == null ? null : TcBlobData.newByteArray(outParms.getPrgbPlatformCredential());
      retval[7] = outParms.getPrgbConformanceCredential() == null ? null : TcBlobData.newByteArray(outParms.getPrgbConformanceCredential());

      return retval;
    } catch (RemoteException e) {
      ConvertRemoteExceptions.convertTcTcsException(e);
      ConvertRemoteExceptions.convertTcTddlException(e);
      ConvertRemoteExceptions.convertTcTpmException(e);
      return null;
    }
  }

  /*
   * This is method is just the same as TcsipMakeIdentity2(...). The only
   * difference is the return Object[] that does not contain credential
   * information.
   */
  public Object[] TcsipMakeIdentity2(long hContext, TcTpmEncauth identityAuth, TcTpmDigest labelPrivCADigest, TcITpmKeyNew idKeyParams, TcTcsAuth inAuth1, TcTcsAuth inAuth2)
    throws TcTddlException, TcTpmException, TcTcsException {
    try {
      MakeIdentityInParms inParms = new MakeIdentityInParms();
      inParms.setHContext(new UnsignedInt(hContext));
      inParms.setIdentityAuth(identityAuth.getEncoded().asByteArray());
      inParms.setIdIdentityKeyInfo(idKeyParams.getEncoded().asByteArray());
      inParms.setIDLabel_PrivCAHash(labelPrivCADigest.getEncoded().asByteArray());
      inParms.setPOwnerAuth(ConvertDataTypesClient.convertTcsAuth(inAuth1));
      inParms.setPSrkAuth(ConvertDataTypesClient.convertTcsAuth(inAuth2));

      MakeIdentityOutParms outParms = stub_.makeIdentity(inParms);

      Object[] retval = new Object[5];
      retval[0] = outParms.getResult().longValue();
      retval[1] = ConvertDataTypesClient.convertTcsAuth(outParms.getPOwnerAuth());
      retval[2] = ConvertDataTypesClient.convertTcsAuth(outParms.getPSrkAuth());
      retval[3] = outParms.getIdIdentityKey() == null ? null : new TcTpmKey(TcBlobData.newByteArray(outParms.getIdIdentityKey()));
      retval[4] = outParms.getPrgbIdentityBinding() == null ? null : TcBlobData.newByteArray(outParms.getPrgbIdentityBinding());

      return retval;
    } catch (RemoteException e) {
      ConvertRemoteExceptions.convertTcTcsException(e);
      ConvertRemoteExceptions.convertTcTddlException(e);
      ConvertRemoteExceptions.convertTcTpmException(e);
      return null;
    }
  }
  // --------- context --------
  public Object[] TcsiOpenContext() {
    try {
      OpenContextOutParms outParms = stub_.openContext();

      Object[] retval = new Object[2];
      retval[1] = ((UnsignedInt) outParms.getHContext()).longValue();
      retval[0] = ((UnsignedInt) outParms.getResult()).longValue();
      return retval;

    } catch (RemoteException e) {
      e.printStackTrace();
      return null;
    }
  }

  public long TcsiCloseContext(long hContext) throws TcTcsException, TcTddlException, TcTpmException {
    try {
      CloseContextInParms inParms = new CloseContextInParms();
      inParms.setHContext(new UnsignedInt(hContext));

      CloseContextOutParms outParms = stub_.closeContext(inParms);

      long retval = outParms.getResult().longValue();

      return retval;
    } catch (RemoteException e) {
      ConvertRemoteExceptions.convertTcTcsException(e);
      ConvertRemoteExceptions.convertTcTddlException(e);
      ConvertRemoteExceptions.convertTcTpmException(e);
      return 0;
    }
  }

  public TcBlobData TcsiGetCapability(long hContext, long capArea, TcBlobData subCap) throws TcTcsException {

    try {
      GetCapabilityInParms inParms = new GetCapabilityInParms();
      inParms.setCapArea(new UnsignedInt(capArea));
      inParms.setHContext(new UnsignedInt(hContext));
      
      inParms.setSubCap(subCap == null ? null: subCap.asByteArray());

      GetCapabilityOutParms outParms = stub_.getCapability(inParms);

      TcBlobData retval = outParms.getResp() == null ? null : TcBlobData.newByteArray(outParms.getResp());
      return retval;
    } catch (RemoteException e) {
      ConvertRemoteExceptions.convertTcTcsException(e);
      return null;
    }
  }

  // --------- event manager methods --------
  public long TcsiLogPcrEvent(long hContext, TcTssPcrEvent pcrEvent) throws TcTcsException {
    try {
      LogPcrEventInParms inParms = new LogPcrEventInParms();
      inParms.setEvent(ConvertDataTypesClient.convertTcTssPcrEvent(pcrEvent));
      inParms.setHContext(new UnsignedInt(hContext));

      LogPcrEventOutParms outParms = stub_.logPcrEvent(inParms);

      long retval = outParms.getPNumber().longValue();

      return retval;
    } catch (RemoteException e) {
      ConvertRemoteExceptions.convertTcTcsException(e);
      return 0;
    }
  }

  public TcTssPcrEvent TcsiGetPcrEvent(long hContext, long pcrIndex, long number) throws TcTcsException {
    try {
      GetPcrEventInParms inParms = new GetPcrEventInParms();
      inParms.setHContext(new UnsignedInt(hContext));
      inParms.setPcrIndex(new UnsignedInt(pcrIndex));
      inParms.setPNumber(new UnsignedInt(number));

      GetPcrEventOutParms outParms = stub_.getPcrEvent(inParms);

      TcTssPcrEvent retval = ConvertDataTypesClient.convertTcTssPcrEvent(outParms.getPpEvent()[0]);

      return retval;
    } catch (RemoteException e) {
      ConvertRemoteExceptions.convertTcTcsException(e);
      return null;
    }
  }

  public TcTssPcrEvent[] TcsiGetPcrEventsByPcr(long hContext, long pcrIndex, long firstEvent, long eventCount) throws TcTcsException {
    try {
      GetPcrEventsByPcrInParms inParms = new GetPcrEventsByPcrInParms();
      inParms.setFirstEvent(new UnsignedInt(firstEvent));
      inParms.setHContext(new UnsignedInt(hContext));
      inParms.setPcrIndex(new UnsignedInt(pcrIndex));
      inParms.setPEventCount(new UnsignedInt(eventCount));

      GetPcrEventsByPcrOutParms outParms = stub_.getPcrEventsByPcr(inParms);

      if (outParms.getPpEvents() == null) { // there are no dumps yet
          return new TcTssPcrEvent[0];
        }

      TcTssPcrEvent[] retval = new TcTssPcrEvent[outParms.getPpEvents().length];
      for (int i = 0; i < retval.length; i++) {
        retval[i] = ConvertDataTypesClient.convertTcTssPcrEvent(outParms.getPpEvents()[i]);
      }

      return retval;
    } catch (RemoteException e) {
      ConvertRemoteExceptions.convertTcTcsException(e);
      return null;
    }
  }

  public TcTssPcrEvent[] TcsiGetPcrEventLog(long hContext) throws TcTcsException {
    try {
      GetPcrEventLogInParms inParms = new GetPcrEventLogInParms();
      inParms.setHContext(new UnsignedInt(hContext));

      GetPcrEventLogOutParms outParms = stub_.getPcrEventLog(inParms);

      if (outParms.getPpEvents() == null) { // there are no dumps yet
        return new TcTssPcrEvent[0];
      }

      TcTssPcrEvent[] retval = new TcTssPcrEvent[outParms.getPpEvents().length];
      for (int i = 0; i < retval.length; i++) {
        retval[i] = ConvertDataTypesClient.convertTcTssPcrEvent(outParms.getPpEvents()[i]);
      }

      return retval;
    } catch (RemoteException e) {
      ConvertRemoteExceptions.convertTcTcsException(e);
      return null;
    }
  }

  // --------- other methods --------
  public Object[] TcsipSelfTestFull(long hContext) throws TcTddlException, TcTpmException, TcTcsException {
    try {
      SelfTestFullInParms inParms = new SelfTestFullInParms();
      inParms.setHContext(new UnsignedInt(hContext));

      SelfTestFullOutParms outParms = stub_.selfTestFull(inParms);

      Object[] retval = new Object[1];
      retval[0] = outParms.getResult().longValue();

      return retval;
    } catch (RemoteException e) {
      ConvertRemoteExceptions.convertTcTcsException(e);
      ConvertRemoteExceptions.convertTcTddlException(e);
      ConvertRemoteExceptions.convertTcTpmException(e);
      return null;
    }
  }

  public Object[] TcsipContinueSelfTest(long hContext) throws TcTddlException, TcTpmException, TcTcsException {
    try {
      ContinueSelfTestInParms inParms = new ContinueSelfTestInParms();
      inParms.setHContext(new UnsignedInt(hContext));

      ContinueSelfTestOutParms outParms = stub_.continueSelfTest(inParms);

      Object[] retval = new Object[1];
      retval[0] = outParms.getResult().longValue();

      return retval;
    } catch (RemoteException e) {
      ConvertRemoteExceptions.convertTcTcsException(e);
      ConvertRemoteExceptions.convertTcTddlException(e);
      ConvertRemoteExceptions.convertTcTpmException(e);
      return null;
    }
  }

  public Object[] TcsipGetTestResult(long hContext) throws TcTddlException, TcTpmException, TcTcsException {
    try {
      GetTestResultInParms inParms = new GetTestResultInParms();
      inParms.setHContext(new UnsignedInt(hContext));

      GetTestResultOutParms outParms = stub_.getTestResult(inParms);

      Object[] retval = new Object[2];
      outParms.getOutData();
      retval[0] = outParms.getResult().longValue();
      retval[1] = outParms.getOutData() == null ? null : TcBlobData.newByteArray(outParms.getOutData());

      return retval;
    } catch (RemoteException e) {
      ConvertRemoteExceptions.convertTcTcsException(e);
      ConvertRemoteExceptions.convertTcTddlException(e);
      ConvertRemoteExceptions.convertTcTpmException(e);
      return null;
    }
  }

  public Object[] TcsipSetOwnerInstall(long hContext, boolean state) throws TcTddlException, TcTpmException, TcTcsException {
    try {

      SetOwnerInstallInParms inParms = new SetOwnerInstallInParms();
      inParms.setHContext(new UnsignedInt(hContext));
      inParms.setState(state ? (byte) 1 : (byte) 0);
      SetOwnerInstallOutParms outParms = stub_.setOwnerInstall(inParms);

      Object[] retval = new Object[1];
      retval[0] = outParms.getResult().longValue();

      return retval;
    } catch (RemoteException e) {
      ConvertRemoteExceptions.convertTcTcsException(e);
      ConvertRemoteExceptions.convertTcTddlException(e);
      ConvertRemoteExceptions.convertTcTpmException(e);
      return null;
    }
  }

  public Object[] TcsipOwnerSetDisable(long hContext, boolean disableState, TcTcsAuth inAuth1) throws TcTddlException, TcTpmException, TcTcsException {
    try {

      OwnerSetDisableInParms inParms = new OwnerSetDisableInParms();

      inParms.setDisableState(disableState ? (byte) 1 : (byte) 0);
      inParms.setHContext(new UnsignedInt(hContext));
      inParms.setOwnerAuth(ConvertDataTypesClient.convertTcsAuth(inAuth1));

      OwnerSetDisableOutParms outParms = stub_.ownerSetDisable(inParms);

      Object[] retval = new Object[2];
      outParms.getOwnerAuth();
      retval[0] = outParms.getResult().longValue();
      retval[1] = ConvertDataTypesClient.convertTcsAuth(outParms.getOwnerAuth());

      return retval;
    } catch (RemoteException e) {
      ConvertRemoteExceptions.convertTcTcsException(e);
      ConvertRemoteExceptions.convertTcTddlException(e);
      ConvertRemoteExceptions.convertTcTpmException(e);
      return null;
    }
  }

  public Object[] TcsipPhysicalEnable(long hContext) throws TcTddlException, TcTpmException, TcTcsException {
    try {
      PhysicalEnableInParms inParms = new PhysicalEnableInParms();
      inParms.setHContext(new UnsignedInt(hContext));

      PhysicalEnableOutParms outParms = stub_.physicalEnable(inParms);

      Object[] retval = new Object[1];
      retval[0] = outParms.getResult().longValue();

      return retval;
    } catch (RemoteException e) {
      ConvertRemoteExceptions.convertTcTcsException(e);
      ConvertRemoteExceptions.convertTcTddlException(e);
      ConvertRemoteExceptions.convertTcTpmException(e);
      return null;
    }
  }

  public Object[] TcsipPhysicalDisable(long hContext) throws TcTddlException, TcTpmException, TcTcsException {
    try {
      PhysicalDisableInParms inParms = new PhysicalDisableInParms();
      inParms.setHContext(new UnsignedInt(hContext));

      PhysicalDisableOutParms outParms = stub_.physicalDisable(inParms);

      Object[] retval = new Object[1];
      retval[0] = outParms.getResult().longValue();

      return retval;
    } catch (RemoteException e) {
      ConvertRemoteExceptions.convertTcTcsException(e);
      ConvertRemoteExceptions.convertTcTddlException(e);
      ConvertRemoteExceptions.convertTcTpmException(e);
      return null;
    }
  }

  public Object[] TcsipPhysicalSetDeactivated(long hContext, boolean state) throws TcTddlException, TcTpmException, TcTcsException {
    try {
      PhysicalSetDeactivatedInParms inParms = new PhysicalSetDeactivatedInParms();
      inParms.setHContext(new UnsignedInt(hContext));
      inParms.setState(state ? (byte) 1 : (byte) 0);

      PhysicalSetDeactivatedOutParms outParms = stub_.physicalSetDeactivated(inParms);

      Object[] retval = new Object[1];
      retval[0] = outParms.getResult().longValue();

      return retval;
    } catch (RemoteException e) {
      ConvertRemoteExceptions.convertTcTcsException(e);
      ConvertRemoteExceptions.convertTcTddlException(e);
      ConvertRemoteExceptions.convertTcTpmException(e);
      return null;
    }
  }

  public Object[] TcsipSetTempDeactivated2(long hContext, TcTcsAuth inAuth1)
    throws TcTddlException, TcTpmException, TcTcsException {
    try {
      SetTempDeactivatedInParms inParms = new SetTempDeactivatedInParms();
      inParms.setHContext(new UnsignedInt(hContext));

      SetTempDeactivatedOutParms outParms = stub_.setTempDeactivated(inParms);

      Object[] retval = new Object[1];
      retval[0] = outParms.getResult().longValue();

      return retval;
    } catch (RemoteException e) {
      ConvertRemoteExceptions.convertTcTcsException(e);
      ConvertRemoteExceptions.convertTcTddlException(e);
      ConvertRemoteExceptions.convertTcTpmException(e);
      return null;
    }
  }

  public Object[] TcsipSetOperatorAuth(long hContext, TcTpmSecret operatorAuth)
    throws TcTddlException, TcTpmException, TcTcsException {
    try {
      SetOperatorAuthInParms inParms = new SetOperatorAuthInParms();
      inParms.setHContext(new UnsignedInt(hContext));
      inParms.setOperatorAuth(operatorAuth.getEncoded().asByteArray());

      SetOperatorAuthOutParms outParms = stub_.setOperatorAuth(inParms);

      Object[] retval = new Object[1];
      retval[0] = outParms.getResult().longValue();

      return retval;
    } catch (RemoteException e) {
      ConvertRemoteExceptions.convertTcTcsException(e);
      ConvertRemoteExceptions.convertTcTddlException(e);
      ConvertRemoteExceptions.convertTcTpmException(e);
      return null;
    }
  }

  public Object[] TcsipTakeOwnership(long hContext, int protocolID, TcBlobData encOwnerAuth, TcBlobData encSrkAuth, TcITpmKeyNew srkParams, TcTcsAuth inAuth1) throws TcTddlException, TcTpmException, TcTcsException {
    try {
      TakeOwnershipInParms inParms = new TakeOwnershipInParms();

      inParms.setEncOwnerAuth(encOwnerAuth.asByteArray());
      inParms.setEncSrkAuth(encSrkAuth.asByteArray());
      inParms.setHContext(new UnsignedInt(hContext));
      inParms.setProtocolID(new UnsignedInt(protocolID));
      inParms.setOwnerAuth(ConvertDataTypesClient.convertTcsAuth(inAuth1));
      inParms.setSrkKeyInfo(srkParams.getEncoded().asByteArray());

      TakeOwnershipOutParms outParms = stub_.takeOwnership(inParms);

      Object[] retval = new Object[3];
      retval[0] = outParms.getResult().longValue();
      retval[1] = ConvertDataTypesClient.convertTcsAuth(outParms.getOwnerAuth());
      retval[2] = outParms.getSrkKeyData() == null ? null : new TcTpmKey(TcBlobData.newByteArray(outParms.getSrkKeyData()));

      return retval;
    } catch (RemoteException e) {
      e.printStackTrace();
      ConvertRemoteExceptions.convertTcTcsException(e);
      ConvertRemoteExceptions.convertTcTddlException(e);
      ConvertRemoteExceptions.convertTcTpmException(e);
      return null;
    }
  }

  public Object[] TcsipOwnerClear(long hContext, TcTcsAuth inAuth1) throws TcTddlException, TcTpmException, TcTcsException {
    try {
      OwnerClearInParms inParms = new OwnerClearInParms();
      inParms.setHContext(new UnsignedInt(hContext));
      inParms.setOwnerAuth(ConvertDataTypesClient.convertTcsAuth(inAuth1));

      OwnerClearOutParms outParms = stub_.ownerClear(inParms);

      Object[] retval = new Object[2];
      retval[0] = outParms.getResult().longValue();
      retval[1] = ConvertDataTypesClient.convertTcsAuth(outParms.getOwnerAuth());

      return retval;
    } catch (RemoteException e) {
      ConvertRemoteExceptions.convertTcTcsException(e);
      ConvertRemoteExceptions.convertTcTddlException(e);
      ConvertRemoteExceptions.convertTcTpmException(e);
      return null;
    }
  }

  public Object[] TcsipForceClear(long hContext) throws TcTddlException, TcTpmException, TcTcsException {
    try {
      ForceClearInParms inParms = new ForceClearInParms();
      inParms.setHContext(new UnsignedInt(hContext));

      ForceClearOutParms outParms = stub_.forceClear(inParms);

      Object[] retval = new Object[1];
      retval[0] = outParms.getResult().longValue();

      return retval;
    } catch (RemoteException e) {
      ConvertRemoteExceptions.convertTcTcsException(e);
      ConvertRemoteExceptions.convertTcTddlException(e);
      ConvertRemoteExceptions.convertTcTpmException(e);
      return null;
    }
  }

  public Object[] TcsipDisableOwnerClear(long hContext, TcTcsAuth inAuth1) throws TcTddlException, TcTpmException, TcTcsException {
    try {
      DisableOwnerClearInParms inParms = new DisableOwnerClearInParms();
      inParms.setHContext(new UnsignedInt(hContext));
      inParms.setOwnerAuth(ConvertDataTypesClient.convertTcsAuth(inAuth1));

      DisableOwnerClearOutParms outParms = stub_.disableOwnerClear(inParms);

      Object[] retval = new Object[2];
      retval[0] = outParms.getResult().longValue();
      retval[1] = ConvertDataTypesClient.convertTcsAuth(outParms.getOwnerAuth());

      return retval;
    } catch (RemoteException e) {
      ConvertRemoteExceptions.convertTcTcsException(e);
      ConvertRemoteExceptions.convertTcTddlException(e);
      ConvertRemoteExceptions.convertTcTpmException(e);
      return null;
    }
  }

  public Object[] TcsipDisableForceClear(long hContext) throws TcTddlException, TcTpmException, TcTcsException {
    try {
      DisableForceClearInParms inParms = new DisableForceClearInParms();
      inParms.setHContext(new UnsignedInt(hContext));

      DisableForceClearOutParms outParms = stub_.disableForceClear(inParms);

      Object[] retval = new Object[1];
      retval[0] = outParms.getResult().longValue();

      return retval;
    } catch (RemoteException e) {
      ConvertRemoteExceptions.convertTcTcsException(e);
      ConvertRemoteExceptions.convertTcTddlException(e);
      ConvertRemoteExceptions.convertTcTpmException(e);
      return null;
    }
  }

  public Object[] TcsipPhysicalPresence(long hContext, int physicalPresence) throws TcTddlException, TcTpmException, TcTcsException {
    try {

      PhysicalPresenceInParms inParms = new PhysicalPresenceInParms();
      inParms.setHContext(new UnsignedInt(hContext));
      inParms.setFPhysicalPresence(new UnsignedShort(new Long(physicalPresence)));

      PhysicalPresenceOutParms outParms = stub_.physicalPresence(inParms);

      Object[] retval = new Object[1];
      retval[0] = outParms.getResult().longValue();

      return retval;
    } catch (RemoteException e) {
      ConvertRemoteExceptions.convertTcTcsException(e);
      ConvertRemoteExceptions.convertTcTddlException(e);
      ConvertRemoteExceptions.convertTcTpmException(e);
      return null;
    }
  }

  public Object[] TcsipGetCapability(long hContext, long capArea, TcBlobData subCap) throws TcTddlException, TcTpmException, TcTcsException {
    try {

      GetCapabilityTPMInParms inParms = new GetCapabilityTPMInParms();
      inParms.setCapArea(new UnsignedInt(capArea));
      inParms.setHContext(new UnsignedInt(hContext));
      if (subCap != null) {
        inParms.setSubCap(subCap.asByteArray());
      } else {
        inParms.setSubCap(new byte[0]);
      }

      //GetCapabilityOutParms outParms = stub_.getCapability(inParms);
      GetCapabilityTPMOutParms outParms = stub_.getCapabilityTPM(inParms);

      Object[] retval = new Object[2];
      retval[0] = outParms.getResult().longValue();
      try {
        retval[1] = TcBlobData.newByteArray(outParms.getResp());
      } catch (NullPointerException e) {
        retval[1] = TcBlobData.newByteArray(new byte[0]);
      }

      return retval;
    } catch (RemoteException e) {
      ConvertRemoteExceptions.convertTcTcsException(e);
      ConvertRemoteExceptions.convertTcTddlException(e);
      ConvertRemoteExceptions.convertTcTpmException(e);
      return null;
    }
  }

  public Object[] TcsipSetCapability(long hContext, long capArea, TcBlobData subCap, TcBlobData setValue, TcTcsAuth inAuth1) throws TcTddlException, TcTpmException, TcTcsException {
    try {
      SetCapabilityInParms inParms = new SetCapabilityInParms();
      inParms.setCapArea(new UnsignedInt(capArea));
      inParms.setHContext(new UnsignedInt(hContext));
      inParms.setOwnerAuth(ConvertDataTypesClient.convertTcsAuth(inAuth1));
      inParms.setSubCap(subCap.asByteArray());
      inParms.setValue(setValue.asByteArray());

      SetCapabilityOutParms outParms = stub_.setCapability(inParms);

      Object[] retval = new Object[1];
      retval[0] = outParms.getResult().longValue();

      return retval;
    } catch (RemoteException e) {
      ConvertRemoteExceptions.convertTcTcsException(e);
      ConvertRemoteExceptions.convertTcTddlException(e);
      ConvertRemoteExceptions.convertTcTpmException(e);
      return null;
    }
  }

  public Object[] TcsipGetCapabilityOwner(long hContext, TcTcsAuth inAuth1) throws TcTddlException, TcTpmException, TcTcsException {
    try {
      GetCapabilityOwnerInParms inParms = new GetCapabilityOwnerInParms();
      inParms.setHContext(new UnsignedInt(hContext));
      inParms.setPOwnerAuth(ConvertDataTypesClient.convertTcsAuth(inAuth1));

      GetCapabilityOwnerOutParms outParms = stub_.getCapabilityOwner(inParms);

      Object[] retval = new Object[5];
      retval[0] = outParms.getResult().longValue();
      retval[1] = ConvertDataTypesClient.convertTcsAuth(outParms.getPOwnerAuth());
      retval[2] = ConvertDataTypesClient.convertTssVersion(outParms.getPVersion());
      retval[3] = outParms.getPNonVolatileFlags().longValue();
      retval[4] = outParms.getPVolatileFlags().longValue();

      return retval;
    } catch (RemoteException e) {
      ConvertRemoteExceptions.convertTcTcsException(e);
      ConvertRemoteExceptions.convertTcTddlException(e);
      ConvertRemoteExceptions.convertTcTpmException(e);
      return null;
    }
  }

  public Object[] TcsipGetAuditDigest(long hContext, long startOrdinal) throws TcTddlException, TcTpmException, TcTcsException {
    try {
      GetAuditDigestInParms inParms = new GetAuditDigestInParms();
      inParms.setHContext(new UnsignedInt(hContext));
      inParms.setStartOrdinal(new UnsignedInt(startOrdinal));

      GetAuditDigestOutParms outParms = stub_.getAuditDigest(inParms);

      Object[] retval = new Object[5];
      retval[0] = outParms.getResult().longValue();
      retval[1] = TcBlobData.newByteArray(outParms.getCounterValue());
      retval[2] = outParms.getAuditDigest() == null ? null : new TcTpmDigest(TcBlobData.newByteArray(outParms.getAuditDigest()));
      retval[3] = outParms.getMore() == (byte) 1 ? true : false;
      retval[4] = outParms.getOrdList();

      Byte[] tempArray = new Byte[outParms.getOrdList().length];

      for (int i = 0; i < tempArray.length; i++) {
        tempArray[i] = outParms.getOrdList()[i].byteValue();
      }
      retval[4] = tempArray;

      return retval;
    } catch (RemoteException e) {
      ConvertRemoteExceptions.convertTcTcsException(e);
      ConvertRemoteExceptions.convertTcTddlException(e);
      ConvertRemoteExceptions.convertTcTpmException(e);
      return null;
    }
  }

  public Object[] TcsipGetAuditDigestSigned(long hContext, long keyHandle, boolean closeAudit, TcTpmNonce antiReplay, TcTcsAuth inAuth1) throws TcTddlException, TcTpmException, TcTcsException {
    try {
      GetAuditDigestSignedInParms inParms = new GetAuditDigestSignedInParms();
      inParms.setAntiReplay(antiReplay.getEncoded().asByteArray());
      inParms.setCloseAudit(closeAudit ? (byte) 1 : (byte) 0);
      inParms.setHContext(new UnsignedInt(hContext));
      inParms.setKeyHandle(new UnsignedInt(keyHandle));
      inParms.setPrivAuth(ConvertDataTypesClient.convertTcsAuth(inAuth1));

      GetAuditDigestSignedOutParms outParms = stub_.getAuditDigestSigned(inParms);

      Object[] retval = new Object[6];
      retval[0] = outParms.getResult().longValue();
      retval[1] = ConvertDataTypesClient.convertTcsAuth(outParms.getPrivAuth());
      retval[2] = TcBlobData.newByteArray(outParms.getCounterValue());
      retval[3] = outParms.getAuditDigest() == null ? null : new TcTpmDigest(TcBlobData.newByteArray(outParms.getAuditDigest()));
      retval[4] = outParms.getOrdinalDigest() == null ? null : new TcTpmDigest(TcBlobData.newByteArray(outParms.getOrdinalDigest()));
      retval[5] = TcBlobData.newByteArray(outParms.getSig());

      return retval;
    } catch (RemoteException e) {
      ConvertRemoteExceptions.convertTcTcsException(e);
      ConvertRemoteExceptions.convertTcTddlException(e);
      ConvertRemoteExceptions.convertTcTpmException(e);
      return null;
    }
  }

  public Object[] TcsipSetOrdinalAuditStatus(long hContext, TcTcsAuth inAuth1, long ordinalToAudit, boolean auditState) throws TcTddlException, TcTpmException, TcTcsException {
    try {
      SetOrdinalAuditStatusInParms inParms = new SetOrdinalAuditStatusInParms();
      inParms.setAuditState(auditState ? (byte) 1 : (byte) 0);
      inParms.setHContext(new UnsignedInt(hContext));
      inParms.setOrdinalToAudit(new UnsignedInt(ordinalToAudit));
      inParms.setOwnerAuth(ConvertDataTypesClient.convertTcsAuth(inAuth1));

      SetOrdinalAuditStatusOutParms outParms = stub_.setOrdinalAuditStatus(inParms);

      Object[] retval = new Object[1];
      outParms.getOwnerAuth();
      retval[0] = outParms.getResult().longValue();

      return retval;
    } catch (RemoteException e) {
      ConvertRemoteExceptions.convertTcTcsException(e);
      ConvertRemoteExceptions.convertTcTddlException(e);
      ConvertRemoteExceptions.convertTcTpmException(e);
      return null;
    }
  }

  public Object[] TcsipFieldUpgrade(long hContext, TcBlobData inData, TcTcsAuth ownerAuth) throws TcTddlException, TcTpmException, TcTcsException {
    try {
      FieldUpgradeInParms inParms = new FieldUpgradeInParms();
      inParms.setDataIn(inData.asByteArray());
      inParms.setHContext(new UnsignedInt(hContext));
      inParms.setOwnerAuth(ConvertDataTypesClient.convertTcsAuth(ownerAuth));

      // Vedor specific - no implementation - method throws an Exception.
      stub_.fieldUpgrade(inParms);

      return null;
    } catch (RemoteException e) {
      ConvertRemoteExceptions.convertTcTcsException(e);
      ConvertRemoteExceptions.convertTcTddlException(e);
      ConvertRemoteExceptions.convertTcTpmException(e);
      return null;
    }
  }

  public Object[] TcsipSetRedirection(long hContext, long keyHandle, long redirCmd, TcBlobData inputData, TcTcsAuth inAuth1) throws TcTddlException, TcTpmException, TcTcsException {
    try {
      SetRedirectionInParms inParms = new SetRedirectionInParms();
      inParms.setHContext(new UnsignedInt(hContext));
      inParms.setKeyHandle(new UnsignedInt(keyHandle));
      inParms.setPrivAuth(ConvertDataTypesClient.convertTcsAuth(inAuth1));

      SetRedirectionOutParms outParms = stub_.setRedirection(inParms);

      Object[] retval = new Object[2];
      retval[0] = outParms.getResult().longValue();
      retval[1] = ConvertDataTypesClient.convertTcsAuth(outParms.getPrivAuth());

      return retval;
    } catch (RemoteException e) {
      ConvertRemoteExceptions.convertTcTcsException(e);
      ConvertRemoteExceptions.convertTcTddlException(e);
      ConvertRemoteExceptions.convertTcTpmException(e);
      return null;
    }
  }

  public Object[] TcsipResetLockValue(long hContext, TcTcsAuth inAuth1) throws TcTddlException, TcTpmException, TcTcsException {
    try {
      ResetLockValueInParms inParms = new ResetLockValueInParms();
      inParms.setHContext(new UnsignedInt(hContext));
      inParms.setOwnerAuth(ConvertDataTypesClient.convertTcsAuth(inAuth1));

      ResetLockValueOutParms outParms = stub_.resetLockValue(inParms);

      Object[] retval = new Object[2];
      retval[0] = outParms.getResult().longValue();
      retval[1] = ConvertDataTypesClient.convertTcsAuth(outParms.getOwnerAuth());

      return retval;
    } catch (RemoteException e) {
      ConvertRemoteExceptions.convertTcTcsException(e);
      ConvertRemoteExceptions.convertTcTddlException(e);
      ConvertRemoteExceptions.convertTcTpmException(e);
      return null;
    }
  }

  public Object[] TcsipSeal(long hContext, long keyHandle, TcTpmEncauth encAuth, TcITpmPcrInfo pcrInfo, TcBlobData inData, TcTcsAuth inAuth1) throws TcTddlException, TcTpmException, TcTcsException {
    try {
      SealInParms inParms = new SealInParms();
      inParms.setEncAuth(encAuth.getEncoded().asByteArray());
      inParms.setHContext(new UnsignedInt(hContext));
      inParms.setInData(inData.asByteArray());
      inParms.setKeyHandle(new UnsignedInt(keyHandle));
      inParms.setPcrInfo(pcrInfo.getEncoded().asByteArray());
      inParms.setPubAuth(ConvertDataTypesClient.convertTcsAuth(inAuth1));
      SealOutParms outParms = stub_.seal(inParms);

      Object[] retval = new Object[3];
      retval[0] = outParms.getResult().longValue();
      retval[1] = ConvertDataTypesClient.convertTcsAuth(outParms.getPubAuth());
      retval[2] = outParms.getSealedData() == null ? null : new TcTpmStoredData(TcBlobData.newByteArray(outParms.getSealedData()));

      return retval;
    } catch (RemoteException e) {
      e.printStackTrace();
      ConvertRemoteExceptions.convertTcTcsException(e);
      ConvertRemoteExceptions.convertTcTddlException(e);
      ConvertRemoteExceptions.convertTcTpmException(e);
      return null;
    }
  }

  public Object[] TcsipUnseal(long hContext, long parentHandle, TcITpmStoredData inData, TcTcsAuth inAuth1, TcTcsAuth inAuth2) throws TcTddlException, TcTpmException, TcTcsException {
    try {
      UnsealInParms inParms = new UnsealInParms();
      inParms.setDataAuth(ConvertDataTypesClient.convertTcsAuth(inAuth1));
      inParms.setHContext(new UnsignedInt(hContext));
      inParms.setKeyAuth(ConvertDataTypesClient.convertTcsAuth(inAuth2));
      inParms.setKeyHandle(new UnsignedInt(parentHandle));
      inParms.setSealedData(inData.getEncoded().asByteArray());

      UnsealOutParms outParms = stub_.unseal(inParms);

      Object[] retval = new Object[4];
      retval[0] = outParms.getResult().longValue();
      retval[1] = ConvertDataTypesClient.convertTcsAuth(outParms.getDataAuth());
      retval[2] = ConvertDataTypesClient.convertTcsAuth(outParms.getKeyAuth());
      retval[3] = outParms.getData() == null ? null : TcBlobData.newByteArray(outParms.getData());

      return retval;
    } catch (RemoteException e) {
      ConvertRemoteExceptions.convertTcTcsException(e);
      ConvertRemoteExceptions.convertTcTddlException(e);
      ConvertRemoteExceptions.convertTcTpmException(e);
      return null;
    }
  }

  public Object[] TcsipUnBind(long hContext, long keyHandle, TcBlobData inData, TcTcsAuth inAuth1) throws TcTddlException, TcTpmException, TcTcsException {
    try {
      UnBindInParms inParms = new UnBindInParms();
      inParms.setHContext(new UnsignedInt(hContext));
      inParms.setInData(inData.asByteArray());
      inParms.setKeyHandle(new UnsignedInt(keyHandle));
      inParms.setPrivAuth(ConvertDataTypesClient.convertTcsAuth(inAuth1));

      UnBindOutParms outParms = stub_.unBind(inParms);

      Object[] retval = new Object[3];
      retval[0] = outParms.getResult().longValue();
      retval[1] = ConvertDataTypesClient.convertTcsAuth(outParms.getPrivAuth());
      retval[2] = outParms.getOutData() == null ? null : TcBlobData.newByteArray(outParms.getOutData());

      return retval;
    } catch (RemoteException e) {
      ConvertRemoteExceptions.convertTcTcsException(e);
      ConvertRemoteExceptions.convertTcTddlException(e);
      ConvertRemoteExceptions.convertTcTpmException(e);
      return null;
    }
  }

  public Object[] TcsipCreateWrapKey(long hContext, long parentHandle, TcTpmEncauth dataUsageAuth, TcTpmEncauth dataMigrationAuth, TcITpmKeyNew keyInfo, TcTcsAuth inAuth1) throws TcTddlException, TcTpmException, TcTcsException {
    try {
      CreateWrapKeyInParms inParms = new CreateWrapKeyInParms();
      inParms.setHContext(new UnsignedInt(hContext));
      inParms.setHWrappingKey(new UnsignedInt(parentHandle));
      inParms.setKeyInfo(keyInfo.getEncoded().asByteArray());
      inParms.setKeyMigrationAuth(dataMigrationAuth.getEncoded().asByteArray());
      inParms.setKeyUsageAuth(dataUsageAuth.getEncoded().asByteArray());
      inParms.setPAuth(ConvertDataTypesClient.convertTcsAuth(inAuth1));

      CreateWrapKeyOutParms outParms = stub_.createWrapKey(inParms);

      Object[] retval = new Object[3];
      retval[0] = outParms.getResult().longValue();
      retval[1] = ConvertDataTypesClient.convertTcsAuth(outParms.getPAuth());
      retval[2] = outParms.getKeyData() == null ? null : new TcTpmKey(TcBlobData.newByteArray(outParms.getKeyData()));

      return retval;
    } catch (RemoteException e) {
      ConvertRemoteExceptions.convertTcTcsException(e);
      ConvertRemoteExceptions.convertTcTddlException(e);
      ConvertRemoteExceptions.convertTcTpmException(e);
      return null;
    }
  }

  public Object[] TcsipSealx(long hContext, long keyHandle, TcTpmEncauth encAuth, TcTpmPcrInfoLong pcrInfo, TcBlobData inData, TcTcsAuth inAuth1) throws TcTddlException, TcTpmException, TcTcsException {
    try {

      SealxInParms inParms = new SealxInParms();
      inParms.setEncAuth(encAuth.getEncoded().asByteArray());
      inParms.setHContext(new UnsignedInt(hContext));
      inParms.setInData(inData.asByteArray());
      inParms.setKeyHandle(new UnsignedInt(keyHandle));
      inParms.setPcrInfo(pcrInfo.getEncoded().asByteArray());
      inParms.setPubAuth(ConvertDataTypesClient.convertTcsAuth(inAuth1));

      SealxOutParms outParms = stub_.sealx(inParms);

      Object[] retval = new Object[3];
      retval[0] = outParms.getResult().longValue();
      retval[1] = ConvertDataTypesClient.convertTcsAuth(outParms.getPubAuth());
      retval[2] = outParms.getSealedData() == null ? null : new TcTpmStoredData(TcBlobData.newByteArray(outParms.getSealedData()));

      return retval;
    } catch (RemoteException e) {
      ConvertRemoteExceptions.convertTcTcsException(e);
      ConvertRemoteExceptions.convertTcTddlException(e);
      ConvertRemoteExceptions.convertTcTpmException(e);
      return null;
    }
  }

  public Object[] TcsipCreateMigrationBlob(long hContext, long parentHandle, int migrationType, TcTpmMigrationkeyAuth migrationKeyAuth, TcBlobData encData, TcTcsAuth inAuth1, TcTcsAuth inAuth2) throws TcTddlException, TcTpmException, TcTcsException {
    try {
      CreateMigrationBlobInParms inParms = new CreateMigrationBlobInParms();
      inParms.setEncData(encData.asByteArray());
      inParms.setEntityAuth(ConvertDataTypesClient.convertTcsAuth(inAuth1));
      inParms.setHContext(new UnsignedInt(hContext));
      inParms.setMigrationKeyAuth(migrationKeyAuth.getEncoded().asByteArray());
      inParms.setMigrationType(new UnsignedShort(migrationType));
      inParms.setParentAuth(ConvertDataTypesClient.convertTcsAuth(inAuth2));
      inParms.setParentHandle(new UnsignedInt(parentHandle));

      CreateMigrationBlobOutParms outParms = stub_.createMigrationBlob(inParms);

      Object[] retval = new Object[5];
      retval[0] = outParms.getResult().longValue();
      retval[1] = ConvertDataTypesClient.convertTcsAuth(outParms.getParentAuth());
      retval[2] = ConvertDataTypesClient.convertTcsAuth(outParms.getEntityAuth());
      retval[3] = outParms.getRandom() == null ? null : TcBlobData.newByteArray(outParms.getRandom());
      retval[4] = outParms.getOutData() == null ? null : TcBlobData.newByteArray(outParms.getOutData());

      return retval;
    } catch (RemoteException e) {
      ConvertRemoteExceptions.convertTcTcsException(e);
      ConvertRemoteExceptions.convertTcTddlException(e);
      ConvertRemoteExceptions.convertTcTpmException(e);
      return null;
    }
  }

  public Object[] TcsipConvertMigrationBlob(long hContext, long parentHandle, TcBlobData inData, TcBlobData random, TcTcsAuth inAuth1) throws TcTddlException, TcTpmException, TcTcsException {
    try {

      ConvertMigrationBlobInParms inParms = new ConvertMigrationBlobInParms();
      inParms.setHContext(new UnsignedInt(hContext));
      inParms.setInData(inData.asByteArray());
      inParms.setParentAuth(ConvertDataTypesClient.convertTcsAuth(inAuth1));
      inParms.setParentHandle(new UnsignedInt(parentHandle));
      inParms.setRandom(random.asByteArray());

      ConvertMigrationBlobOutParms outParms = stub_.convertMigrationBlob(inParms);

      Object[] retval = new Object[3];
      retval[0] = outParms.getResult().longValue();
      retval[2] = ConvertDataTypesClient.convertTcsAuth(outParms.getParentAuth());
      retval[1] = outParms.getOutData() == null ? null : TcBlobData.newByteArray(outParms.getOutData());
      return retval;
    } catch (RemoteException e) {
      ConvertRemoteExceptions.convertTcTcsException(e);
      ConvertRemoteExceptions.convertTcTddlException(e);
      ConvertRemoteExceptions.convertTcTpmException(e);
      return null;
    }
  }

  public Object[] TcsipAuthorizeMigrationKey(long hContext, int migrationScheme, TcTpmPubkey migrationKey, TcTcsAuth inAuth1) throws TcTddlException, TcTpmException, TcTcsException {
    try {

      AuthorizeMigrationKeyInParms inParms = new AuthorizeMigrationKeyInParms();
      inParms.setHContext(new UnsignedInt(hContext));
      inParms.setMigrateScheme(new UnsignedInt(migrationScheme));
      inParms.setMigrationKey(migrationKey.getEncoded().asByteArray());
      inParms.setOwnerAuth(ConvertDataTypesClient.convertTcsAuth(inAuth1));

      AuthorizeMigrationKeyOutParms outParms = stub_.authorizeMigrationKey(inParms);

      Object[] retval = new Object[3];
      retval[0] = outParms.getResult().longValue();
      retval[1] = ConvertDataTypesClient.convertTcsAuth(outParms.getOwnerAuth());
      retval[2] = outParms.getMigrationKeyAuth() == null ? null : TcBlobData.newByteArray(outParms.getMigrationKeyAuth());

      return retval;
    } catch (RemoteException e) {
      ConvertRemoteExceptions.convertTcTcsException(e);
      ConvertRemoteExceptions.convertTcTddlException(e);
      ConvertRemoteExceptions.convertTcTpmException(e);
      return null;
    }
  }

  public Object[] TcsipMigrateKey(long hContext, long maKeyHandle, TcTpmPubkey pubKey, TcBlobData inData, TcTcsAuth inAuth1) throws TcTddlException, TcTpmException, TcTcsException {
    try {

      MigrateKeyInParms inParms = new MigrateKeyInParms();
      inParms.setHContext(new UnsignedInt(hContext));
      inParms.setHMaKey(new UnsignedInt(maKeyHandle));
      inParms.setInData(inData.asByteArray());
      inParms.setOwnerAuth(ConvertDataTypesClient.convertTcsAuth(inAuth1));
      inParms.setPublicKey(pubKey.getEncoded().asByteArray());

      MigrateKeyOutParms outParms = stub_.migrateKey(inParms);

      Object[] retval = new Object[3];
      retval[0] = outParms.getResult().longValue();
      retval[1] = ConvertDataTypesClient.convertTcsAuth(outParms.getOwnerAuth());
      retval[2] = outParms.getOutData() == null ? null : TcBlobData.newByteArray(outParms.getOutData());

      return retval;
    } catch (RemoteException e) {
      ConvertRemoteExceptions.convertTcTcsException(e);
      ConvertRemoteExceptions.convertTcTddlException(e);
      ConvertRemoteExceptions.convertTcTpmException(e);
      return null;
    }
  }

  public Object[] TcsipCmkSetRestrictions(long hContext, long restriction, TcTcsAuth inAuth1) throws TcTddlException, TcTpmException, TcTcsException {
    try {
      CreateMaintenanceArchiveInParms inParms = new CreateMaintenanceArchiveInParms();
      inParms.setHContext(new UnsignedInt(hContext));
      inParms.setOwnerAuth(ConvertDataTypesClient.convertTcsAuth(inAuth1));

      CreateMaintenanceArchiveOutParms outParms = stub_.createMaintenanceArchive(inParms);

      Object[] retval = new Object[2];
      retval[0] = outParms.getResult().longValue();
      retval[1] = ConvertDataTypesClient.convertTcsAuth(outParms.getOwnerAuth());

      return retval;
    } catch (RemoteException e) {
      ConvertRemoteExceptions.convertTcTcsException(e);
      ConvertRemoteExceptions.convertTcTddlException(e);
      ConvertRemoteExceptions.convertTcTpmException(e);
      return null;
    }
  }

  public Object[] TcsipLoadMaintenanceArchive(long hContext, TcBlobData inData, TcTcsAuth ownerAuth) throws TcTddlException, TcTpmException, TcTcsException {
    try {
      LoadMaintenanceArchiveInParms inParms = new LoadMaintenanceArchiveInParms();
      inParms.setDataIn(inData.asByteArray());
      inParms.setHContext(new UnsignedInt(hContext));
      inParms.setOwnerAuth(ConvertDataTypesClient.convertTcsAuth(ownerAuth));

      LoadMaintenanceArchiveOutParms outParms = stub_.loadMaintenanceArchive(inParms);

      Object[] retval = new Object[2];

      retval[0] = outParms.getDataOut() == null ? null : TcBlobData.newByteArray(outParms.getDataOut());
      retval[1] = ConvertDataTypesClient.convertTcsAuth(outParms.getOwnerAuth());

      return retval;
    } catch (RemoteException e) {
      ConvertRemoteExceptions.convertTcTcsException(e);
      ConvertRemoteExceptions.convertTcTddlException(e);
      ConvertRemoteExceptions.convertTcTpmException(e);
      return null;
    }
  }

  public Object[] TcsipKillMaintenanceFeature(long hContext, TcTcsAuth inAuth1) throws TcTddlException, TcTpmException, TcTcsException {
    try {
      KillMaintenanceFeatureInParms inParms = new KillMaintenanceFeatureInParms();
      inParms.setHContext(new UnsignedInt(hContext));
      inParms.setOwnerAuth(ConvertDataTypesClient.convertTcsAuth(inAuth1));

      KillMaintenanceFeatureOutParms outParms = stub_.killMaintenanceFeature(inParms);

      Object[] retval = new Object[2];
      retval[0] = outParms.getResult().longValue();
      retval[1] = ConvertDataTypesClient.convertTcsAuth(outParms.getOwnerAuth());

      return retval;
    } catch (RemoteException e) {
      ConvertRemoteExceptions.convertTcTcsException(e);
      ConvertRemoteExceptions.convertTcTddlException(e);
      ConvertRemoteExceptions.convertTcTpmException(e);
      return null;
    }
  }

  public Object[] TcsipLoadManuMaintPub(long hContext, TcTpmNonce antiReplay, TcTpmPubkey pubKey) throws TcTddlException, TcTpmException, TcTcsException {
    try {
      LoadManuMaintPubInParms inParms = new LoadManuMaintPubInParms();
      inParms.setAntiReplay(antiReplay.getEncoded().asByteArray());
      inParms.setHContext(new UnsignedInt(hContext));
      inParms.setPubKey(pubKey.getEncoded().asByteArray());

      LoadManuMaintPubOutParms outParms = stub_.loadManuMaintPub(inParms);

      Object[] retval = new Object[2];
      retval[0] = outParms.getResult();
      retval[1] = outParms.getChecksum() == null ? null : new TcTpmDigest(TcBlobData.newByteArray(outParms.getChecksum()));

      return retval;
    } catch (RemoteException e) {
      ConvertRemoteExceptions.convertTcTcsException(e);
      ConvertRemoteExceptions.convertTcTddlException(e);
      ConvertRemoteExceptions.convertTcTpmException(e);
      return null;
    }
  }

  public Object[] TcsipReadManuMaintPub(long hContext, TcTpmNonce antiReplay) throws TcTddlException, TcTpmException, TcTcsException {
    try {
      ReadManuMaintPubInParms inParms = new ReadManuMaintPubInParms();
      inParms.setAntiReplay(antiReplay.getEncoded().asByteArray());
      inParms.setHContext(new UnsignedInt(hContext));

      ReadManuMaintPubOutParms outParms = stub_.readManuMaintPub(inParms);

      Object[] retval = new Object[2];
      retval[0] = outParms.getResult().longValue();
      retval[1] = outParms.getChecksum() == null ? null : new TcTpmDigest(TcBlobData.newByteArray(outParms.getChecksum()));

      return retval;
    } catch (RemoteException e) {
      ConvertRemoteExceptions.convertTcTcsException(e);
      ConvertRemoteExceptions.convertTcTddlException(e);
      ConvertRemoteExceptions.convertTcTpmException(e);
      return null;
    }
  }

  public Object[] TcsipSign(long hContext, long keyHandle, TcBlobData areaToSign, TcTcsAuth inAuth1) throws TcTddlException, TcTpmException, TcTcsException {
    try {
      SignInParms inParms = new SignInParms();
      inParms.setAreaToSign(areaToSign.asByteArray());
      inParms.setHContext(new UnsignedInt(hContext));
      inParms.setKeyHandle(new UnsignedInt(keyHandle));
      inParms.setPrivAuth(ConvertDataTypesClient.convertTcsAuth(inAuth1));

      SignOutParms outParms = stub_.sign(inParms);

      Object[] retval = new Object[3];

      retval[0] = outParms.getResult().longValue();
      retval[1] = ConvertDataTypesClient.convertTcsAuth(outParms.getPrivAuth());
      retval[2] = TcBlobData.newByteArray(outParms.getSig());

      return retval;
    } catch (RemoteException e) {
      ConvertRemoteExceptions.convertTcTcsException(e);
      ConvertRemoteExceptions.convertTcTddlException(e);
      ConvertRemoteExceptions.convertTcTpmException(e);
      return null;
    }
  }

  public Object[] TcsipGetRandom(long hContext, long bytesRequested) throws TcTddlException, TcTpmException, TcTcsException {
    try {
      GetRandomInParms inParms = new GetRandomInParms();
      inParms.setBytesRequested(new UnsignedInt(bytesRequested));
      inParms.setHContext(new UnsignedInt(hContext));

      GetRandomOutParms outParms = stub_.getRandom(inParms);

      Object[] retval = new Object[2];
      retval[0] = outParms.getResult().longValue();
      retval[1] = TcBlobData.newByteArray(outParms.getRandomBytes());

      return retval;
    } catch (RemoteException e) {
      ConvertRemoteExceptions.convertTcTcsException(e);
      ConvertRemoteExceptions.convertTcTddlException(e);
      ConvertRemoteExceptions.convertTcTpmException(e);
      return null;
    }
  }

  public Object[] TcsipStirRandom(long hContext, TcBlobData inData) throws TcTddlException, TcTpmException, TcTcsException {
    try {
      StirRandomInParms inParms = new StirRandomInParms();
      inParms.setHContext(new UnsignedInt(hContext));
      inParms.setInData(inData.asByteArray());

      StirRandomOutParms outParms = stub_.stirRandom(inParms);

      Object[] retval = new Object[1];
      retval[0] = outParms.getResult().longValue();

      return retval;
    } catch (RemoteException e) {
      ConvertRemoteExceptions.convertTcTcsException(e);
      ConvertRemoteExceptions.convertTcTddlException(e);
      ConvertRemoteExceptions.convertTcTpmException(e);
      return null;
    }
  }

  public Object[] TcsipCertifyKey(long hContext, long certHandle, long keyHandle, TcTpmNonce antiReplay, TcTcsAuth inAuth1, TcTcsAuth inAuth2) throws TcTddlException, TcTpmException, TcTcsException {
    try {
      CertifyKeyInParms inParms = new CertifyKeyInParms();
      inParms.setAntiReplay(antiReplay.getEncoded().asByteArray());
      inParms.setCertAuth(ConvertDataTypesClient.convertTcsAuth(inAuth1));
      inParms.setCertHandle(new UnsignedInt(certHandle));
      inParms.setHContext(new UnsignedInt(hContext));
      inParms.setKeyAuth(ConvertDataTypesClient.convertTcsAuth(inAuth2));
      inParms.setKeyHandle(new UnsignedInt(keyHandle));

      CertifyKeyOutParms outParms = stub_.certifyKey(inParms);

      Object[] retval = new Object[5];
      retval[0] = outParms.getResult().longValue();
      retval[1] = ConvertDataTypesClient.convertTcsAuth(outParms.getCertAuth());
      retval[2] = ConvertDataTypesClient.convertTcsAuth(outParms.getKeyAuth());
      
      
      TcBlobData certInfo2Tag = TcBlobData.newByteArray(new byte[] { 0x00, TcTpmConstants.TPM_TAG_CERTIFY_INFO2 });
      TcBlobData tag = TcBlobData.newByteArray(TcBlobData.newByteArray(outParms.getCertifyInfo()).getRange(0, 2));
 
      Object certInfoObj = null;
      if (tag.equals(certInfo2Tag)) {
    	  certInfoObj = new TcTpmCertifyInfo2(TcBlobData.newByteArray(outParms.getCertifyInfo()));
      } else {
    	  certInfoObj = new TcTpmCertifyInfo(TcBlobData.newByteArray(outParms.getCertifyInfo()));
      }
      retval[3] = outParms.getCertifyInfo() == null ? null : certInfoObj;
      
      retval[4] = outParms.getOutData() == null ? null : TcBlobData.newByteArray(outParms.getOutData());

      return retval;
    } catch (RemoteException e) {
      ConvertRemoteExceptions.convertTcTcsException(e);
      ConvertRemoteExceptions.convertTcTddlException(e);
      ConvertRemoteExceptions.convertTcTpmException(e);
      return null;
    }
  }

  public Object[] TcsipCertifyKey2(long hContext, long certHandle, long keyHandle, TcTpmDigest migrationPubDigest, TcTpmNonce antiReplay, TcTcsAuth inAuth1, TcTcsAuth inAuth2) throws TcTddlException, TcTpmException, TcTcsException {
    try {
      CertifyKey2InParms inParms = new CertifyKey2InParms();
      inParms.setAntiReplay(antiReplay.getEncoded().asByteArray());
      inParms.setCertAuth(ConvertDataTypesClient.convertTcsAuth(inAuth1));
      inParms.setCertHandle(new UnsignedInt(certHandle));
      inParms.setHContext(new UnsignedInt(hContext));
      inParms.setKeyAuth(ConvertDataTypesClient.convertTcsAuth(inAuth2));
      inParms.setKeyHandle(new UnsignedInt(keyHandle));
      inParms.setMSAdigest(migrationPubDigest.getEncoded().asByteArray());

      CertifyKey2OutParms outParms = stub_.certifyKey2(inParms);

      Object[] retval = new Object[5];
      retval[0] = outParms.getResult().longValue();
      retval[1] = ConvertDataTypesClient.convertTcsAuth(outParms.getCertAuth());
      retval[2] = ConvertDataTypesClient.convertTcsAuth(outParms.getKeyAuth());
      retval[3] = outParms.getCertifyInfo() == null ? null : new TcTpmCertifyInfo(TcBlobData.newByteArray(outParms.getCertifyInfo()));
      retval[4] = outParms.getOutData() == null ? null : TcBlobData.newByteArray(outParms.getOutData());

      return retval;
    } catch (RemoteException e) {
      ConvertRemoteExceptions.convertTcTcsException(e);
      ConvertRemoteExceptions.convertTcTddlException(e);
      ConvertRemoteExceptions.convertTcTpmException(e);
      return null;
    }
  }

  public Object[] TcsipCreateEndorsementKeyPair(long hContext, TcTpmNonce antiReplay, TcTpmKeyParms keyInfo) throws TcTddlException, TcTpmException, TcTcsException {
    try {
      CreateEndorsementKeyPairInParms inParms = new CreateEndorsementKeyPairInParms();
      inParms.setAntiReplay(antiReplay.getEncoded().asByteArray());
      inParms.setEndorsementKeyInfo(keyInfo.getEncoded().asByteArray());
      inParms.setHContext(new UnsignedInt(hContext));

      CreateEndorsementKeyPairOutParms outParms = stub_.createEndorsementKeyPair(inParms);

      Object[] retval = new Object[3];
      retval[0] = outParms.getResult().longValue();
      retval[1] = outParms.getEndorsementKey() == null ? null : new TcTpmPubkey(TcBlobData.newByteArray(outParms.getEndorsementKey()));
      retval[2] = outParms.getChecksum() == null ? null : new TcTpmDigest(TcBlobData.newByteArray(outParms.getChecksum()));

      return retval;
    } catch (RemoteException e) {
      ConvertRemoteExceptions.convertTcTcsException(e);
      ConvertRemoteExceptions.convertTcTddlException(e);
      ConvertRemoteExceptions.convertTcTpmException(e);
      return null;
    }
  }

  public Object[] TcsipCreateRevocableEK(long hContext, TcTpmNonce antiReplay, TcTpmKeyParms keyInfo, boolean generateReset, TcTpmNonce inputEKreset) throws TcTddlException, TcTpmException, TcTcsException {
    try {
      CreateRevocableEndorsementKeyPairInParms inParms = new CreateRevocableEndorsementKeyPairInParms();
      inParms.setAntiReplay(antiReplay.getEncoded().asByteArray());
      inParms.setEKResetAuth(inputEKreset.getEncoded().asByteArray());
      inParms.setEndorsementKeyInfo(keyInfo.getEncoded().asByteArray());
      inParms.setGenResetAuth(generateReset ? (byte) 1 : (byte) 0);
      inParms.setHContext(new UnsignedInt(hContext));

      CreateRevocableEndorsementKeyPairOutParms outParms = stub_.createRevocableEndorsementKeyPair(inParms);


      Object[] retval = new Object[4];
      retval[0] = outParms.getResult().longValue();
      retval[1] = outParms.getEndorsementKey() == null ? null : new TcTpmKey(TcBlobData.newByteArray(outParms.getEndorsementKey()));
      retval[2] = outParms.getChecksum() == null ? null : new TcTpmDigest(TcBlobData.newByteArray(outParms.getChecksum()));
      retval[3] = TcBlobData.newByteArray(outParms.getEKResetAuth());

      return retval;
    } catch (RemoteException e) {
      ConvertRemoteExceptions.convertTcTcsException(e);
      ConvertRemoteExceptions.convertTcTddlException(e);
      ConvertRemoteExceptions.convertTcTpmException(e);
      return null;
    }
  }

  public Object[] TcsipRevokeEndorsementKeyPair(long hContext, TcTpmNonce EKReset) throws TcTddlException, TcTpmException, TcTcsException {
    try {
      RevokeEndorsementKeyPairInParms inParms = new RevokeEndorsementKeyPairInParms();
      inParms.setEKResetAuth(EKReset.getEncoded().asByteArray());
      inParms.setHContext(new UnsignedInt(hContext));

      RevokeEndorsementKeyPairOutParms outParms = stub_.revokeEndorsementKeyPair(inParms);

      Object[] retval = new Object[1];
      retval[0] = outParms.getResult().longValue();

      return retval;
    } catch (RemoteException e) {
      ConvertRemoteExceptions.convertTcTcsException(e);
      ConvertRemoteExceptions.convertTcTddlException(e);
      ConvertRemoteExceptions.convertTcTpmException(e);
      return null;
    }
  }

  public Object[] TcsipReadPubek(long hContext, TcTpmNonce antiReplay) throws TcTddlException, TcTpmException, TcTcsException {
    try {
      ReadPubekInParms inParms = new ReadPubekInParms();
      inParms.setAntiReplay(antiReplay.getEncoded().asByteArray());
      inParms.setHContext(new UnsignedInt(hContext));

      ReadPubekOutParms outParms = stub_.readPubek(inParms);

      Object[] retval = new Object[3];
      retval[0] = outParms.getResult().longValue();
      retval[1] = outParms.getPubEndorsementKey() == null ? null : new TcTpmPubkey(TcBlobData.newByteArray(outParms.getPubEndorsementKey()));
      retval[2] = outParms.getChecksum() == null ? null : new TcTpmDigest(TcBlobData.newByteArray(outParms.getChecksum()));

      return retval;
    } catch (RemoteException e) {
      ConvertRemoteExceptions.convertTcTcsException(e);
      ConvertRemoteExceptions.convertTcTddlException(e);
      ConvertRemoteExceptions.convertTcTpmException(e);
      return null;
    }
  }

  public Object[] TcsipActivateIdentity(long hContext, long idKeyHandle, TcBlobData blob, TcTcsAuth inAuth1, TcTcsAuth inAuth2) throws TcTddlException, TcTpmException, TcTcsException {
    try {
      ActivateTPMIdentityInParms inParms = new ActivateTPMIdentityInParms();
      inParms.setBlob(blob.asByteArray());
      inParms.setHContext(new UnsignedInt(hContext));
      inParms.setIdKey(new UnsignedInt(idKeyHandle));
      inParms.setIdKeyAuth(ConvertDataTypesClient.convertTcsAuth(inAuth1));
      inParms.setOwnerAuth(ConvertDataTypesClient.convertTcsAuth(inAuth2));

      ActivateTPMIdentityOutParms outParms = stub_.activateTPMIdentity(inParms);

      Object[] retval = new Object[4];
      retval[0] = outParms.getResult().longValue();
      retval[1] = ConvertDataTypesClient.convertTcsAuth(outParms.getIdKeyAuth());
      retval[2] = ConvertDataTypesClient.convertTcsAuth(outParms.getOwnerAuth());
      retval[3] = outParms.getSymmetricKey() == null ? null : new TcTpmSymmetricKey(TcBlobData.newByteArray(outParms.getSymmetricKey()));

      return retval;
    } catch (RemoteException e) {
      ConvertRemoteExceptions.convertTcTcsException(e);
      ConvertRemoteExceptions.convertTcTddlException(e);
      ConvertRemoteExceptions.convertTcTpmException(e);
      return null;
    }
  }

  public Object[] TcsipExtend(long hContext, long pcrNum, TcTpmDigest inDigest) throws TcTddlException, TcTpmException, TcTcsException {
    try {
      ExtendInParms inParms = new ExtendInParms();
      inParms.setHContext(new UnsignedInt(hContext));
      inParms.setInDigest(inDigest.getEncoded().asByteArray());
      inParms.setPcrNum(new UnsignedInt(pcrNum));

      ExtendOutParms outParms = stub_.extend(inParms);

      Object[] retval = new Object[2];
      retval[0] = outParms.getResult().longValue();
      retval[1] = outParms.getOutDigest() == null ? null : new TcTpmDigest(TcBlobData.newByteArray(outParms.getOutDigest()));

      return retval;
    } catch (RemoteException e) {
      ConvertRemoteExceptions.convertTcTcsException(e);
      ConvertRemoteExceptions.convertTcTddlException(e);
      ConvertRemoteExceptions.convertTcTpmException(e);
      return null;
    }
  }

  public Object[] TcsipPcrRead(long hContext, long pcrIndex) throws TcTddlException, TcTpmException, TcTcsException {
    try {
      PcrReadInParms inParms = new PcrReadInParms();
      inParms.setHContext(new UnsignedInt(hContext));
      inParms.setPcrNum(new UnsignedInt(pcrIndex));

      PcrReadOutParms outParms = stub_.pcrRead(inParms);

      Object[] retval = new Object[2];
      retval[0] = outParms.getResult().longValue();
      retval[1] = outParms.getOutDigest() == null ? null : new TcTpmDigest(TcBlobData.newByteArray(outParms.getOutDigest()));

      return retval;
    } catch (RemoteException e) {
      ConvertRemoteExceptions.convertTcTcsException(e);
      ConvertRemoteExceptions.convertTcTddlException(e);
      ConvertRemoteExceptions.convertTcTpmException(e);
      return null;
    }
  }

  public Object[] TcsipQuote(long hContext, long keyHandle, TcTpmNonce externalData, TcTpmPcrSelection targetPCR, TcTcsAuth inAuth1) throws TcTddlException, TcTpmException, TcTcsException {
    try {
      QuoteInParms inParms = new QuoteInParms();
      inParms.setAntiReplay(externalData.getEncoded().asByteArray());
      inParms.setHContext(new UnsignedInt(hContext));
      inParms.setKeyHandle(new UnsignedInt(keyHandle));
      inParms.setPcrTarget(targetPCR.getEncoded().asByteArray());
      inParms.setPrivAuth(ConvertDataTypesClient.convertTcsAuth(inAuth1));

      QuoteOutParms outParms = stub_.quote(inParms);

      Object[] retval = new Object[4];
      retval[0] = outParms.getResult().longValue();
      retval[1] = ConvertDataTypesClient.convertTcsAuth(outParms.getPrivAuth());
      retval[2] = outParms.getPcrData() == null ? null : new TcTpmPcrComposite(TcBlobData.newByteArray(outParms.getPcrData()));
      retval[3] = outParms.getSig() == null ? null : TcBlobData.newByteArray(outParms.getSig());

      return retval;
    } catch (RemoteException e) {
      ConvertRemoteExceptions.convertTcTcsException(e);
      ConvertRemoteExceptions.convertTcTddlException(e);
      ConvertRemoteExceptions.convertTcTpmException(e);
      return null;
    }
  }

  public Object[] TcsipPcrReset(long hContext, TcTpmPcrSelection pcrSelection) throws TcTddlException, TcTpmException, TcTcsException {
    try {
      PcrResetInParms inParms = new PcrResetInParms();
      inParms.setHContext(new UnsignedInt(hContext));
      inParms.setPcrTarget(pcrSelection.getEncoded().asByteArray());

      PcrResetOutParms outParms = stub_.pcrReset(inParms);

      Object[] retval = new Object[1];
      retval[0] = outParms.getResult().longValue();

      return retval;
    } catch (RemoteException e) {
      ConvertRemoteExceptions.convertTcTcsException(e);
      ConvertRemoteExceptions.convertTcTddlException(e);
      ConvertRemoteExceptions.convertTcTpmException(e);
      return null;
    }
  }

  public Object[] TcsipQuote2(long hContext, long keyHandle, TcTpmNonce externalData, TcTpmPcrSelection targetPCR, boolean addVersion, TcTcsAuth inAuth1) throws TcTddlException, TcTpmException, TcTcsException {
    try {
      Quote2InParms inParms = new Quote2InParms();
      inParms.setAddVersion(addVersion ? (byte) 1 : (byte) 0);
      inParms.setAntiReplay(externalData.getEncoded().asByteArray());
      inParms.setHContext(new UnsignedInt(hContext));
      inParms.setKeyHandle(new UnsignedInt(keyHandle));
      inParms.setPcrTarget(targetPCR.getEncoded().asByteArray());
      inParms.setPrivAuth(ConvertDataTypesClient.convertTcsAuth(inAuth1));

      Quote2OutParms outParms = stub_.quote2(inParms);

      Object[] retval = new Object[5];
      retval[0] = outParms.getResult().longValue();
      retval[1] = ConvertDataTypesClient.convertTcsAuth(outParms.getPrivAuth());
      retval[2] = new TcTpmPcrInfoShort(TcBlobData.newByteArray(outParms.getPcrData()));
      retval[3] = (outParms.getVersionInfo() == null) ? null : new TcTpmCapVersionInfo(TcBlobData.newByteArray(outParms.getVersionInfo()));
      retval[4] = TcBlobData.newByteArray(outParms.getSig());

      return retval;
    } catch (RemoteException e) {
      ConvertRemoteExceptions.convertTcTcsException(e);
      ConvertRemoteExceptions.convertTcTddlException(e);
      ConvertRemoteExceptions.convertTcTpmException(e);
      return null;
    }
  }

  public Object[] TcsipChangeAuth(long hContext, long parentHandle, int protocolID, TcTpmEncauth newAuth, int entityType, TcBlobData encData, TcTcsAuth inAuth1, TcTcsAuth inAuth2) throws TcTddlException, TcTpmException, TcTcsException {
    try {
      ChangeAuthInParms inParms = new ChangeAuthInParms();
      inParms.setEncData(encData.asByteArray());
      inParms.setEntityAuth(ConvertDataTypesClient.convertTcsAuth(inAuth1));
      inParms.setEntityType(new UnsignedInt(entityType));
      inParms.setHContext(new UnsignedInt(hContext));
      inParms.setNewAuth(newAuth.getEncoded().asByteArray());
      inParms.setOwnerAuth(ConvertDataTypesClient.convertTcsAuth(inAuth2));
      inParms.setParentHandle(new UnsignedInt(parentHandle));
      inParms.setProtocolID(new UnsignedInt(protocolID));

      ChangeAuthOutParms outParms = stub_.changeAuth(inParms);

      Object[] retval = new Object[4];
      retval[0] = outParms.getResult().longValue();
      retval[1] = ConvertDataTypesClient.convertTcsAuth(outParms.getOwnerAuth());
      retval[2] = ConvertDataTypesClient.convertTcsAuth(outParms.getEntityAuth());
      retval[3] = outParms.getOutData() == null ? null : TcBlobData.newByteArray(outParms.getOutData());

      return retval;
    } catch (RemoteException e) {
      ConvertRemoteExceptions.convertTcTcsException(e);
      ConvertRemoteExceptions.convertTcTddlException(e);
      ConvertRemoteExceptions.convertTcTpmException(e);
      return null;
    }
  }

  public Object[] TcsipChangeAuthOwner(long hContext, int protocolID, TcTpmEncauth newAuth, int entityType, TcTcsAuth inAuth1) throws TcTddlException, TcTpmException, TcTcsException {
    try {
      ChangeAuthOwnerInParms inParms = new ChangeAuthOwnerInParms();
      inParms.setEntityType(new UnsignedInt(entityType));
      inParms.setHContext(new UnsignedInt(hContext));
      inParms.setNewAuth(newAuth.getEncoded().asByteArray());
      inParms.setOwnerAuth(ConvertDataTypesClient.convertTcsAuth(inAuth1));
      inParms.setProtocolID(new UnsignedInt(protocolID));

      ChangeAuthOwnerOutParms outParms = stub_.changeAuthOwner(inParms);

      Object[] retval = new Object[2];
      retval[0] = outParms.getResult().longValue();
      retval[1] = ConvertDataTypesClient.convertTcsAuth(outParms.getOwnerAuth());

      return retval;
    } catch (RemoteException e) {
      ConvertRemoteExceptions.convertTcTcsException(e);
      ConvertRemoteExceptions.convertTcTddlException(e);
      ConvertRemoteExceptions.convertTcTpmException(e);
      return null;
    }
  }

  public Object[] TcsipOIAP(long hContext) throws TcTddlException, TcTpmException, TcTcsException {
    try {
      OIAPInParms inParms = new OIAPInParms();
      inParms.setHContext(new UnsignedInt(hContext));

      OIAPOutParms outParms = stub_.OIAP(inParms);

      Object[] retval = new Object[3];
      retval[0] = outParms.getResult().longValue();
      retval[1] = outParms.getAuthHandle().longValue();
      retval[2] = outParms.getNonce0() == null ? null : new TcTpmNonce(TcBlobData.newByteArray(outParms.getNonce0()));

      return retval;
    } catch (RemoteException e) {
      ConvertRemoteExceptions.convertTcTcsException(e);
      ConvertRemoteExceptions.convertTcTddlException(e);
      ConvertRemoteExceptions.convertTcTpmException(e);
      return null;
    }
  }

  public Object[] TcsipOSAP(long hContext, int entityType, long entityValue, TcTpmNonce nonceOddOSAP) throws TcTddlException, TcTpmException, TcTcsException {
    try {
      OSAPInParms inParms = new OSAPInParms();
      inParms.setEntityType(new UnsignedInt(entityType));
      inParms.setEntityValue(new UnsignedInt(entityValue));
      inParms.setHContext(new UnsignedInt(hContext));
      inParms.setNonceOddOSAP(nonceOddOSAP.getEncoded().asByteArray());

      OSAPOutParms outParms = stub_.OSAP(inParms);

      Object[] retval = new Object[4];
      retval[0] = outParms.getResult().longValue();
      retval[1] = outParms.getAuthHandle().longValue();
      retval[2] = outParms.getNonceEven() == null ? null : new TcTpmNonce(TcBlobData.newByteArray(outParms.getNonceEven()));
      retval[3] = outParms.getNonceEvenOSAP() == null ? null : new TcTpmNonce(TcBlobData.newByteArray(outParms.getNonceEvenOSAP()));

      return retval;
    } catch (RemoteException e) {
      ConvertRemoteExceptions.convertTcTcsException(e);
      ConvertRemoteExceptions.convertTcTddlException(e);
      ConvertRemoteExceptions.convertTcTpmException(e);
      return null;
    }
  }

  public Object[] TcsipDSAP(long hContext, int entityType, long keyHandle, TcTpmNonce nonceOddDSAP, TcBlobData entityValue) throws TcTddlException, TcTpmException, TcTcsException {
    try {
      DSAPInParms inParms = new DSAPInParms();
      inParms.setEntityType(new UnsignedShort(entityType));
      inParms.setEntityValue(entityValue.asByteArray());
      inParms.setHContext(new UnsignedInt(hContext));
      inParms.setKeyHandle(new UnsignedInt(keyHandle));
      inParms.setNonceOddDSAP(nonceOddDSAP.getEncoded().asByteArray());

      DSAPOutParms outParms = stub_.DSAP(inParms);

      Object[] retval = new Object[4];

      retval[0] = outParms.getResult().longValue();
      retval[1] = outParms.getAuthHandle().longValue();
      retval[2] = outParms.getNonceEven() == null ? null : new TcTpmNonce(TcBlobData.newByteArray(outParms.getNonceEven()));
      retval[3] = outParms.getNonceEvenDSAP() == null ? null : new TcTpmNonce(TcBlobData.newByteArray(outParms.getNonceEvenDSAP()));

      return retval;
    } catch (RemoteException e) {
      ConvertRemoteExceptions.convertTcTcsException(e);
      ConvertRemoteExceptions.convertTcTddlException(e);
      ConvertRemoteExceptions.convertTcTpmException(e);
      return null;
    }
  }

  public Object[] TcsipTickStampBlob(long hContext, long keyHandle, TcTpmNonce antiReplay, TcTpmDigest digestToStamp, TcTcsAuth inAuth1) throws TcTddlException, TcTpmException, TcTcsException {
    try {
      TickStampBlobInParms inParms = new TickStampBlobInParms();
      inParms.setAntiReplay(antiReplay.getEncoded().asByteArray());
      inParms.setDigestToStamp(digestToStamp.getEncoded().asByteArray());
      inParms.setHContext(new UnsignedInt(hContext));
      inParms.setHKey(new UnsignedInt(keyHandle));
      inParms.setPrivAuth(ConvertDataTypesClient.convertTcsAuth(inAuth1));

      TickStampBlobOutParms outParms = stub_.tickStampBlob(inParms);

      Object[] retval = new Object[4];
      retval[0] = outParms.getResult().longValue();
      retval[1] = ConvertDataTypesClient.convertTcsAuth(outParms.getPrivAuth());
      retval[2] = new TcTpmCurrentTicks(TcBlobData.newByteArray(outParms.getPrgbTickCount()));
      retval[3] = TcBlobData.newByteArray(outParms.getPrgbSignature());

      return retval;
    } catch (RemoteException e) {
      ConvertRemoteExceptions.convertTcTcsException(e);
      ConvertRemoteExceptions.convertTcTddlException(e);
      ConvertRemoteExceptions.convertTcTpmException(e);
      return null;
    }
  }

  public Object[] TcsEstablishTransport(long hContext, long encHandle, TcTpmTransportPublic transPublic, TcBlobData secret, TcTcsAuth inAuth1) throws TcTddlException, TcTpmException, TcTcsException {
    try {
      EstablishTransportInParms inParms = new EstablishTransportInParms();
      inParms.setHContext(new UnsignedInt(hContext));
      inParms.setHEncKey(new UnsignedInt(encHandle));
      inParms.setPEncKeyAuth(ConvertDataTypesClient.convertTcsAuth(inAuth1));
      inParms.setRgbSecret(secret.asByteArray());
      inParms.setRgbTransSessionInfo(transPublic.getEncoded().asByteArray());
      // inParms.setUlTransControlFlags();

      EstablishTransportOutParms outParms = stub_.establishTransport(inParms);

      Object[] retval = new Object[6];
      retval[0] = outParms.getResult().longValue();
      retval[1] = ConvertDataTypesClient.convertTcsAuth(outParms.getPEncKeyAuth());
      retval[2] = outParms.getHTransSession().longValue();
      retval[3] = outParms.getPbLocality().longValue();
      retval[4] = new TcTpmCurrentTicks(TcBlobData.newByteArray(outParms.getPrgbCurrentTicks()));
      retval[5] = new TcTpmNonce(TcBlobData.newByteArray(outParms.getPTransNonce()));

      return retval;
    } catch (RemoteException e) {
      ConvertRemoteExceptions.convertTcTcsException(e);
      ConvertRemoteExceptions.convertTcTddlException(e);
      ConvertRemoteExceptions.convertTcTpmException(e);
      return null;
    }
  }

  public Object[] TcsExecuteTransport(long hContext, TcBlobData wrappedCmd, long transHandle, TcTcsAuth inAuth1) throws TcTddlException, TcTpmException, TcTcsException {
    try {
      ExecuteTransportInParms inParms = new ExecuteTransportInParms();
      inParms.setHContext(new UnsignedInt(hContext));
      inParms.setPTransAuth(ConvertDataTypesClient.convertTcsAuth(inAuth1));
      // inParms.setPWrappedCmdAuth1();
      // inParms.setPWrappedCmdAuth2();
      inParms.setRgbWrappedCmdParamIn(wrappedCmd.asByteArray());
      // inParms.setRghHandles();
      inParms.setUnWrappedCommandOrdinal(new UnsignedInt(transHandle));

      ExecuteTransportOutParms outParms = stub_.executeTransport(inParms);

      Object[] retval = new Object[5];
      retval[0] = outParms.getResult().longValue();
      retval[1] = ConvertDataTypesClient.convertTcsAuth(outParms.getPTransAuth());
      retval[2] = outParms.getPunCurrentTicks().longValue();
      retval[3] = outParms.getPbLocality().longValue();
      retval[4] = TcBlobData.newByteArray(outParms.getRgbWrappedCmdParamOut());

      return retval;
    } catch (RemoteException e) {
      ConvertRemoteExceptions.convertTcTcsException(e);
      ConvertRemoteExceptions.convertTcTddlException(e);
      ConvertRemoteExceptions.convertTcTpmException(e);
      return null;
    }
  }

  public Object[] TcsReleaseTransportSigned(long hContext, long keyHandle, TcTpmNonce antiReplay, long transHandle, TcTcsAuth inAuth1, TcTcsAuth inAuth2) throws TcTddlException, TcTpmException, TcTcsException {
    try {
      ReleaseTransportSignedInParms inParms = new ReleaseTransportSignedInParms();
      inParms.setAntiReplayNonce(antiReplay.getEncoded().asByteArray());
      inParms.setHContext(new UnsignedInt(hContext));
      inParms.setHSignatureKey(new UnsignedInt(keyHandle));
      inParms.setPKeyAuth(ConvertDataTypesClient.convertTcsAuth(inAuth1));
      inParms.setPTransAuth(ConvertDataTypesClient.convertTcsAuth(inAuth2));
      //FIXME: long transHandle - where is it?

      ReleaseTransportSignedOutParms outParms = stub_.releaseTransportSigned(inParms);

      Object[] retval = new Object[6];
      retval[0] = outParms.getResult().longValue();
      retval[1] = ConvertDataTypesClient.convertTcsAuth(outParms.getPTransAuth());
      retval[2] = ConvertDataTypesClient.convertTcsAuth(outParms.getPKeyAuth());
      retval[3] = outParms.getPbLocality().longValue();
      retval[4] = new TcTpmCurrentTicks(TcBlobData.newByteArray(outParms.getPrgbCurrentTicks()));
      retval[5] = TcBlobData.newByteArray(outParms.getPrgbSignature());

      return retval;
    } catch (RemoteException e) {
      ConvertRemoteExceptions.convertTcTcsException(e);
      ConvertRemoteExceptions.convertTcTddlException(e);
      ConvertRemoteExceptions.convertTcTpmException(e);
      return null;
    }
  }

  public Object[] TcsipCreateCounter(long hContext, TcBlobData label, TcTpmEncauth encAuth, TcTcsAuth inAuth1) throws TcTddlException, TcTpmException, TcTcsException {
    try {
      CreateCounterInParms inParms = new CreateCounterInParms();
      inParms.setCounterAuth(encAuth.getEncoded().asByteArray());
      inParms.setHContext(new UnsignedInt(hContext));
      inParms.setPLabel(label.asByteArray());
      inParms.setPOwnerAuth(ConvertDataTypesClient.convertTcsAuth(inAuth1));

      CreateCounterOutParms outParms = stub_.createCounter(inParms);

      Object[] retval = new Object[4];
      retval[0] = outParms.getResult().longValue();
      retval[1] = ConvertDataTypesClient.convertTcsAuth(outParms.getPOwnerAuth());
      retval[2] = outParms.getIdCounter().longValue();
      retval[3] = ConvertDataTypesClient.convertTpmCounterValue(outParms.getCounterValue());

      return retval;
    } catch (RemoteException e) {
      ConvertRemoteExceptions.convertTcTcsException(e);
      ConvertRemoteExceptions.convertTcTddlException(e);
      ConvertRemoteExceptions.convertTcTpmException(e);
      return null;
    }
  }

  public Object[] TcsipIncrementCounter(long hContext, long countID, TcTcsAuth inAuth1) throws TcTddlException, TcTpmException, TcTcsException {
    try {
      IncrementCounterInParms inParms = new IncrementCounterInParms();
      inParms.setHContext(new UnsignedInt(hContext));
      inParms.setIdCounter(new UnsignedInt(countID));
      inParms.setPCounterAuth(ConvertDataTypesClient.convertTcsAuth(inAuth1));

      IncrementCounterOutParms outParms = stub_.incrementCounter(inParms);

      Object[] retval = new Object[3];
      retval[0] = outParms.getResult().longValue();
      retval[1] = ConvertDataTypesClient.convertTcsAuth(outParms.getPCounterAuth());
      retval[2] = ConvertDataTypesClient.convertTpmCounterValue(outParms.getCounterValue());

      return retval;
    } catch (RemoteException e) {
      ConvertRemoteExceptions.convertTcTcsException(e);
      ConvertRemoteExceptions.convertTcTddlException(e);
      ConvertRemoteExceptions.convertTcTpmException(e);
      return null;
    }
  }

  public Object[] TcsipReadCounter(long hContext, long countID) throws TcTddlException, TcTpmException, TcTcsException {
    try {
      ReadCounterInParms inParms = new ReadCounterInParms();
      inParms.setHContext(new UnsignedInt(hContext));
      inParms.setIdCounter(new UnsignedInt(countID));

      ReadCounterOutParms outParms = stub_.readCounter(inParms);

      Object[] retval = new Object[2];
      retval[0] = outParms.getResult().longValue();
      retval[1] = ConvertDataTypesClient.convertTpmCounterValue(outParms.getCounterValue());

      return retval;
    } catch (RemoteException e) {
      ConvertRemoteExceptions.convertTcTcsException(e);
      ConvertRemoteExceptions.convertTcTddlException(e);
      ConvertRemoteExceptions.convertTcTpmException(e);
      return null;
    }
  }

  public Object[] TcsipReleaseCounter(long hContext, long countID, TcTcsAuth inAuth1) throws TcTddlException, TcTpmException, TcTcsException {
    try {
      ReleaseCounterInParms inParms = new ReleaseCounterInParms();
      inParms.setHContext(new UnsignedInt(hContext));
      inParms.setIdCounter(new UnsignedInt(countID));
      inParms.setPCounterAuth(ConvertDataTypesClient.convertTcsAuth(inAuth1));

      ReleaseCounterOutParms outParms = stub_.releaseCounter(inParms);

      Object[] retval = new Object[2];
      retval[0] = outParms.getResult().longValue();
      retval[1] = ConvertDataTypesClient.convertTcsAuth(outParms.getPCounterAuth());

      return retval;
    } catch (RemoteException e) {
      ConvertRemoteExceptions.convertTcTcsException(e);
      ConvertRemoteExceptions.convertTcTddlException(e);
      ConvertRemoteExceptions.convertTcTpmException(e);
      return null;
    }
  }

  public Object[] TcsipReleaseCounterOwner(long hContext, long countID, TcTcsAuth inAuth1) throws TcTddlException, TcTpmException, TcTcsException {
    try {
      ReleaseCounterOwnerInParms inParms = new ReleaseCounterOwnerInParms();
      inParms.setHContext(new UnsignedInt(hContext));
      inParms.setIdCounter(new UnsignedInt(countID));
      inParms.setPOwnerAuth(ConvertDataTypesClient.convertTcsAuth(inAuth1));

      ReleaseCounterOwnerOutParms outParms = stub_.releaseCounterOwner(inParms);

      Object[] retval = new Object[2];
      retval[0] = outParms.getResult().longValue();
      retval[1] = ConvertDataTypesClient.convertTcsAuth(outParms.getPOwnerAuth());

      return retval;
    } catch (RemoteException e) {
      ConvertRemoteExceptions.convertTcTcsException(e);
      ConvertRemoteExceptions.convertTcTddlException(e);
      ConvertRemoteExceptions.convertTcTpmException(e);
      return null;
    }
  }

  public Object[] TcsipDirWriteAuth(long hContext, long dirIndex, TcTpmDigest newContents, TcTcsAuth inAuth1) throws TcTddlException, TcTpmException, TcTcsException {
    try {
      DirWriteAuthInParms inParms = new DirWriteAuthInParms();
      inParms.setDirIndex(new UnsignedInt(dirIndex));
      inParms.setHContext(new UnsignedInt(hContext));
      inParms.setNewContents(newContents.getEncoded().asByteArray());
      inParms.setOwnerAuth(ConvertDataTypesClient.convertTcsAuth(inAuth1));

      DirWriteAuthOutParms outParms = stub_.dirWriteAuth(inParms);

      Object[] retval = new Object[2];
      retval[0] = outParms.getResult().longValue();
      retval[1] = ConvertDataTypesClient.convertTcsAuth(outParms.getOwnerAuth());

      return retval;
    } catch (RemoteException e) {
      ConvertRemoteExceptions.convertTcTcsException(e);
      ConvertRemoteExceptions.convertTcTddlException(e);
      ConvertRemoteExceptions.convertTcTpmException(e);
      return null;
    }
  }

  public Object[] TcsipDirRead(long hContext, long dirIndex) throws TcTddlException, TcTpmException, TcTcsException {
    try {
      DirReadInParms inParms = new DirReadInParms();
      inParms.setDirIndex(new UnsignedInt(dirIndex));
      inParms.setHContext(new UnsignedInt(hContext));

      DirReadOutParms outParms = stub_.dirRead(inParms);

      Object[] retval = new Object[2];
      retval[0] = outParms.getResult().longValue();
      retval[1] = outParms.getDirValue() == null ? null : new TcTpmDigest(TcBlobData.newByteArray(outParms.getDirValue()));

      return retval;
    } catch (RemoteException e) {
      ConvertRemoteExceptions.convertTcTcsException(e);
      ConvertRemoteExceptions.convertTcTddlException(e);
      ConvertRemoteExceptions.convertTcTpmException(e);
      return null;
    }
  }

  public Object[] TcsipChangeAuthAsymStart(long hContext, long idHandle, TcTpmNonce antiReplay, TcTpmKeyParms tempKey, TcTcsAuth inAuth1) throws TcTddlException, TcTpmException, TcTcsException {
    try {
      ChangeAuthAsymStartInParms inParms = new ChangeAuthAsymStartInParms();
      inParms.setAntiReplay(antiReplay.getEncoded().asByteArray());
      inParms.setHContext(new UnsignedInt(hContext));
      inParms.setIdHandle(new UnsignedInt(idHandle));
      inParms.setPAuth(ConvertDataTypesClient.convertTcsAuth(inAuth1));
      inParms.setTempKeyInfoData(tempKey.getEncoded().asByteArray());

      ChangeAuthAsymStartOutParms outParms = stub_.changeAuthAsymStart(inParms);

      Object[] retval = new Object[6];
      retval[0] = outParms.getResult().longValue();
      retval[1] = ConvertDataTypesClient.convertTcsAuth(outParms.getPAuth());
      retval[2] = outParms.getCertifyInfo() == null ? null : new TcTpmCertifyInfo(TcBlobData.newByteArray(outParms.getCertifyInfo()));
      retval[3] = TcBlobData.newByteArray(outParms.getSig());
      retval[4] = outParms.getEphHandle().longValue();
      retval[5] = outParms.getTempKeyData() == null ? null : new TcTpmKey(TcBlobData.newByteArray(outParms.getTempKeyData()));

      return retval;
    } catch (RemoteException e) {
      ConvertRemoteExceptions.convertTcTcsException(e);
      ConvertRemoteExceptions.convertTcTddlException(e);
      ConvertRemoteExceptions.convertTcTpmException(e);
      return null;
    }
  }

  public Object[] TcsipOwnerReadPubek(long hContext, TcTcsAuth inAuth1) throws TcTddlException, TcTpmException, TcTcsException {
    try {
      OwnerReadPubekInParms inParms = new OwnerReadPubekInParms();
      inParms.setHContext(new UnsignedInt(hContext));
      inParms.setOwnerAuth(ConvertDataTypesClient.convertTcsAuth(inAuth1));

      OwnerReadPubekOutParms outParms = stub_.ownerReadPubek(inParms);

      Object[] retval = new Object[3];
      retval[0] = outParms.getResult().longValue();
      retval[1] = ConvertDataTypesClient.convertTcsAuth(outParms.getOwnerAuth());
      retval[2] = new TcTpmPubkey(TcBlobData.newByteArray(outParms.getPubEndorsementKey()));

      return retval;
    } catch (RemoteException e) {
      ConvertRemoteExceptions.convertTcTcsException(e);
      ConvertRemoteExceptions.convertTcTddlException(e);
      ConvertRemoteExceptions.convertTcTpmException(e);
      return null;
    }
  }

  public Object[] TcsipDisablePubekRead(long hContext, TcTcsAuth inAuth1) throws TcTddlException, TcTpmException, TcTcsException {
    try {
      DisablePubekReadInParms inParms = new DisablePubekReadInParms();
      inParms.setHContext(new UnsignedInt(hContext));
      inParms.setOwnerAuth(ConvertDataTypesClient.convertTcsAuth(inAuth1));

      DisablePubekReadOutParms outParms = stub_.disablePubekRead(inParms);

      Object[] retval = new Object[2];
      retval[0] = outParms.getResult().longValue();
      retval[1] = ConvertDataTypesClient.convertTcsAuth(outParms.getOwnerAuth());

      return retval;
    } catch (RemoteException e) {
      ConvertRemoteExceptions.convertTcTcsException(e);
      ConvertRemoteExceptions.convertTcTddlException(e);
      ConvertRemoteExceptions.convertTcTpmException(e);
      return null;
    }
  }

  public Object[] TcsipCmkCreateKey(long hContext, long parentHandle, TcTpmEncauth dataUsageAuth,
    TcTpmDigest migrationAuthorityApproval, TcTpmDigest migrationAuthorityDigest, TcTpmKey12 keyInfo, TcTcsAuth inAuth1)
    throws TcTddlException, TcTpmException, TcTcsException {
    try {
      CMK_CreateKeyInParms inParms = new CMK_CreateKeyInParms();
      inParms.setHContext(new UnsignedInt(hContext));
      inParms.setHWrappingKey(new UnsignedInt(parentHandle));
      inParms.setKeyUsageAuth(dataUsageAuth.getEncoded().asByteArray());
      inParms.setMigAuthApproval(migrationAuthorityApproval.getEncoded().asByteArray());
      inParms.setMigAuthorityDigest(migrationAuthorityDigest.getEncoded().asByteArray());
      inParms.setPAuth(ConvertDataTypesClient.convertTcsAuth(inAuth1));
      inParms.setPrgbKeyData(keyInfo.getEncoded().asByteArray());

      CMK_CreateKeyOutParms outParms = stub_.CMK_CreateKey(inParms);

      Object[] retval = new Object[3];
      retval[0] = outParms.getResult().longValue();
      retval[1] = ConvertDataTypesClient.convertTcsAuth(outParms.getPAuth());
      retval[3] = outParms.getPrgbKeyData() == null ? null : TcBlobData.newByteArray(outParms.getPrgbKeyData());

      return retval;
    } catch (RemoteException e) {
      ConvertRemoteExceptions.convertTcTcsException(e);
      ConvertRemoteExceptions.convertTcTddlException(e);
      ConvertRemoteExceptions.convertTcTpmException(e);
      return null;
    }
  }

  public Object[] TcsipCmkCreateTicket(long hContext, TcTpmPubkey verificationKey, TcTpmDigest signedData, TcBlobData signatureValue, TcTcsAuth inAuth1)
    throws TcTddlException, TcTpmException, TcTcsException {
    try {
      CMK_CreateTicketInParms inParms = new CMK_CreateTicketInParms();
      inParms.setHContext(new UnsignedInt(hContext));
      inParms.setPublicVerifyKey(verificationKey.getEncoded().asByteArray());
      inParms.setSignedData(signedData.getEncoded().asByteArray());
      inParms.setSigValue(signatureValue.asByteArray());
      inParms.setPOwnerAuth(ConvertDataTypesClient.convertTcsAuth(inAuth1));

      CMK_CreateTicketOutParms outParms = stub_.CMK_CreateTicket(inParms);

      Object[] retval = new Object[3];
      retval[0] = outParms.getResult().longValue();
      retval[1] = ConvertDataTypesClient.convertTcsAuth(outParms.getPOwnerAuth());
      retval[2] = outParms.getSigTicket() == null ? null : new TcTpmDigest(TcBlobData.newByteArray(outParms.getSigTicket()));

      return retval;
    } catch (RemoteException e) {
      ConvertRemoteExceptions.convertTcTcsException(e);
      ConvertRemoteExceptions.convertTcTddlException(e);
      ConvertRemoteExceptions.convertTcTpmException(e);
      return null;
    }
  }

  public Object[] TcsipCmkCreateBlob(long hContext, long parentHandle, int migrationType,
    TcTpmMigrationkeyAuth migrationKeyAuth, TcTpmDigest pubSourceKeyDigest,
    TcTpmMsaComposite msaList, TcBlobData restrictTicket, TcBlobData sigTicket,
    TcBlobData encData, TcTcsAuth inAuth1)
    throws TcTddlException, TcTpmException, TcTcsException {
    try {
      CMK_CreateBlobInParms inParms = new CMK_CreateBlobInParms();
      inParms.setHContext(new UnsignedInt(hContext));
      inParms.setParentHandle(new UnsignedInt(parentHandle));
      inParms.setMigrationType(new UnsignedInt(migrationType));
      inParms.setMigrationKeyAuth(migrationKeyAuth.getEncoded().asByteArray());
      inParms.setPubSourceKeyDigest(pubSourceKeyDigest.getEncoded().asByteArray());
      inParms.setMsaList(msaList.getEncoded().asByteArray());
      inParms.setRestrictTicket(restrictTicket.asByteArray());
      inParms.setSigTicket(sigTicket.asByteArray());
      inParms.setEncData(encData.asByteArray());
      inParms.setParentAuth(ConvertDataTypesClient.convertTcsAuth(inAuth1));

      CMK_CreateBlobOutParms outParms = stub_.CMK_CreateBlob(inParms);

      Object[] retval = new Object[4];
      retval[0] = outParms.getResult().longValue();
      retval[1] = ConvertDataTypesClient.convertTcsAuth(outParms.getParentAuth());
      retval[2] = TcBlobData.newByteArray(outParms.getRandom());
      retval[3] = outParms.getOutData() == null ? null : TcBlobData.newByteArray(outParms.getOutData());

      return retval;
    } catch (RemoteException e) {
      ConvertRemoteExceptions.convertTcTcsException(e);
      ConvertRemoteExceptions.convertTcTddlException(e);
      ConvertRemoteExceptions.convertTcTpmException(e);
      return null;
    }
  }

  public Object[] TcsipCmkConvertMigration(long hContext, long parentHandle, TcTpmCmkAuth restrictTicket,
    TcTpmDigest sigTicket, TcTpmKey12 migratedKey,
    TcTpmMsaComposite msaList, TcBlobData random, TcTcsAuth inAuth1)
    throws TcTddlException, TcTpmException, TcTcsException {
    try {
      CMK_ConvertMigrationInParms inParms = new CMK_ConvertMigrationInParms();

      inParms.setHContext(new UnsignedInt(hContext));
      inParms.setParentHandle(new UnsignedInt(parentHandle));
      inParms.setRestrictTicket(ConvertDataTypesClient.convertTpmCmkAuth(restrictTicket));
      inParms.setSigTicket(sigTicket.getEncoded().asByteArray());
      inParms.setPrgbKeyData(migratedKey.getEncoded().asByteArray());
      inParms.setMsaList(msaList.getEncoded().asByteArray());
      inParms.setRandom(random.asByteArray());
      inParms.setParentAuth(ConvertDataTypesClient.convertTcsAuth(inAuth1));

      CMK_ConvertMigrationOutParms outParms = stub_.CMK_ConvertMigration(inParms);

      //{ outBlob.getRetCodeAsLong(), outAuth1, outData };
      Object[] retval = new Object[3];

      retval[0] = outParms.getResult().longValue();
      retval[1] = ConvertDataTypesClient.convertTcsAuth(outParms.getParentAuth());
      retval[2] = outParms.getOutData() == null ? null : TcBlobData.newByteArray(outParms.getOutData());

      return retval;
    } catch (RemoteException e) {
      ConvertRemoteExceptions.convertTcTcsException(e);
      ConvertRemoteExceptions.convertTcTddlException(e);
      ConvertRemoteExceptions.convertTcTpmException(e);
      return null;
    }
  }

  public Object[] TcsipDaaJoin(long hContext, long handle, short stage, TcBlobData inputData0, TcBlobData inputData1, TcTcsAuth inAuth1)
    throws TcTddlException, TcTpmException, TcTcsException {
    try {
      TPM_DAA_JoinInParms inParms = new TPM_DAA_JoinInParms();

      inParms.setHContext(new UnsignedInt(hContext));
      inParms.setHandle(new UnsignedInt(handle));
      inParms.setInputData0(inputData0.asByteArray());
      inParms.setInputData1(inputData1.asByteArray());
      inParms.setOwnerAuth(ConvertDataTypesClient.convertTcsAuth(inAuth1));
      inParms.setStage((byte) stage);

      TPM_DAA_JoinOutParms outParms = stub_.TPM_DAA_Join(inParms);

      Object[] retval = new Object[3];
      retval[0] = outParms.getResult().longValue();
      retval[1] = ConvertDataTypesClient.convertTcsAuth(outParms.getOwnerAuth());
      retval[2] = outParms.getOutputData() == null ? null : TcBlobData.newByteArray(outParms.getOutputData());

      return retval;
    } catch (RemoteException e) {
      ConvertRemoteExceptions.convertTcTcsException(e);
      ConvertRemoteExceptions.convertTcTddlException(e);
      ConvertRemoteExceptions.convertTcTpmException(e);
      return null;
    }
  }

  public Object[] TcsipDaaSign(long hContext, long handle, short stage, TcBlobData inputData0, TcBlobData inputData1, TcTcsAuth inAuth1)
    throws TcTddlException, TcTpmException, TcTcsException {
    try {
      TPM_DAA_SignInParms inParms = new TPM_DAA_SignInParms();

      inParms.setHContext(new UnsignedInt(hContext));
      inParms.setHandle(new UnsignedInt(handle));
      inParms.setInputData0(inputData0.asByteArray());
      inParms.setInputData1(inputData1.asByteArray());
      inParms.setOwnerAuth(ConvertDataTypesClient.convertTcsAuth(inAuth1));
      inParms.setStage((byte) stage);

      TPM_DAA_SignOutParms outParms = stub_.TPM_DAA_Sign(inParms);

      Object[] retval = new Object[3];
      retval[0] = outParms.getResult().longValue();
      retval[1] = ConvertDataTypesClient.convertTcsAuth(outParms.getOwnerAuth());
      retval[2] = outParms.getOutputData() == null ? null : TcBlobData.newByteArray(outParms.getOutputData());

      return retval;
    } catch (RemoteException e) {
      ConvertRemoteExceptions.convertTcTcsException(e);
      ConvertRemoteExceptions.convertTcTddlException(e);
      ConvertRemoteExceptions.convertTcTpmException(e);
      return null;
    }
  }

  public Object[] TcsipDelegateLoadOwnerDelegation(long hContext, long index, TcTpmDelegateOwnerBlob blob, TcTcsAuth inAuth1)
    throws TcTddlException, TcTpmException, TcTcsException {
    try {
      Delegate_LoadOwnerDelegationInParms inParms = new Delegate_LoadOwnerDelegationInParms();
      inParms.setHContext(new UnsignedInt(hContext));
      inParms.setIndex(new UnsignedInt(index));
      inParms.setBlob(blob.getEncoded().asByteArray());
      inParms.setOwnerAuth(ConvertDataTypesClient.convertTcsAuth(inAuth1));

      Delegate_LoadOwnerDelegationOutParms outParms = stub_.delegate_LoadOwnerDelegation(inParms);

      Object[] retval = new Object[2];
      retval[0] = outParms.getResult().longValue();
      retval[1] = ConvertDataTypesClient.convertTcsAuth(outParms.getOwnerAuth());

      return retval;
    } catch (RemoteException e) {
      ConvertRemoteExceptions.convertTcTcsException(e);
      ConvertRemoteExceptions.convertTcTddlException(e);
      ConvertRemoteExceptions.convertTcTpmException(e);
      return null;
    }
  }

  public Object[] TcsipNvDefineOrReleaseSpace(long hContext, TcTpmNvDataPublic pubInfo, TcTpmEncauth encAuth, TcTcsAuth inAuth1)
    throws TcTddlException, TcTpmException, TcTcsException {
    try {
      NV_DefineOrReleaseSpaceInParms inParms = new NV_DefineOrReleaseSpaceInParms();
      inParms.setHContext(new UnsignedInt(hContext));
      inParms.setPPubInfo(pubInfo.getEncoded().asByteArray());
      inParms.setEncAuth(encAuth.getEncoded().asByteArray());
      inParms.setPAuth(ConvertDataTypesClient.convertTcsAuth(inAuth1));

      NV_DefineOrReleaseSpaceOutParms outParms = stub_.NV_DefineOrReleaseSpace(inParms);

      Object[] retval = new Object[2];
      retval[0] = outParms.getResult().longValue();
      retval[1] = ConvertDataTypesClient.convertTcsAuth(outParms.getPAuth());

      return retval;
    } catch (RemoteException e) {
      ConvertRemoteExceptions.convertTcTcsException(e);
      ConvertRemoteExceptions.convertTcTddlException(e);
      ConvertRemoteExceptions.convertTcTpmException(e);
      return null;
    }
  }

  public Object[] TcsipNvWriteValue(long hContext, long nvIndex, long offset, TcBlobData data, TcTcsAuth inAuth1)
    throws TcTddlException, TcTpmException, TcTcsException {
    try {
      NV_WriteValueInParms inParms = new NV_WriteValueInParms();

      inParms.setHContext(new UnsignedInt(hContext));
      inParms.setHNVStore(new UnsignedInt(nvIndex));
      inParms.setOffset(new UnsignedInt(offset));
      inParms.setRgbDataToWrite(data.asByteArray());
      inParms.setPrivAuth(ConvertDataTypesClient.convertTcsAuth(inAuth1));

      NV_WriteValueOutParms outParms = stub_.NV_WriteValue(inParms);

      Object[] retval = new Object[2];
      retval[0] = outParms.getResult().longValue();
      retval[1] = ConvertDataTypesClient.convertTcsAuth(outParms.getPrivAuth());

      return retval;
    } catch (RemoteException e) {
      ConvertRemoteExceptions.convertTcTcsException(e);
      ConvertRemoteExceptions.convertTcTddlException(e);
      ConvertRemoteExceptions.convertTcTpmException(e);
      return null;
    }
  }

  public Object[] TcsipNvWriteValueAuth(long hContext, long nvIndex, long offset, TcBlobData data, TcTcsAuth inAuth1)
    throws TcTddlException, TcTpmException, TcTcsException {
    try {
      NV_WriteValueAuthInParms inParms = new NV_WriteValueAuthInParms();
      inParms.setHContext(new UnsignedInt(hContext));
      inParms.setHNVStore(new UnsignedInt(nvIndex));
      inParms.setOffset(new UnsignedInt(offset));
      inParms.setRgbDataToWrite(data.asByteArray());
      inParms.setNVAuth(ConvertDataTypesClient.convertTcsAuth(inAuth1));

      NV_WriteValueAuthOutParms outParms = stub_.NV_WriteValueAuth(inParms);

      Object[] retval = new Object[2];
      retval[0] = outParms.getResult().longValue();
      retval[1] = ConvertDataTypesClient.convertTcsAuth(outParms.getNVAuth());

      return retval;
    } catch (RemoteException e) {
      ConvertRemoteExceptions.convertTcTcsException(e);
      ConvertRemoteExceptions.convertTcTddlException(e);
      ConvertRemoteExceptions.convertTcTpmException(e);
      return null;
    }
  }

  public Object[] TcsipNvReadValue(long hContext, long nvIndex, long offset, long dataSz, TcTcsAuth inAuth1)
    throws TcTddlException, TcTpmException, TcTcsException {
    try {
      NV_ReadValueInParms inParms = new NV_ReadValueInParms();
      inParms.setHContext(new UnsignedInt(hContext));
      inParms.setHNVStore(new UnsignedInt(nvIndex));
      inParms.setOffset(new UnsignedInt(offset));
      inParms.setPulDataLength(new UnsignedInt(dataSz));
      inParms.setPrivAuth(inAuth1 == null ? null : ConvertDataTypesClient.convertTcsAuth(inAuth1));

      NV_ReadValueOutParms outParms = stub_.NV_ReadValue(inParms);

      Object[] retval = new Object[3];
      retval[0] = outParms.getResult().longValue();
      retval[1] = outParms.getPrivAuth() == null ? null :ConvertDataTypesClient.convertTcsAuth(outParms.getPrivAuth());
      retval[2] = outParms.getRgbDataRead() == null ? null : TcBlobData.newByteArray(outParms.getRgbDataRead());

      return retval;
    } catch (RemoteException e) {
      ConvertRemoteExceptions.convertTcTcsException(e);
      ConvertRemoteExceptions.convertTcTddlException(e);
      ConvertRemoteExceptions.convertTcTpmException(e);
      return null;
    }
  }

  public Object[] TcsipNvReadValueAuth(long hContext, long nvIndex, long offset, long dataSz, TcTcsAuth inAuth1)
    throws TcTddlException, TcTpmException, TcTcsException {
    try {
      NV_ReadValueAuthInParms inParms = new NV_ReadValueAuthInParms();
      inParms.setHContext(new UnsignedInt(hContext));
      inParms.setHNVStore(new UnsignedInt(nvIndex));
      inParms.setOffset(new UnsignedInt(offset));
      inParms.setPulDataLength(new UnsignedInt(dataSz));
      inParms.setNVAuth(ConvertDataTypesClient.convertTcsAuth(inAuth1));

      NV_ReadValueAuthOutParms outParms = stub_.NV_ReadValueAuth(inParms);

      Object[] retval = new Object[3];
      retval[0] = outParms.getResult().longValue();
      retval[1] = ConvertDataTypesClient.convertTcsAuth(outParms.getNVAuth());
      retval[2] = outParms.getRgbDataRead() == null ? null : TcBlobData.newByteArray(outParms.getRgbDataRead());

      return retval;
    } catch (RemoteException e) {
      ConvertRemoteExceptions.convertTcTcsException(e);
      ConvertRemoteExceptions.convertTcTddlException(e);
      ConvertRemoteExceptions.convertTcTpmException(e);
      return null;
    }
  }

  public Object[] TcsSHA1Start(long hContext)
    throws TcTddlException, TcTpmException, TcTcsException {
    return null; //TODO - Not in WSDL
  }

  public Object[] TcsSHA1Update(long hContext, long numBytes, TcBlobData hashData)
    throws TcTddlException, TcTpmException, TcTcsException {
    return null; //TODO - Not in WSDL
  }

  public Object[] TcsSHA1Complete(long hContext, TcBlobData hashData)
    throws TcTddlException, TcTpmException, TcTcsException {
    return null; //TODO - Not in WSDL
  }

  public Object[] TcsSHA1CompleteExtend(long hContext, long pcrNum, TcBlobData hashData)
    throws TcTddlException, TcTpmException, TcTcsException {
    return null; //TODO - Not in WSDL
  }

  public Object[] TcsipDelegateManage(long hContext, long familyID, long opCode, TcBlobData opData, TcTcsAuth inAuth1)
    throws TcTddlException, TcTpmException, TcTcsException {
    try {
      Delegate_ManageInParms inParms = new Delegate_ManageInParms();
      inParms.setHContext(new UnsignedInt(hContext));
      inParms.setFamilyID(new UnsignedInt(familyID));
      inParms.setOpFlag(new UnsignedInt(opCode));
      inParms.setOpData(opData.asByteArray());
      inParms.setOwnerAuth(ConvertDataTypesClient.convertTcsAuth(inAuth1));

      Delegate_ManageOutParms outParms = stub_.delegate_Manage(inParms);

      Object[] retval = new Object[3];
      retval[0] = outParms.getResult().longValue();
      retval[1] = ConvertDataTypesClient.convertTcsAuth(outParms.getOwnerAuth());
      retval[2] = outParms.getRetData() == null ? null : TcBlobData.newByteArray(outParms.getRetData());

      return retval;
    } catch (RemoteException e) {
      ConvertRemoteExceptions.convertTcTcsException(e);
      ConvertRemoteExceptions.convertTcTddlException(e);
      ConvertRemoteExceptions.convertTcTpmException(e);
      return null;
    }
  }

  public Object[] TcsipDelegateCreateKeyDelegation(long hContext, long keyHandle, TcTpmDelegatePublic publicInfo, TcTpmEncauth delAuth, TcTcsAuth inAuth1)
    throws TcTddlException, TcTpmException, TcTcsException {
    try {
      Delegate_CreateKeyDelegationInParms inParms = new Delegate_CreateKeyDelegationInParms();
      inParms.setHContext(new UnsignedInt(hContext));
      inParms.setHKey(new UnsignedInt(keyHandle));
      inParms.setPublicInfo(publicInfo.getEncoded().asByteArray());
      inParms.setEncDelAuth(delAuth.getEncoded().asByteArray());
      inParms.setKeyAuth(ConvertDataTypesClient.convertTcsAuth(inAuth1));

      Delegate_CreateKeyDelegationOutParms outParms = stub_.delegate_CreateKeyDelegation(inParms);

      Object[] retval = new Object[3];
      retval[0] = outParms.getResult().longValue();
      retval[1] = ConvertDataTypesClient.convertTcsAuth(outParms.getKeyAuth());
      retval[2] = outParms.getBlob() == null ? null : TcBlobData.newByteArray(outParms.getBlob());

      return retval;
    } catch (RemoteException e) {
      ConvertRemoteExceptions.convertTcTcsException(e);
      ConvertRemoteExceptions.convertTcTddlException(e);
      ConvertRemoteExceptions.convertTcTpmException(e);
      return null;
    }
  }

  public Object[] TcsipDelegateCreateOwnerDelegation(long hContext, boolean increment, TcTpmDelegatePublic publicInfo, TcTpmEncauth delAuth, TcTcsAuth inAuth1)
    throws TcTddlException, TcTpmException, TcTcsException {
    try {
      Delegate_CreateOwnerDelegationInParms inParms = new Delegate_CreateOwnerDelegationInParms();
      inParms.setHContext(new UnsignedInt(hContext));
      inParms.setIncrement(increment ? (byte) 1 : (byte) 0);
      inParms.setPublicInfo(publicInfo.getEncoded().asByteArray());
      inParms.setEncDelAuth(delAuth.getEncoded().asByteArray());
      inParms.setOwnerAuth(ConvertDataTypesClient.convertTcsAuth(inAuth1));

      Delegate_CreateOwnerDelegationOutParms outParms = stub_.delegate_CreateOwnerDelegation(inParms);

      Object[] retval = new Object[3];
      retval[0] = outParms.getResult().longValue();
      retval[1] = ConvertDataTypesClient.convertTcsAuth(outParms.getOwnerAuth());
      retval[2] = outParms.getBlob() == null ? null : TcBlobData.newByteArray(outParms.getBlob());

      return retval;
    } catch (RemoteException e) {
      ConvertRemoteExceptions.convertTcTcsException(e);
      ConvertRemoteExceptions.convertTcTddlException(e);
      ConvertRemoteExceptions.convertTcTpmException(e);
      return null;
    }
  }

  public Object[] TcsipDelegateReadTable(long hContext)
    throws TcTddlException, TcTpmException, TcTcsException {
    try {
      Delegate_ReadTableInParms inParms = new Delegate_ReadTableInParms();
      inParms.setHContext(new UnsignedInt(hContext));

      Delegate_ReadTableOutParms outParms = stub_.delegate_ReadTable(inParms);

      Object[] retval = new Object[3];
      retval[0] = outParms.getResult().longValue();
      retval[1] = outParms.getPpFamilyTable() == null ? null : TcBlobData.newByteArray(outParms.getPpFamilyTable());
      retval[2] = outParms.getPpDelegateTable() == null ? null : TcBlobData.newByteArray(outParms.getPpDelegateTable());

      return retval;
    } catch (RemoteException e) {
      ConvertRemoteExceptions.convertTcTcsException(e);
      ConvertRemoteExceptions.convertTcTddlException(e);
      ConvertRemoteExceptions.convertTcTpmException(e);
      return null;
    }
  }

  public Object[] TcsipDelegateUpdateVerificationCount(long hContext, TcBlobData inputData, TcTcsAuth inAuth1)
    throws TcTddlException, TcTpmException, TcTcsException {
    try {
      Delegate_UpdateVerificationCountInParms inParms = new Delegate_UpdateVerificationCountInParms();
      inParms.setHContext(new UnsignedInt(hContext));
      inParms.setInput(inputData.asByteArray());
      inParms.setOwnerAuth(ConvertDataTypesClient.convertTcsAuth(inAuth1));

      Delegate_UpdateVerificationCountOutParms outParms = stub_.delegate_UpdateVerificationCount(inParms);

      Object[] retval = new Object[3];
      retval[0] = outParms.getResult().longValue();
      retval[1] = outParms.getOutput() == null ? null : TcBlobData.newByteArray(outParms.getOutput());
      retval[2] = ConvertDataTypesClient.convertTcsAuth(outParms.getOwnerAuth());

      return retval;
    } catch (RemoteException e) {
      ConvertRemoteExceptions.convertTcTcsException(e);
      ConvertRemoteExceptions.convertTcTddlException(e);
      ConvertRemoteExceptions.convertTcTpmException(e);
      return null;
    }
  }

  public Object[] TcsipDelegateVerifyDelegation(long hContext, TcBlobData delegation)
    throws TcTddlException, TcTpmException, TcTcsException {
    try {
      Delegate_VerifyDelegationInParms inParms = new Delegate_VerifyDelegationInParms();
      inParms.setHContext(new UnsignedInt(hContext));
      inParms.setDelegate(delegation.asByteArray());

      Delegate_VerifyDelegationOutParms outParms = stub_.delegate_VerifyDelegation(inParms);

      Object[] retval = new Object[1];
      retval[0] = outParms.getResult().longValue();

      return retval;
    } catch (RemoteException e) {
      ConvertRemoteExceptions.convertTcTcsException(e);
      ConvertRemoteExceptions.convertTcTddlException(e);
      ConvertRemoteExceptions.convertTcTpmException(e);
      return null;
    }
  }

  public Object[] TcsipSetTempDeactivated(long hContext)
    throws TcTddlException, TcTpmException, TcTcsException {
    try {
      SetTempDeactivatedInParms inParms = new SetTempDeactivatedInParms();
      inParms.setHContext(new UnsignedInt(hContext));

      SetTempDeactivatedOutParms outParms = stub_.setTempDeactivated(inParms);

      Object[] retval = new Object[1];
      retval[0] = outParms.getResult().longValue();

      return retval;
    } catch (RemoteException e) {
      ConvertRemoteExceptions.convertTcTcsException(e);
      ConvertRemoteExceptions.convertTcTddlException(e);
      ConvertRemoteExceptions.convertTcTpmException(e);
      return null;
    }
  }

  public Object[] TcsipIfxReadTpm11EkCert(long hContext, byte index, TcBlobData antiReplay)
    throws TcTddlException, TcTpmException, TcTcsException {
    return null;  //TODO - Not in WSDL.
  }

  public Object[] TcsipTerminateHandle(long hContext, long handle)
    throws TcTddlException, TcTpmException, TcTcsException {
    try {
      TerminateHandleInParms inParms = new TerminateHandleInParms();
      inParms.setHContext(new UnsignedInt(hContext));
      inParms.setHandle(new UnsignedInt(handle));

      TerminateHandleOutParms outParms = stub_.terminateHandle(inParms);

      Object[] retval = new Object[1];
      retval[0] = outParms.getResult().longValue();

      return retval;
    } catch (RemoteException e) {
      ConvertRemoteExceptions.convertTcTcsException(e);
      ConvertRemoteExceptions.convertTcTddlException(e);
      ConvertRemoteExceptions.convertTcTpmException(e);
      return null;
    }
  }

  public Object[] TcsipOwnerReadInternalPub(long hContext, long keyHandle, TcTcsAuth inAuth1) throws TcTddlException, TcTpmException {
    try {
      OwnerReadInternalPubInParms inParms = new OwnerReadInternalPubInParms();
      inParms.setHContext(new UnsignedInt(hContext));
      inParms.setHKey(new UnsignedInt(keyHandle));
      inParms.setPOwnerAuth(ConvertDataTypesClient.convertTcsAuth(inAuth1));

      OwnerReadInternalPubOutParms outParms = stub_.ownerReadInternalPub(inParms);

      Object[] retval = new Object[3];
      retval[0] = outParms.getResult().longValue();
      retval[1] = ConvertDataTypesClient.convertTcsAuth(outParms.getPOwnerAuth());
      retval[2] = outParms.getPpbPubKeyData() == null ? null : new TcTpmPubkey(TcBlobData.newByteArray(outParms.getPpbPubKeyData()));

      return retval;
    } catch (RemoteException e) {
      ConvertRemoteExceptions.convertTcTddlException(e);
      ConvertRemoteExceptions.convertTcTpmException(e);
      return null;
    }
  }

  public Object[] TcsipChangeAuthAsymFinish(long hContext, long parentHandle, long ephHandle,
    int entityType, TcTpmDigest newAuthLink, TcBlobData encNewAuth, TcBlobData encData,
    TcTcsAuth inAuth1) throws TcTddlException, TcTpmException, TcTcsException {
    try {
      ChangeAuthAsymFinishInParms inParms = new ChangeAuthAsymFinishInParms();
      inParms.setHContext(new UnsignedInt(hContext));
      inParms.setParentHandle(new UnsignedInt(parentHandle));
      inParms.setEphHandle(new UnsignedInt(ephHandle));
      inParms.setEntityType(new UnsignedInt(entityType));
      inParms.setNewAuthLink(newAuthLink.getEncoded().asByteArray());
      inParms.setEncNewAuth(encNewAuth.asByteArray());
      inParms.setEncDataIn(encData.asByteArray());
      inParms.setOwnerAuth(ConvertDataTypesClient.convertTcsAuth(inAuth1));

      ChangeAuthAsymFinishOutParms outParms = stub_.changeAuthAsymFinish(inParms);

      Object[] retval = new Object[5];
      retval[0] = outParms.getResult().longValue();
      retval[1] = ConvertDataTypesClient.convertTcsAuth(outParms.getOwnerAuth());
      retval[2] = outParms.getEncDataOut() == null ? null : TcBlobData.newByteArray(outParms.getEncDataOut());
      retval[3] = new TcTpmNonce(TcBlobData.newByteArray(outParms.getSaltNonce()));
      retval[4] = new TcTpmDigest(TcBlobData.newByteArray(outParms.getChangeProof()));

      return retval;
    } catch (RemoteException e) {
      ConvertRemoteExceptions.convertTcTddlException(e);
      ConvertRemoteExceptions.convertTcTpmException(e);
      ConvertRemoteExceptions.convertTcTcsException(e);
      return null;
    }
  }

// FIXME This function does not exist in the ifx WSDL Interface.
  public Object[] TcsiGetCredentials(long hContext)
    throws TcTddlException, TcTpmException, TcTcsException {
    try {
      GetCredentialsInParms inParms = new GetCredentialsInParms();
      inParms.setHContext(new UnsignedInt(hContext));

      GetCredentialsOutParms outParms = stub_.getCredentials(inParms);

      Object[] retval = new Object[3];
      retval[0] = outParms.getEndorsementCredential() == null ? null : TcBlobData.newByteArray(outParms.getEndorsementCredential());
      retval[1] = outParms.getPlatformCredential() == null ? null : TcBlobData.newByteArray(outParms.getPlatformCredential());
      retval[2] = outParms.getConformanceCredential() == null ? null : TcBlobData.newByteArray(outParms.getConformanceCredential());

      return retval;
    } catch (RemoteException e) {
      ConvertRemoteExceptions.convertTcTcsException(e);
      ConvertRemoteExceptions.convertTcTddlException(e);
      ConvertRemoteExceptions.convertTcTpmException(e);
      return null;
    }
  }

  public long TcsiFreeMemory(long hContext, long pMemory) {
    return 0;  //TODO - Not in WSDL.
  }

  public long TcsiGetPcrEventCount(long hContext, long pcrIndex) throws TcTcsException {
    try {
      PcrEventCountInParms inParms = new PcrEventCountInParms();
      inParms.setHContext(new UnsignedInt(hContext));
      inParms.setPcrIndex(new UnsignedInt(pcrIndex));

      PcrEventCountOutParms outParms = stub_.pcrEventCount(inParms);

      long retval = outParms.getResult().longValue();
      return retval;
    } catch (RemoteException e) {
      ConvertRemoteExceptions.convertTcTcsException(e);
      return 0;
    }
  }

  public Object[] TcsipReadCurrentTicks(long hContext) throws TcTddlException, TcTpmException, TcTcsException {
    try {
      ReadCurrentTicksInParms inParms = new ReadCurrentTicksInParms();
      inParms.setHContext(new UnsignedInt(hContext));

      ReadCurrentTicksOutParms outParms = stub_.readCurrentTicks(inParms);

      Object[] retval = new Object[2];
      retval[0] = outParms.getResult().longValue();
      retval[1] = new TcTpmCurrentTicks(TcBlobData.newByteArray(outParms.getPrgbCurrentTime()));

      return retval;
    } catch (RemoteException e) {
      ConvertRemoteExceptions.convertTcTddlException(e);
      ConvertRemoteExceptions.convertTcTpmException(e);
      ConvertRemoteExceptions.convertTcTcsException(e);
      return null;
    }
  }

  public Object[] TcsipCmkApproveMA(long hContext, TcTpmDigest migrationAuthorityDigest, TcTcsAuth inAuth1)
    throws TcTddlException, TcTpmException, TcTcsException {
    try {
      CMK_ApproveMAInParms inParms = new CMK_ApproveMAInParms();
      inParms.setHContext(new UnsignedInt(hContext));
      inParms.setMigAuthorityDigest(migrationAuthorityDigest.getEncoded().asByteArray());
      inParms.setOwnerAuth(ConvertDataTypesClient.convertTcsAuth(inAuth1));

      CMK_ApproveMAOutParms outParms = stub_.CMK_ApproveMA(inParms);

      Object[] retval = new Object[3];
      retval[0] = outParms.getResult().longValue();
      retval[1] = ConvertDataTypesClient.convertTcsAuth(outParms.getOwnerAuth());
      retval[2] = outParms.getHmacMigAuthDigest() == null ? null : new TcTpmDigest(TcBlobData.newByteArray(outParms.getHmacMigAuthDigest()));

      return retval;
    } catch (RemoteException e) {
      ConvertRemoteExceptions.convertTcTcsException(e);
      ConvertRemoteExceptions.convertTcTddlException(e);
      ConvertRemoteExceptions.convertTcTpmException(e);
      return null;
    }
  }

  public Object[] TcsipCreateMaintenanceArchive(long hContext, boolean generateRandom, TcTcsAuth inAuth1)
    throws TcTddlException, TcTpmException, TcTcsException {
    try {
      CreateMaintenanceArchiveInParms inParms = new CreateMaintenanceArchiveInParms();
      inParms.setHContext(new UnsignedInt(hContext));
      inParms.setGenerateRandom(generateRandom ? (byte) 1 : (byte) 0);
      inParms.setOwnerAuth(ConvertDataTypesClient.convertTcsAuth(inAuth1));

      CreateMaintenanceArchiveOutParms outParms = stub_.createMaintenanceArchive(inParms);

      Object[] retval = new Object[4];
      retval[0] = outParms.getResult().longValue();
      retval[1] = ConvertDataTypesClient.convertTcsAuth(outParms.getOwnerAuth());
      retval[2] = outParms.getRandom() == null ? null : TcBlobData.newByteArray(outParms.getRandom());
      retval[3] = TcBlobData.newByteArray(outParms.getArchive());

      return retval;
    } catch (RemoteException e) {
      ConvertRemoteExceptions.convertTcTcsException(e);
      ConvertRemoteExceptions.convertTcTddlException(e);
      ConvertRemoteExceptions.convertTcTpmException(e);
      return null;
    }
  }
}