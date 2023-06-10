/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Michael Steurer
 */
package iaik.tc.tss.impl.java.tcs.soapservice;

import java.rmi.RemoteException;

import org.apache.axis.AxisFault;
import org.apache.axis.types.UnsignedInt;

import iaik.tc.tss.api.exceptions.common.TcTssException;
import iaik.tc.tss.api.exceptions.tcs.TcTcsException;
import iaik.tc.tss.api.exceptions.tcs.TcTddlException;
import iaik.tc.tss.api.exceptions.tcs.TcTpmException;
import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.tss.api.structs.tcs.TcTcsAuth;
import iaik.tc.tss.api.structs.tcs.TcTcsLoadkeyInfo;
import iaik.tc.tss.api.structs.tpm.TcITpmPcrInfo;
import iaik.tc.tss.api.structs.tpm.TcITpmStoredData;
import iaik.tc.tss.api.structs.tpm.TcTpmCapVersionInfo;
import iaik.tc.tss.api.structs.tpm.TcTpmCertifyInfo;
import iaik.tc.tss.api.structs.tpm.TcTpmCertifyInfo2;
import iaik.tc.tss.api.structs.tpm.TcTpmCmkAuth;
import iaik.tc.tss.api.structs.tpm.TcTpmCounterValue;
import iaik.tc.tss.api.structs.tpm.TcTpmCurrentTicks;
import iaik.tc.tss.api.structs.tpm.TcTpmDelegateKeyBlob;
import iaik.tc.tss.api.structs.tpm.TcTpmDelegateOwnerBlob;
import iaik.tc.tss.api.structs.tpm.TcTpmDelegatePublic;
import iaik.tc.tss.api.structs.tpm.TcTpmDigest;
import iaik.tc.tss.api.structs.tpm.TcTpmEncauth;
import iaik.tc.tss.api.structs.tpm.TcTpmKey;
import iaik.tc.tss.api.structs.tpm.TcTpmKey12;
import iaik.tc.tss.api.structs.tpm.TcTpmKeyNew;
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
import iaik.tc.tss.api.structs.tpm.TcTpmStoredData12;
import iaik.tc.tss.api.structs.tpm.TcTpmSymmetricKey;
import iaik.tc.tss.api.structs.tpm.TcTpmTransportPublic;
import iaik.tc.tss.api.structs.tsp.TcTssKmKeyinfo;
import iaik.tc.tss.api.structs.tsp.TcTssPcrEvent;
import iaik.tc.tss.api.structs.tsp.TcTssUuid;
import iaik.tc.tss.api.structs.tsp.TcTssVersion;
import iaik.tc.tss.impl.java.tcs.tcsi.TcTcsi;
import iaik.tc.tss.impl.java.tcs.soapservice.serverties.*;
import org.apache.axis.types.UnsignedLong;


/**
 * 
 * Provides Bindings for the TCS SOAP Service.
 * ATTENTION: use this iaik.tc.tss.impl.java.tcs.soapservice.TSSCoreServiceBindingImpl instead of iaik.tc.tss.impl.java.tcs.soapservice.serverties.TSSCoreServiceBindingImpl
 *  
 *  @author rtoegl
 *
 */
public class TSSCoreServiceBindingImpl implements TSSCoreServicePort {

  public OpenContextOutParms openContext() throws RemoteException {

    Object[] retval = TcTcsi.TcsiOpenContext();

    OpenContextOutParms outParms = new OpenContextOutParms();
    outParms.setHContext(new UnsignedInt((Long) retval[1]));
    outParms.setResult(new UnsignedInt((Long) retval[0]));

    return outParms;
  }

  public GetCredentialsOutParms getCredentials(GetCredentialsInParms inParms) throws RemoteException {
    long hContext = inParms.getHContext().longValue();
    Object[] retval = null;

    try {
      retval = TcTcsi.TcsiGetCredentials(hContext);
    } catch (TcTcsException e) {
      throw new RemoteException("", e);
    } catch (TcTpmException e) {
      e.printStackTrace();
      throw new RemoteException("", e);
    } catch (TcTddlException e) {
      throw new RemoteException("", e);
    }

    GetCredentialsOutParms outParms = new GetCredentialsOutParms();
    outParms.setEndorsementCredential(retval[1] == null ? null : ((TcBlobData) retval[0]).asByteArray());
    outParms.setPlatformCredential(retval[1] == null ? null : ((TcBlobData) retval[1]).asByteArray());
    outParms.setConformanceCredential(retval[1] == null ? null : ((TcBlobData) retval[2]).asByteArray());

    return outParms;
  }

  public CloseContextOutParms closeContext(CloseContextInParms inParms) throws RemoteException, AxisFault {
    long hContext = inParms.getHContext().longValue();
    long retval;

    try {
      retval = TcTcsi.TcsiCloseContext(hContext);
    } catch (TcTcsException e) {
      throw new RemoteException("", e);
    } catch (TcTpmException e) {
      throw new RemoteException("", e);
    } catch (TcTddlException e) {
      throw new RemoteException("", e);
    } catch (Exception e) {
      e.printStackTrace();
      throw new RemoteException("", e);
    }

    CloseContextOutParms outParms = new CloseContextOutParms();
    outParms.setResult(new UnsignedInt(retval));

    return outParms;
  }

  public GetCapabilityOutParms getCapability(GetCapabilityInParms inParms) throws RemoteException {
    long hContext = inParms.getHContext().longValue();
    Long caparea = inParms.getCapArea().longValue();
    TcBlobData subcap = inParms.getSubCap() == null ? null : TcBlobData.newByteArray(inParms.getSubCap());
    Object[] retval = new Object[2];

    try {
      retval[0] = 0l;
      retval[1] = TcTcsi.TcsiGetCapability(hContext, caparea, subcap);
     } catch (TcTcsException e) {
      throw new RemoteException("", e);
    } catch (Exception e) {
      e.printStackTrace();
      throw new RemoteException("", e);
    }

    GetCapabilityOutParms outParms = new GetCapabilityOutParms();
    outParms.setResult(new UnsignedInt((Long) retval[0]));
    outParms.setResp(retval[1] == null ? null : ((TcBlobData) retval[1]).asByteArray());

    return outParms;
  }

  public GetCapabilityTPMOutParms getCapabilityTPM(GetCapabilityTPMInParms inParms) throws RemoteException {
    long hContext = inParms.getHContext().longValue();
    Long capArea = inParms.getCapArea().longValue();
    TcBlobData subCap = inParms.getSubCap() == null ? null : TcBlobData.newByteArray(inParms.getSubCap());
    Object[] retval = null;

    try {
      retval = TcTcsi.TcsipGetCapability(hContext, capArea, subCap);
    } catch (TcTddlException e) {
      throw new RemoteException("", e);
    } catch (TcTpmException e) {
      throw new RemoteException("", e);
    } catch (TcTcsException e) {
      throw new RemoteException("", e);
    } catch (Exception e) {
      e.printStackTrace();
      throw new RemoteException("", e);
    }

    GetCapabilityTPMOutParms outParms = new GetCapabilityTPMOutParms();
    outParms.setResult(new UnsignedInt((Long) retval[0]));
    outParms.setResp(retval[1] == null ? null : ((TcBlobData) retval[1]).asByteArray());

    return outParms;
  }

  public RegisterKeyOutParms registerKey(RegisterKeyInParms inParms) throws RemoteException {
    long hContext = inParms.getHContext().longValue();
    TcTssUuid wrappingKeyUuid = ConvertDataTypesServer.convertTssUuid(inParms.getWrappingKeyUUID());
    TcTssUuid keyUuid = ConvertDataTypesServer.convertTssUuid(inParms.getKeyUUID());
    TcBlobData key = TcBlobData.newByteArray(inParms.getRgbKey());
    TcBlobData vendorData = inParms.getGbVendorData() == null ? null : TcBlobData.newByteArray(inParms.getGbVendorData());

    try {
      // void() function
      TcTcsi.TcsiRegisterKey(hContext, wrappingKeyUuid, keyUuid, key, vendorData);
    } catch (TcTssException e) {
      throw new RemoteException("", e);
    } catch (Exception e) {
      e.printStackTrace();
      throw new RemoteException("", e);
    }

    return null;
  }

  public UnregisterKeyOutParms unregisterKey(UnregisterKeyInParms inParms) throws RemoteException {
    long hContext = inParms.getHContext().longValue();
    TcTssUuid keyUuid = ConvertDataTypesServer.convertTssUuid(inParms.getKeyUUID());

    try {
      // void() function
      TcTcsi.TcsiUnregisterKey(hContext, keyUuid);
    } catch (TcTssException e) {
      throw new RemoteException("", e);
    } catch (Exception e) {
      e.printStackTrace();
      throw new RemoteException("", e);
    }

    return null;
  }

  public KeyControlOwnerOutParms keyControlOwner(KeyControlOwnerInParms inParms) throws RemoteException {
    long hContext = inParms.getHContext().longValue();
    long tcsKeyHandle = inParms.getHKey().longValue();
    long attribName = inParms.getAttribName().longValue();
    long attribValue = new Long(inParms.getAttribValue());
    TcTcsAuth ownerAuth = ConvertDataTypesServer.convertTcsAuth(inParms.getPOwnerAuth());

    TcTssUuid uuidData = null; // FIXME There is no variable in the inParms that fits TcTssUuid

    try {
      // TODO - Method not implemented yet
      TcTcsi.TcsipKeyControlOwner(hContext, tcsKeyHandle, attribName, attribValue, ownerAuth, uuidData);
    } catch (TcTcsException e) {
      throw new RemoteException("", e);
    } catch (Exception e) {
      e.printStackTrace();
      throw new RemoteException("", e);
    }

    KeyControlOwnerOutParms outParms = new KeyControlOwnerOutParms();

    return outParms;
  }

  public EnumRegisteredKeysOutParms enumRegisteredKeys(EnumRegisteredKeysInParms inParms) throws RemoteException {
    long hContext = inParms.getHContext().longValue();
    TcTssUuid keyUuid = inParms.getPKeyUUID() == null ? null : ConvertDataTypesServer.convertTssUuid(inParms.getPKeyUUID());
    TcTssKmKeyinfo[] retval;

    try {
      retval = TcTcsi.TcsiEnumRegisteredKeys(hContext, keyUuid);
    } catch (TcTssException e) {
      throw new RemoteException("", e);
    } catch (Exception e) {
      e.printStackTrace();
      throw new RemoteException("", e);
    }

    TSSKMKEYINFO[] retval2 = new TSSKMKEYINFO[retval.length];
    for (int i = 0; i < retval.length; i++) {
      retval2[i] = ConvertDataTypesServer.convertTssKmKeyinfo(retval[i]);
    }
    EnumRegisteredKeysOutParms outParms = new EnumRegisteredKeysOutParms();
    outParms.setPpKeyHierarchy(retval2);
    
    return outParms;
  }

  public GetRegisteredKeyOutParms getRegisteredKey(GetRegisteredKeyInParms inParms) throws RemoteException {
    long hContext = inParms.getHContext().longValue();
    TcTssUuid keyUuid = ConvertDataTypesServer.convertTssUuid(inParms.getKeyUUID());
    TcTssKmKeyinfo retval;

    try {
      retval = TcTcsi.TcsiGetRegisteredKey(hContext, keyUuid);
    } catch (TcTssException e) {
      throw new RemoteException("", e);
    } catch (Exception e) {
      e.printStackTrace();
      throw new RemoteException("", e);
    }

    GetRegisteredKeyOutParms outParms = new GetRegisteredKeyOutParms();
    outParms.setPpKeyInfo(ConvertDataTypesServer.convertTssKmKeyinfo(retval));

    return outParms;
  }

  public GetRegisteredKeyBlobOutParms getRegisteredKeyBlob(GetRegisteredKeyBlobInParms inParms) throws RemoteException {
    long hContext = inParms.getHContext().longValue();
    TcTssUuid keyUuid = ConvertDataTypesServer.convertTssUuid(inParms.getKeyUUID());
    TcBlobData retval;

    try {
      retval = TcTcsi.TcsiGetRegisteredKeyBlob(hContext, keyUuid);
    } catch (TcTssException e) {
      throw new RemoteException("", e);
    } catch (Exception e) {
      e.printStackTrace();
      throw new RemoteException("", e);
    }

    GetRegisteredKeyBlobOutParms outParms = new GetRegisteredKeyBlobOutParms();
    outParms.setPrgbKey(retval == null ? null : retval.asByteArray());

    return outParms;
  }

  public GetRegisteredKeyByPublicInfoOutParms getRegisteredKeyByPublicInfo(GetRegisteredKeyByPublicInfoInParms inParms) throws RemoteException {
    long hContext = inParms.getHContext().longValue();
    long algid = inParms.getAlgID().longValue();
    TcBlobData publicInfo = TcBlobData.newByteArray(inParms.getRgbPublicInfo());
    TcBlobData retval;

    try {
      retval = TcTcsi.TcsiGetRegisteredKeyByPublicInfo(hContext, algid, publicInfo);
    } catch (TcTssException e) {
      throw new RemoteException("", e);
    } catch (Exception e) {
      e.printStackTrace();
      throw new RemoteException("", e);
    }

    GetRegisteredKeyByPublicInfoOutParms outParms = new GetRegisteredKeyByPublicInfoOutParms();
    outParms.setKeyBlob(retval == null ? null : retval.asByteArray());

    return outParms;
  }

  public LoadKeyByBlobOutParms loadKeyByBlob(LoadKeyByBlobInParms inParms) throws RemoteException {
    long hContext = inParms.getHContext().longValue();
    long unwrappingKey = inParms.getHUnwrappingKey().longValue();
    TcTpmKey wrappedKeyBlob = new TcTpmKey(TcBlobData.newByteArray(inParms.getRgbWrappedKeyBlob()));
    TcTcsAuth inAuth = ConvertDataTypesServer.convertTcsAuth(inParms.getPAuth());
    Object[] retval = null;

    try {
      retval = TcTcsi.TcsipLoadKeyByBlob(hContext, unwrappingKey, wrappedKeyBlob, inAuth);
    } catch (TcTddlException e) {
      throw new RemoteException("", e);
    } catch (TcTpmException e) {
      throw new RemoteException("", e);

    } catch (TcTcsException e) {
      throw new RemoteException("", e);
    } catch (Exception e) {
      e.printStackTrace();
      throw new RemoteException("", e);
    }

    LoadKeyByBlobOutParms outParms = new LoadKeyByBlobOutParms();
    outParms.setResult(new UnsignedInt((Long) retval[0]));
    outParms.setPAuth(ConvertDataTypesServer.convertTcsAuth((TcTcsAuth) retval[1]));
    outParms.setPhKeyHMAC(new UnsignedInt((Long) retval[2]));
    outParms.setPhKeyTCSI(new UnsignedInt((Long) retval[3]));

    return outParms;
  }

  public LoadKeyByUUIDOutParms loadKeyByUUID(LoadKeyByUUIDInParms inParms) throws RemoteException {
    TcTssUuid keyUuid = ConvertDataTypesServer.convertTssUuid(inParms.getKeyUUID());
    long hContext = inParms.getHContext().longValue();
    TcTcsLoadkeyInfo loadKeyInfo = ConvertDataTypesServer.convertTcsLoadkeyInfo(inParms.getPLoadKeyInfo());

    try {
      // TcsipLoadKeyByUuid(...) is not implemented yet
      TcTcsi.TcsipLoadKeyByUuid(hContext, keyUuid, loadKeyInfo);
    } catch (TcTssException e) {
      throw new RemoteException("", e);
    }

    LoadKeyByUUIDOutParms outParms = new LoadKeyByUUIDOutParms();

    return outParms;
  }

  public EvictKeyOutParms evictKey(EvictKeyInParms inParms) throws RemoteException {
    long hContext = inParms.getHContext().longValue();
    long TcsKeyHandle = inParms.getHKey().longValue();
    Object[] retval = null;

    try {
      retval = TcTcsi.TcsipEvictKey(hContext, TcsKeyHandle);
    } catch (TcTddlException e) {
      throw new RemoteException("", e);
    } catch (TcTpmException e) {
      throw new RemoteException("", e);
    } catch (TcTcsException e) {
      throw new RemoteException("", e);
    } catch (Exception e) {
      e.printStackTrace();
      throw new RemoteException("", e);
    }

    EvictKeyOutParms outParms = new EvictKeyOutParms();
    outParms.setResult(new UnsignedInt((Long) retval[0]));

    return outParms;
  }

  public CreateWrapKeyOutParms createWrapKey(CreateWrapKeyInParms inParms) throws RemoteException {
    long hContext = inParms.getHContext().longValue();
    long parentHandle = inParms.getHWrappingKey().longValue();
    TcTpmEncauth dataUsageAuth = new TcTpmEncauth(TcBlobData.newByteArray(inParms.getKeyUsageAuth()));
    TcTpmEncauth dataMigrationAuth = new TcTpmEncauth(TcBlobData.newByteArray(inParms.getKeyMigrationAuth()));

    TcTpmKeyNew keyInfo = new TcTpmKeyNew(TcBlobData.newByteArray(inParms.getKeyInfo()));
    // if(keyInfo.getPubKey().getKey() == null) {
    // keyInfo.setPubKey(null);
    // }

    TcTcsAuth inAuth1 = ConvertDataTypesServer.convertTcsAuth(inParms.getPAuth());
    Object[] retval = null;

    try {
      retval = TcTcsi.TcsipCreateWrapKey(hContext, parentHandle, dataUsageAuth, dataMigrationAuth, keyInfo, inAuth1);
    } catch (TcTddlException e) {
      throw new RemoteException("", e);
    } catch (TcTpmException e) {
      throw new RemoteException("", e);
    } catch (TcTcsException e) {
      throw new RemoteException("", e);
    } catch (Exception e) {
      e.printStackTrace();
      throw new RemoteException("", e);
    }
    
    CreateWrapKeyOutParms outParms = new CreateWrapKeyOutParms();
    outParms.setResult(new UnsignedInt((Long) retval[0]));
    outParms.setPAuth(ConvertDataTypesServer.convertTcsAuth((TcTcsAuth) retval[1]));
    outParms.setKeyData(retval[2] == null ? null : ((TcTpmKey) retval[2]).getEncoded().asByteArray());

    return outParms;
  }

  public GetPubKeyOutParms getPubKey(GetPubKeyInParms inParms) throws RemoteException {
    long hContext = inParms.getHContext().longValue();
    long keyHandle = inParms.getHKey().longValue();
    TcTcsAuth inAuth1 = ConvertDataTypesServer.convertTcsAuth(inParms.getPAuth());
    Object[] retval = null;

    try {
      retval = TcTcsi.TcsipGetPubKey(hContext, keyHandle, inAuth1);
    } catch (TcTddlException e) {
      throw new RemoteException("", e);
    } catch (TcTpmException e) {
      throw new RemoteException("", e);
    } catch (TcTcsException e) {
      throw new RemoteException("", e);
    } catch (Exception e) {
      e.printStackTrace();
      throw new RemoteException("", e);
    }

    GetPubKeyOutParms outParms = new GetPubKeyOutParms();
    outParms.setResult(new UnsignedInt((Long) retval[0]));
    outParms.setPAuth(ConvertDataTypesServer.convertTcsAuth((TcTcsAuth) retval[1]));
    outParms.setPrgbPubKey(retval[2] == null ? null : ((TcTpmPubkey) retval[2]).getEncoded().asByteArray());

    return outParms;
  }

  public MakeIdentityOutParms makeIdentity(MakeIdentityInParms inParms) throws RemoteException {
    long hContext = inParms.getHContext().longValue();
    TcTpmEncauth identityAuth = new TcTpmEncauth(TcBlobData.newByteArray(inParms.getIdentityAuth()));
    TcTpmDigest labelPrivCADigest = new TcTpmDigest(TcBlobData.newByteArray(inParms.getIDLabel_PrivCAHash()));

    TcTpmKeyNew idKeyParams = new TcTpmKeyNew(TcBlobData.newByteArray(inParms.getIdIdentityKeyInfo()));
    // if(idKeyParams.getPubKey().getKeyLength() == 0) {
    // idKeyParams.setPubKey(null);
    // }

    TcTcsAuth inAuth1 = ConvertDataTypesServer.convertTcsAuth(inParms.getPOwnerAuth());
    TcTcsAuth inAuth2 = ConvertDataTypesServer.convertTcsAuth(inParms.getPSrkAuth());
    Object[] retval = null;

    try {
      retval = TcTcsi.TcsipMakeIdentity(hContext, identityAuth, labelPrivCADigest, idKeyParams, inAuth1, inAuth2);
    } catch (TcTddlException e) {
      throw new RemoteException("", e);
    } catch (TcTpmException e) {
      throw new RemoteException("", e);
    } catch (TcTcsException e) {
      throw new RemoteException("", e);
    } catch (Exception e) {
      e.printStackTrace();
      throw new RemoteException("", e);
    }

    MakeIdentityOutParms outParms = new MakeIdentityOutParms();
    outParms.setResult(new UnsignedInt((Long) retval[0]));
    outParms.setPOwnerAuth(ConvertDataTypesServer.convertTcsAuth((TcTcsAuth) retval[1]));
    outParms.setPSrkAuth(ConvertDataTypesServer.convertTcsAuth((TcTcsAuth) retval[2]));
    outParms.setIdIdentityKey(retval[3] == null ? null : ((TcTpmKey) retval[3]).getEncoded().asByteArray());
    outParms.setPrgbIdentityBinding(retval[4] == null ? null : ((TcBlobData) retval[4]).asByteArray());
    outParms.setPrgbEndorsementCredential(retval[5] == null ? null : ((TcBlobData) retval[5]).asByteArray());
    outParms.setPrgbPlatformCredential(retval[6] == null ? null : ((TcBlobData) retval[6]).asByteArray());
    outParms.setPrgbConformanceCredential(retval[7] == null ? null : ((TcBlobData) retval[7]).asByteArray());

    return outParms;
  }

  public LogPcrEventOutParms logPcrEvent(LogPcrEventInParms inParms) throws RemoteException {
    long hContext = inParms.getHContext().longValue();
    TcTssPcrEvent pcrEvent;
    pcrEvent = ConvertDataTypesServer.convertTcTssPcrEvent(inParms.getEvent());
    long retval;

    try {
      retval = TcTcsi.TcsiLogPcrEvent(hContext, pcrEvent);
    } catch (TcTcsException e) {
      throw new RemoteException("", e);
    } catch (Exception e) {
      e.printStackTrace();
      throw new RemoteException("", e);
    }

    LogPcrEventOutParms outParms = new LogPcrEventOutParms();
    outParms.setPNumber(new UnsignedInt(retval));

    return outParms;
  }

  public GetPcrEventOutParms getPcrEvent(GetPcrEventInParms inParms) throws RemoteException {
    long hContext = inParms.getHContext().longValue();
    long pcrIndex = inParms.getPcrIndex().longValue();
    long number = inParms.getPNumber().longValue();
    TcTssPcrEvent retval;

    try {
      retval = TcTcsi.TcsiGetPcrEvent(hContext, pcrIndex, number);
    } catch (TcTcsException e) {
      throw new RemoteException("", e);
    } catch (Exception e) {
      e.printStackTrace();
      throw new RemoteException("", e);
    }

    GetPcrEventOutParms outParms = new GetPcrEventOutParms();
    
    iaik.tc.tss.impl.java.tcs.soapservice.serverties.TSSPCREVENT[] events= new iaik.tc.tss.impl.java.tcs.soapservice.serverties.TSSPCREVENT[1];
    events[0]= ConvertDataTypesServer.convertTcTssPcrEvent(retval);
    outParms.setPpEvent(events);
    

    return outParms;
  }

  public PcrEventCountOutParms pcrEventCount(PcrEventCountInParms inParms) throws RemoteException {
    long hContext = inParms.getHContext().longValue();
    long pcrIndex = inParms.getPcrIndex().longValue();
    long retval;

    try {
      retval = TcTcsi.TcsiGetPcrEventCount(hContext, pcrIndex);
    } catch (TcTcsException e) {
      throw new RemoteException("", e);
    } catch (Exception e) {
      e.printStackTrace();
      throw new RemoteException("", e);
    }

    PcrEventCountOutParms outParms = new PcrEventCountOutParms();
    outParms.setResult(new UnsignedInt((Long) retval));
    return outParms;
  }

  public GetPcrEventsByPcrOutParms getPcrEventsByPcr(GetPcrEventsByPcrInParms inParms) throws RemoteException {
    long hContext = inParms.getHContext().longValue();
    long pcrIndex = inParms.getPcrIndex().longValue();
    long firstEvent = inParms.getFirstEvent().longValue();
    long eventCount = inParms.getPEventCount().longValue();
    Object[] retval = null;

    try {
      retval = TcTcsi.TcsiGetPcrEventsByPcr(hContext, pcrIndex, firstEvent, eventCount);
    } catch (TcTcsException e) {
      throw new RemoteException("", e);
    } catch (Exception e) {
      e.printStackTrace();
      throw new RemoteException("", e);
    }

    GetPcrEventsByPcrOutParms outParms = new GetPcrEventsByPcrOutParms();
    TSSPCREVENT[] retval2 = new TSSPCREVENT[retval.length];
    for (int i = 0; i < retval.length; i++) {
      retval2[i] = ConvertDataTypesServer.convertTcTssPcrEvent((TcTssPcrEvent) retval[i]);
    }
    outParms.setPpEvents(retval2);

    return outParms;
  }

  public GetPcrEventLogOutParms getPcrEventLog(GetPcrEventLogInParms inParms) throws RemoteException {
    long hContext = inParms.getHContext().longValue();
    Object[] retval = null;

    try {
      retval = TcTcsi.TcsiGetPcrEventLog(hContext);
    } catch (TcTcsException e) {
      throw new RemoteException("", e);
    }

    GetPcrEventLogOutParms outParms = new GetPcrEventLogOutParms();
    TSSPCREVENT[] retval2 = new TSSPCREVENT[retval.length];
    for (int i = 0; i < retval.length; i++) {
      retval2[i] = ConvertDataTypesServer.convertTcTssPcrEvent((TcTssPcrEvent) retval[i]);
    }
    outParms.setPpEvents(retval2);

    return outParms;
  }

  public SetOwnerInstallOutParms setOwnerInstall(SetOwnerInstallInParms inParms) throws RemoteException {
    long hContext = inParms.getHContext().longValue();
    boolean state = ((Byte) inParms.getState() != 0);
    Object[] retval = null;

    try {
      retval = TcTcsi.TcsipSetOwnerInstall(hContext, state);
    } catch (TcTddlException e) {
      throw new RemoteException("", e);
    } catch (TcTpmException e) {
      throw new RemoteException("", e);
    } catch (TcTcsException e) {
      throw new RemoteException("", e);
    } catch (Exception e) {
      e.printStackTrace();
      throw new RemoteException("", e);
    }

    SetOwnerInstallOutParms outParms = new SetOwnerInstallOutParms();
    outParms.setResult(new UnsignedInt((Long) retval[0]));

    return outParms;
  }

  public TakeOwnershipOutParms takeOwnership(TakeOwnershipInParms inParms) throws RemoteException {
    long hContext = inParms.getHContext().longValue();
    int protocolID = inParms.getProtocolID().intValue();
    TcBlobData encOwnerAuth = TcBlobData.newByteArray(inParms.getEncOwnerAuth());
    TcBlobData encSrkAuth = TcBlobData.newByteArray(inParms.getEncSrkAuth());
    TcTpmKeyNew srkParams = new TcTpmKeyNew(TcBlobData.newByteArray(inParms.getSrkKeyInfo()));

    // TcTpmKeyNew srkParams = new
    // TcTpmKeyNew(TcBlobData.newByteArray(inParms.getSrkKeyInfo()));
    // srkParams.setPcrInfo(null);
    // srkParams.setPubKey(null);

    TcTcsAuth inAuth1 = ConvertDataTypesServer.convertTcsAuth(inParms.getOwnerAuth());
    Object[] retval = null;

    try {
      retval = TcTcsi.TcsipTakeOwnership(hContext, protocolID, encOwnerAuth, encSrkAuth, srkParams, inAuth1);
    } catch (TcTddlException e) {

      throw new RemoteException("", e);
    } catch (TcTpmException e) {
      throw new RemoteException("", e);
    } catch (TcTcsException e) {
      throw new RemoteException("", e);
    } catch (Exception e) {
      e.printStackTrace();
      throw new RemoteException("", e);
    }

    TakeOwnershipOutParms outParms = new TakeOwnershipOutParms();
    outParms.setResult(new UnsignedInt((Long) retval[0]));
    outParms.setOwnerAuth(ConvertDataTypesServer.convertTcsAuth((TcTcsAuth) retval[1]));
    outParms.setSrkKeyData(retval[2] == null ? null : ((TcTpmKey) retval[2]).getEncoded().asByteArray());

    return outParms;
  }

  public SetOperatorAuthOutParms setOperatorAuth(SetOperatorAuthInParms inParms) throws RemoteException {
    long hContext = inParms.getHContext().longValue();
    TcTpmSecret operatorAuth = new TcTpmSecret(TcBlobData.newByteArray(inParms.getOperatorAuth()));
    Object[] retval = null;

    try {
      retval = TcTcsi.TcsipSetOperatorAuth(hContext, operatorAuth);
    } catch (TcTddlException e) {
      throw new RemoteException("", e);
    } catch (TcTpmException e) {
      throw new RemoteException("", e);
    } catch (TcTcsException e) {
      throw new RemoteException("", e);
    } catch (Exception e) {
      e.printStackTrace();
      throw new RemoteException("", e);
    }

    SetOperatorAuthOutParms outParms = new SetOperatorAuthOutParms();
    outParms.setResult(new UnsignedInt((Long) retval[0]));

    return outParms;
  }

  public OIAPOutParms OIAP(OIAPInParms inParms) throws RemoteException {
    long hContext = inParms.getHContext().longValue();
    Object[] retval = null;

    try {
      retval = TcTcsi.TcsipOIAP(hContext);
    } catch (TcTddlException e) {
      throw new RemoteException("", e);
    } catch (TcTpmException e) {
      throw new RemoteException("", e);
    } catch (TcTcsException e) {
      throw new RemoteException("", e);
    } catch (Exception e) {
      e.printStackTrace();
      throw new RemoteException("", e);
    }

    OIAPOutParms outParms = new OIAPOutParms();
    outParms.setResult(new UnsignedInt((Long) (retval[0])));
    outParms.setAuthHandle(new UnsignedInt((Long) (retval[1])));
    outParms.setNonce0(retval[2] == null ? null : ((TcTpmNonce) retval[2]).getEncoded().asByteArray());

    return outParms;
  }

  public OSAPOutParms OSAP(OSAPInParms inParms) throws RemoteException {
    long hContext = inParms.getHContext().longValue();
    int entityType = inParms.getEntityType().intValue();
    long entityValue = inParms.getEntityValue().longValue();
    TcTpmNonce nonceOddOSAP = new TcTpmNonce(TcBlobData.newByteArray(inParms.getNonceOddOSAP()));
    Object[] retval = null;

    try {
      retval = TcTcsi.TcsipOSAP(hContext, entityType, entityValue, nonceOddOSAP);
    } catch (TcTddlException e) {
      throw new RemoteException("", e);
    } catch (TcTpmException e) {
      throw new RemoteException("", e);
    } catch (TcTcsException e) {
      throw new RemoteException("", e);
    } catch (Exception e) {
      e.printStackTrace();
      throw new RemoteException("", e);
    }

    OSAPOutParms outParms = new OSAPOutParms();
    outParms.setResult(new UnsignedInt((Long) (retval[0])));
    outParms.setAuthHandle(new UnsignedInt((Long) (retval[1])));
    outParms.setNonceEven(retval[2] == null ? null : ((TcTpmNonce) retval[2]).getEncoded().asByteArray());
    outParms.setNonceEvenOSAP(retval[3] == null ? null : ((TcTpmNonce) retval[3]).getEncoded().asByteArray());

    return outParms;
  }

  public ChangeAuthOutParms changeAuth(ChangeAuthInParms inParms) throws RemoteException {
    long hContext = inParms.getHContext().longValue();
    long parentHandle = inParms.getParentHandle().longValue();
    int protocolID = inParms.getProtocolID().intValue();
    TcTpmEncauth newAuth = new TcTpmEncauth(TcBlobData.newByteArray(inParms.getNewAuth()));
    int entityType = inParms.getEntityType().intValue();
    TcBlobData encData = TcBlobData.newByteArray(inParms.getEncData());
    TcTcsAuth inAuth1 = ConvertDataTypesServer.convertTcsAuth(inParms.getEntityAuth());
    TcTcsAuth inAuth2 = ConvertDataTypesServer.convertTcsAuth(inParms.getOwnerAuth());
    Object[] retval = null;

    try {
      retval = TcTcsi.TcsipChangeAuth(hContext, parentHandle, protocolID, newAuth, entityType, encData, inAuth1, inAuth2);
    } catch (TcTddlException e) {
      throw new RemoteException("", e);
    } catch (TcTpmException e) {
      throw new RemoteException("", e);
    } catch (TcTcsException e) {
      throw new RemoteException("", e);
    } catch (Exception e) {
      e.printStackTrace();
      throw new RemoteException("", e);
    }

    ChangeAuthOutParms outParms = new ChangeAuthOutParms();
    outParms.setResult(new UnsignedInt((Long) (retval[0])));
    outParms.setOwnerAuth(ConvertDataTypesServer.convertTcsAuth((TcTcsAuth) retval[1]));
    outParms.setEntityAuth(ConvertDataTypesServer.convertTcsAuth((TcTcsAuth) retval[2]));
    outParms.setOutData(retval[3] == null ? null : ((TcBlobData) retval[3]).asByteArray());

    return outParms;
  }

  public ChangeAuthOwnerOutParms changeAuthOwner(ChangeAuthOwnerInParms inParms) throws RemoteException {
    long hContext = inParms.getHContext().longValue();
    int protocolID = inParms.getProtocolID().intValue();
    TcTpmEncauth newAuth = new TcTpmEncauth(TcBlobData.newByteArray(inParms.getNewAuth()));
    int entityType = inParms.getEntityType().intValue();
    TcTcsAuth inAuth1 = ConvertDataTypesServer.convertTcsAuth(inParms.getOwnerAuth());
    Object[] retval = null;

    try {
      retval = TcTcsi.TcsipChangeAuthOwner(hContext, protocolID, newAuth, entityType, inAuth1);
    } catch (TcTddlException e) {
      throw new RemoteException("", e);
    } catch (TcTpmException e) {
      throw new RemoteException("", e);
    } catch (TcTcsException e) {
      throw new RemoteException("", e);
    } catch (Exception e) {
      e.printStackTrace();
      throw new RemoteException("", e);
    }

    ChangeAuthOwnerOutParms outParms = new ChangeAuthOwnerOutParms();
    outParms.setResult(new UnsignedInt((Long) (retval[0])));
    outParms.setOwnerAuth(ConvertDataTypesServer.convertTcsAuth((TcTcsAuth) retval[1]));

    return outParms;
  }

  public ChangeAuthAsymStartOutParms changeAuthAsymStart(ChangeAuthAsymStartInParms inParms) throws RemoteException {

    long hContext = inParms.getHContext().longValue();
    long idHandle = inParms.getIdHandle().longValue();
    TcTpmNonce antiReplay = new TcTpmNonce(TcBlobData.newByteArray(inParms.getAntiReplay()));
    TcTpmKeyParms tempKey = new TcTpmKeyParms(TcBlobData.newByteArray(inParms.getTempKeyInfoData()));
    TcTcsAuth inAuth1 = ConvertDataTypesServer.convertTcsAuth(inParms.getPAuth());
    Object[] retval = null;

    try {
      retval = TcTcsi.TcsipChangeAuthAsymStart(hContext, idHandle, antiReplay, tempKey, inAuth1);
    } catch (TcTddlException e) {
      throw new RemoteException("", e);
    } catch (TcTpmException e) {
      throw new RemoteException("", e);
    } catch (TcTcsException e) {
      throw new RemoteException("", e);
    } catch (Exception e) {
      e.printStackTrace();
      throw new RemoteException("", e);
    }

    ChangeAuthAsymStartOutParms outParms = new ChangeAuthAsymStartOutParms();
    outParms.setResult(new UnsignedInt((Long) (retval[0])));
    outParms.setPAuth(ConvertDataTypesServer.convertTcsAuth((TcTcsAuth) (retval[1])));
    outParms.setCertifyInfo(retval[2] == null ? null : ((TcTpmCertifyInfo) retval[2]).getEncoded().asByteArray());
    outParms.setSig(retval[3] == null ? null : ((TcBlobData) retval[3]).asByteArray());
    outParms.setEphHandle(new UnsignedInt((Long) (retval[4])));
    outParms.setTempKeyData(retval[5] == null ? null : ((TcTpmKey) retval[5]).getEncData().asByteArray());

    return outParms;
  }

  public ChangeAuthAsymFinishOutParms changeAuthAsymFinish(ChangeAuthAsymFinishInParms inParms) throws RemoteException {

    long hContext = inParms.getHContext().longValue();
    long parentHandle = inParms.getParentHandle().longValue();
    long ephHandle = inParms.getEphHandle().longValue();
    int entityType = inParms.getEntityType().intValue();
    TcTpmDigest newAuthLink = new TcTpmDigest(TcBlobData.newByteArray(inParms.getNewAuthLink()));
    TcBlobData encNewAuth = TcBlobData.newByteArray(inParms.getEncNewAuth());
    TcBlobData encData = TcBlobData.newByteArray(inParms.getEncDataIn());
    TcTcsAuth inAuth1 = ConvertDataTypesServer.convertTcsAuth(inParms.getOwnerAuth());
    Object[] retval = null;

    try {
      retval = TcTcsi.TcsipChangeAuthAsymFinish(hContext, parentHandle, ephHandle, entityType, newAuthLink, encNewAuth, encData, inAuth1);
    } catch (TcTddlException e) {
      throw new RemoteException("", e);
    } catch (TcTpmException e) {
      throw new RemoteException("", e);
    } catch (TcTcsException e) {
      throw new RemoteException("", e);
    } catch (Exception e) {
      e.printStackTrace();
      throw new RemoteException("", e);
    }

    ChangeAuthAsymFinishOutParms outParms = new ChangeAuthAsymFinishOutParms();

    outParms.setResult(new UnsignedInt((Long) (retval[0])));
    outParms.setOwnerAuth(ConvertDataTypesServer.convertTcsAuth((TcTcsAuth) (retval[1])));
    outParms.setEncDataOut(retval[2] == null ? null : ((TcBlobData) retval[2]).asByteArray());
    outParms.setSaltNonce(retval[3] == null ? null : ((TcTpmNonce) retval[3]).getEncoded().asByteArray());
    outParms.setChangeProof(retval[4] == null ? null : ((TcTpmDigest) retval[4]).getEncoded().asByteArray());

    return outParms;
  }

  public TerminateHandleOutParms terminateHandle(TerminateHandleInParms inParms) throws RemoteException {

    long hContext = inParms.getHContext().longValue();
    long handle = inParms.getHandle().longValue();
    Object[] retval = null;

    try {
      retval = TcTcsi.TcsipTerminateHandle(hContext, handle);
    } catch (TcTddlException e) {
      throw new RemoteException("", e);
    } catch (TcTpmException e) {
      throw new RemoteException("", e);
    } catch (TcTcsException e) {
      throw new RemoteException("", e);
    } catch (Exception e) {
      e.printStackTrace();
      throw new RemoteException("", e);
    }

    TerminateHandleOutParms outParms = new TerminateHandleOutParms();
    outParms.setResult(new UnsignedInt((Long) (retval[0])));

    return outParms;
  }

  public ActivateTPMIdentityOutParms activateTPMIdentity(ActivateTPMIdentityInParms inParms) throws RemoteException {

    long hContext = inParms.getHContext().longValue();
    long idKeyHandle = inParms.getIdKey().longValue();
    TcBlobData blob = TcBlobData.newByteArray(inParms.getBlob());
    TcTcsAuth inAuth1 = ConvertDataTypesServer.convertTcsAuth(inParms.getIdKeyAuth());
    TcTcsAuth inAuth2 = ConvertDataTypesServer.convertTcsAuth(inParms.getOwnerAuth());
    Object[] retval = null;

    try {
      retval = TcTcsi.TcsipActivateTpmIdentity(hContext, idKeyHandle, blob, inAuth1, inAuth2);
    } catch (TcTddlException e) {
      throw new RemoteException("", e);
    } catch (TcTpmException e) {
      throw new RemoteException("", e);
    } catch (TcTcsException e) {
      throw new RemoteException("", e);
    } catch (Exception e) {
      e.printStackTrace();
      throw new RemoteException("", e);
    }

    ActivateTPMIdentityOutParms outParms = new ActivateTPMIdentityOutParms();
    outParms.setResult(new UnsignedInt((Long) (retval[0])));
    outParms.setIdKeyAuth(ConvertDataTypesServer.convertTcsAuth((TcTcsAuth) (retval[1])));
    outParms.setOwnerAuth(ConvertDataTypesServer.convertTcsAuth((TcTcsAuth) (retval[2])));
    outParms.setSymmetricKey(retval[3] == null ? null : ((TcTpmSymmetricKey) retval[3]).getEncoded().asByteArray());

    return outParms;
  }

  public ExtendOutParms extend(ExtendInParms inParms) throws RemoteException {

    long hContext = inParms.getHContext().longValue();
    long pcrNum = inParms.getPcrNum().longValue();
    TcTpmDigest inDigest = new TcTpmDigest(TcBlobData.newByteArray(inParms.getInDigest()));
    Object[] retval = null;

    try {
      retval = TcTcsi.TcsipExtend(hContext, pcrNum, inDigest);
    } catch (TcTddlException e) {
      throw new RemoteException("", e);
    } catch (TcTpmException e) {
      throw new RemoteException("", e);
    } catch (TcTcsException e) {
      throw new RemoteException("", e);
    } catch (Exception e) {
      e.printStackTrace();
      throw new RemoteException("", e);
    }

    ExtendOutParms outParms = new ExtendOutParms();
    outParms.setResult(new UnsignedInt((Long) (retval[0])));
    outParms.setOutDigest(retval[1] == null ? null : ((TcTpmDigest) retval[1]).getEncoded().asByteArray());

    return outParms;
  }

  public PcrReadOutParms pcrRead(PcrReadInParms inParms) throws RemoteException {

    long hContext = inParms.getHContext().longValue();
    long pcrNum = inParms.getPcrNum().longValue();
    Object[] retval = null;

    try {
      retval = TcTcsi.TcsipPcrRead(hContext, pcrNum);
    } catch (TcTddlException e) {
      throw new RemoteException("", e);
    } catch (TcTpmException e) {
      throw new RemoteException("", e);
    } catch (TcTcsException e) {
      throw new RemoteException("", e);
    } catch (Exception e) {
      e.printStackTrace();
      throw new RemoteException("", e);
    }

    PcrReadOutParms outParms = new PcrReadOutParms();
    outParms.setResult(new UnsignedInt((Long) (retval[0])));
    outParms.setOutDigest(retval[1] == null ? null : ((TcTpmDigest) retval[1]).getEncoded().asByteArray());

    return outParms;
  }

  public QuoteOutParms quote(QuoteInParms inParms) throws RemoteException {

    long hContext = inParms.getHContext().longValue();
    long keyHandle = inParms.getKeyHandle().longValue();
    TcTpmNonce externalData = new TcTpmNonce(TcBlobData.newByteArray(inParms.getAntiReplay()));
    TcTpmPcrSelection targetPCR = new TcTpmPcrSelection(TcBlobData.newByteArray(inParms.getPcrTarget()));
    TcTcsAuth inAuth1 = ConvertDataTypesServer.convertTcsAuth(inParms.getPrivAuth());
    Object[] retval = null;

    try {
      retval = TcTcsi.TcsipQuote(hContext, keyHandle, externalData, targetPCR, inAuth1);
    } catch (TcTddlException e) {
      throw new RemoteException("", e);
    } catch (TcTpmException e) {
      throw new RemoteException("", e);
    } catch (TcTcsException e) {
      throw new RemoteException("", e);
    } catch (Exception e) {
      e.printStackTrace();
      throw new RemoteException("", e);
    }

    QuoteOutParms outParms = new QuoteOutParms();
    outParms.setResult(new UnsignedInt((Long) retval[0]));
    outParms.setPrivAuth(ConvertDataTypesServer.convertTcsAuth((TcTcsAuth) retval[1]));
    outParms.setPcrData(retval[2] == null ? null : ((TcTpmPcrComposite) retval[2]).getEncoded().asByteArray());
    outParms.setSig(retval[3] == null ? null : ((TcBlobData) retval[3]).asByteArray());

    return outParms;
  }

  public DirWriteAuthOutParms dirWriteAuth(DirWriteAuthInParms inParms) throws RemoteException {

    long hContext = inParms.getHContext().longValue();
    long dirIndex = inParms.getDirIndex().longValue();
    TcTpmDigest newContents = new TcTpmDigest(TcBlobData.newByteArray(inParms.getNewContents()));
    TcTcsAuth inAuth1 = ConvertDataTypesServer.convertTcsAuth(inParms.getOwnerAuth());
    Object[] retval = null;

    try {
      retval = TcTcsi.TcsipDirWriteAuth(hContext, dirIndex, newContents, inAuth1);
    } catch (TcTddlException e) {
      throw new RemoteException("", e);
    } catch (TcTpmException e) {
      throw new RemoteException("", e);
    } catch (TcTcsException e) {
      throw new RemoteException("", e);
    } catch (Exception e) {
      e.printStackTrace();
      throw new RemoteException("", e);
    }

    DirWriteAuthOutParms outParms = new DirWriteAuthOutParms();
    outParms.setResult(new UnsignedInt((Long) retval[0]));
    outParms.setOwnerAuth(ConvertDataTypesServer.convertTcsAuth((TcTcsAuth) retval[1]));

    return outParms;
  }

  public DirReadOutParms dirRead(DirReadInParms inParms) throws RemoteException {

    long hContext = inParms.getHContext().longValue();
    long dirIndex = inParms.getDirIndex().longValue();
    Object[] retval = null;

    try {
      retval = TcTcsi.TcsipDirRead(hContext, dirIndex);
    } catch (TcTddlException e) {
      throw new RemoteException("", e);
    } catch (TcTpmException e) {
      throw new RemoteException("", e);
    } catch (TcTcsException e) {
      throw new RemoteException("", e);
    } catch (Exception e) {
      e.printStackTrace();
      throw new RemoteException("", e);
    }

    DirReadOutParms outParms = new DirReadOutParms();
    outParms.setResult(new UnsignedInt((Long) retval[0]));
    outParms.setDirValue(retval[1] == null ? null : ((TcTpmDigest) retval[1]).getEncoded().asByteArray());

    return outParms;
  }

  public SealOutParms seal(SealInParms inParms) throws RemoteException {

    long hContext = inParms.getHContext().longValue();
    long keyHandle = inParms.getKeyHandle().longValue();
    TcTpmEncauth encAuth = new TcTpmEncauth(TcBlobData.newByteArray(inParms.getEncAuth()));

    
    //    FIXXXME: Hardcoded TpmPCRInfo LONG. 
    
    TcITpmPcrInfo pcrInfo = new TcTpmPcrInfoLong(TcBlobData.newByteArray(inParms.getPcrInfo()));
    TcBlobData inData = TcBlobData.newByteArray(inParms.getInData());
    TcTcsAuth inAuth1 = ConvertDataTypesServer.convertTcsAuth(inParms.getPubAuth());
    Object[] retval = null;

    try {
      retval = TcTcsi.TcsipSeal(hContext, keyHandle, encAuth, pcrInfo, inData, inAuth1);
    } catch (TcTddlException e) {
      throw new RemoteException("", e);
    } catch (TcTpmException e) {
      throw new RemoteException("", e);
    } catch (TcTcsException e) {
      throw new RemoteException("", e);
    } catch (Exception e) {
      e.printStackTrace();
      throw new RemoteException("", e);
    }

    SealOutParms outParms = new SealOutParms();
    outParms.setResult(new UnsignedInt((Long) retval[0]));
    outParms.setPubAuth(ConvertDataTypesServer.convertTcsAuth((TcTcsAuth) retval[1]));
    outParms.setSealedData(retval[2] == null ? null : ((TcITpmStoredData) retval[2]).getEncoded().asByteArray());

    return outParms;
  }

  public UnsealOutParms unseal(UnsealInParms inParms) throws RemoteException {

    long hContext = inParms.getHContext().longValue();
    long parentHandle = inParms.getKeyHandle().longValue();
    TcTpmStoredData12 inData = new TcTpmStoredData12(TcBlobData.newByteArray(inParms.getSealedData()));
    TcTcsAuth inAuth1 = ConvertDataTypesServer.convertTcsAuth(inParms.getDataAuth());
    TcTcsAuth inAuth2 = ConvertDataTypesServer.convertTcsAuth(inParms.getKeyAuth());
    Object[] retval = null;

    try {
      retval = TcTcsi.TcsipUnseal(hContext, parentHandle, inData, inAuth1, inAuth2);
    } catch (TcTddlException e) {
      throw new RemoteException("", e);
    } catch (TcTpmException e) {
      throw new RemoteException("", e);
    } catch (TcTcsException e) {
      throw new RemoteException("", e);
    } catch (Exception e) {
      e.printStackTrace();
      throw new RemoteException("", e);
    }

    UnsealOutParms outParms = new UnsealOutParms();
    outParms.setResult(new UnsignedInt((Long) retval[0]));
    outParms.setDataAuth(ConvertDataTypesServer.convertTcsAuth((TcTcsAuth) retval[1]));
    outParms.setKeyAuth(ConvertDataTypesServer.convertTcsAuth((TcTcsAuth) retval[2]));
    outParms.setData(retval[3] == null ? null : ((TcBlobData) retval[3]).asByteArray());

    return outParms;
  }

  public UnBindOutParms unBind(UnBindInParms inParms) throws RemoteException {

    long hContext = inParms.getHContext().longValue();
    long keyHandle = inParms.getKeyHandle().longValue();
    TcBlobData inData = TcBlobData.newByteArray(inParms.getInData());
    TcTcsAuth inAuth1 = ConvertDataTypesServer.convertTcsAuth(inParms.getPrivAuth());
    Object[] retval = null;

    try {
      retval = TcTcsi.TcsipUnBind(hContext, keyHandle, inData, inAuth1);
    } catch (TcTddlException e) {
      throw new RemoteException("", e);
    } catch (TcTpmException e) {
      throw new RemoteException("", e);
    } catch (TcTcsException e) {
      throw new RemoteException("", e);
    } catch (Exception e) {
      e.printStackTrace();
      throw new RemoteException("", e);
    }

    UnBindOutParms outParms = new UnBindOutParms();
    outParms.setResult(new UnsignedInt((Long) retval[0]));
    outParms.setPrivAuth(ConvertDataTypesServer.convertTcsAuth((TcTcsAuth) retval[1]));
    outParms.setOutData(retval[2] == null ? null : ((TcBlobData) retval[2]).asByteArray());

    return outParms;
  }

  public CreateMigrationBlobOutParms createMigrationBlob(CreateMigrationBlobInParms inParms) throws RemoteException {

    long hContext = inParms.getHContext().longValue();
    long parentHandle = inParms.getParentHandle().longValue();
    int migrationType = inParms.getMigrationType().intValue();
    TcTpmMigrationkeyAuth migrationKeyAuth = new TcTpmMigrationkeyAuth(TcBlobData.newByteArray(inParms.getMigrationKeyAuth()));
    TcBlobData encData = TcBlobData.newByteArray(inParms.getEncData());
    TcTcsAuth inAuth1 = ConvertDataTypesServer.convertTcsAuth(inParms.getEntityAuth());
    TcTcsAuth inAuth2 = ConvertDataTypesServer.convertTcsAuth(inParms.getParentAuth());
    Object[] retval = null;

    try {
      retval = TcTcsi.TcsipCreateMigrationBlob(hContext, parentHandle, migrationType, migrationKeyAuth, encData, inAuth1, inAuth2);
    } catch (TcTddlException e) {
      throw new RemoteException("", e);
    } catch (TcTpmException e) {
      throw new RemoteException("", e);
    } catch (TcTcsException e) {
      throw new RemoteException("", e);
    } catch (Exception e) {
      e.printStackTrace();
      throw new RemoteException("", e);
    }

    CreateMigrationBlobOutParms outParms = new CreateMigrationBlobOutParms();
    outParms.setResult(new UnsignedInt((Long) retval[0]));
    outParms.setParentAuth(ConvertDataTypesServer.convertTcsAuth((TcTcsAuth) retval[1]));
    outParms.setEntityAuth(ConvertDataTypesServer.convertTcsAuth((TcTcsAuth) retval[2]));
    outParms.setRandom(retval[3] == null ? null : ((TcBlobData) retval[3]).asByteArray());
    outParms.setOutData(retval[4] == null ? null : ((TcBlobData) retval[4]).asByteArray());

    return outParms;
  }

  public ConvertMigrationBlobOutParms convertMigrationBlob(ConvertMigrationBlobInParms inParms) throws RemoteException {

    long hContext = inParms.getHContext().longValue();
    long parentHandle = inParms.getParentHandle().longValue();
    TcBlobData inData = TcBlobData.newByteArray(inParms.getInData());
    TcBlobData random = TcBlobData.newByteArray(inParms.getRandom());
    TcTcsAuth inAuth1 = ConvertDataTypesServer.convertTcsAuth(inParms.getParentAuth());
    Object[] retval = null;

    try {
      retval = TcTcsi.TcsipConvertMigrationBlob(hContext, parentHandle, inData, random, inAuth1);
    } catch (TcTddlException e) {
      throw new RemoteException("", e);
    } catch (TcTpmException e) {
      throw new RemoteException("", e);
    } catch (TcTcsException e) {
      throw new RemoteException("", e);
    } catch (Exception e) {
      e.printStackTrace();
      throw new RemoteException("", e);
    }

    ConvertMigrationBlobOutParms outParms = new ConvertMigrationBlobOutParms();
    outParms.setResult(new UnsignedInt((Long) retval[0]));
    outParms.setParentAuth(ConvertDataTypesServer.convertTcsAuth((TcTcsAuth) retval[1]));
    outParms.setOutData(retval[2] == null ? null : ((TcBlobData) retval[2]).asByteArray());

    return outParms;
  }

  public AuthorizeMigrationKeyOutParms authorizeMigrationKey(AuthorizeMigrationKeyInParms inParms) throws RemoteException {

    long hContext = inParms.getHContext().longValue();
    int migrationScheme = inParms.getMigrateScheme().intValue();
    TcTpmPubkey migrationKey = new TcTpmPubkey(TcBlobData.newByteArray(inParms.getMigrationKey()));
    TcTcsAuth inAuth1 = ConvertDataTypesServer.convertTcsAuth(inParms.getOwnerAuth());
    Object[] retval = null;

    try {
      retval = TcTcsi.TcsipAuthorizeMigrationKey(hContext, migrationScheme, migrationKey, inAuth1);
    } catch (TcTddlException e) {
      throw new RemoteException("", e);
    } catch (TcTpmException e) {
      throw new RemoteException("", e);
    } catch (TcTcsException e) {
      throw new RemoteException("", e);
    } catch (Exception e) {
      e.printStackTrace();
      throw new RemoteException("", e);
    }

    AuthorizeMigrationKeyOutParms outParms = new AuthorizeMigrationKeyOutParms();
    outParms.setResult(new UnsignedInt((Long) retval[0]));
    outParms.setOwnerAuth(ConvertDataTypesServer.convertTcsAuth((TcTcsAuth) retval[1]));
    outParms.setMigrationKeyAuth(retval[2] == null ? null : ((TcBlobData) retval[2]).asByteArray());

    return outParms;
  }

  public CertifyKeyOutParms certifyKey(CertifyKeyInParms inParms) throws RemoteException {

    long hContext = inParms.getHContext().longValue();
    long certHandle = inParms.getCertHandle().longValue();
    long keyHandle = inParms.getKeyHandle().longValue();
    TcTpmNonce antiReplay = new TcTpmNonce(TcBlobData.newByteArray(inParms.getAntiReplay()));
    TcTcsAuth inAuth1 = ConvertDataTypesServer.convertTcsAuth(inParms.getCertAuth());
    TcTcsAuth inAuth2 = ConvertDataTypesServer.convertTcsAuth(inParms.getKeyAuth());
    Object[] retval = null;

    try {
      retval = TcTcsi.TcsipCertifyKey(hContext, certHandle, keyHandle, antiReplay, inAuth1, inAuth2);
    } catch (TcTddlException e) {
      throw new RemoteException("", e);
    } catch (TcTpmException e) {
      throw new RemoteException("", e);
    } catch (TcTcsException e) {
      throw new RemoteException("", e);
    } catch (Exception e) {
      e.printStackTrace();
      throw new RemoteException("", e);
    }

    CertifyKeyOutParms outParms = new CertifyKeyOutParms();
    outParms.setResult(new UnsignedInt((Long) retval[0]));
    outParms.setCertAuth(ConvertDataTypesServer.convertTcsAuth((TcTcsAuth) retval[1]));
    outParms.setKeyAuth(ConvertDataTypesServer.convertTcsAuth((TcTcsAuth) retval[2]));

    byte[] retvalthree=null; 
    try {	
    	TcTpmCertifyInfo certinfo = (TcTpmCertifyInfo) retval[3];
    	retvalthree = certinfo.getEncoded().asByteArray();
    } catch (ClassCastException e) 
    {
		TcTpmCertifyInfo2 certinfo2 = (TcTpmCertifyInfo2) retval[3];
    	retvalthree = certinfo2.getEncoded().asByteArray();
  	}
    	
    
    outParms.setCertifyInfo(retval[3] == null ? null : retvalthree);

    outParms.setOutData(retval[4] == null ? null : ((TcBlobData) retval[4]).asByteArray());

    return outParms;
  }

  public GetRandomOutParms getRandom(GetRandomInParms inParms) throws RemoteException {

    long hContext = inParms.getHContext().longValue();
    long bytesRequested = inParms.getBytesRequested().longValue();
    Object[] retval = null;

    try {
      retval = TcTcsi.TcsipGetRandom(hContext, bytesRequested);
    } catch (TcTddlException e) {
      throw new RemoteException("", e);
    } catch (TcTpmException e) {
      throw new RemoteException("", e);
    } catch (TcTcsException e) {
      throw new RemoteException("", e);
    } catch (Exception e) {
      e.printStackTrace();
      throw new RemoteException("", e);
    }

    GetRandomOutParms outParms = new GetRandomOutParms();
    outParms.setResult(new UnsignedInt((Long) retval[0]));
    outParms.setRandomBytes(((TcBlobData) retval[1]).asByteArray());

    return outParms;
  }

  public StirRandomOutParms stirRandom(StirRandomInParms inParms) throws RemoteException {

    long hContext = inParms.getHContext().longValue();
    TcBlobData inData = TcBlobData.newByteArray(inParms.getInData());
    Object[] retval = null;

    try {
      retval = TcTcsi.TcsipStirRandom(hContext, inData);
    } catch (TcTddlException e) {
      throw new RemoteException("", e);
    } catch (TcTpmException e) {
      throw new RemoteException("", e);
    } catch (TcTcsException e) {
      throw new RemoteException("", e);
    } catch (Exception e) {
      e.printStackTrace();
      throw new RemoteException("", e);
    }

    StirRandomOutParms outParms = new StirRandomOutParms();
    outParms.setResult(new UnsignedInt((Long) retval[0]));

    return outParms;
  }

  public GetCapabilityOwnerOutParms getCapabilityOwner(GetCapabilityOwnerInParms inParms) throws RemoteException {


    long hContext = inParms.getHContext().longValue();
    ConvertDataTypesServer.convertTcsAuth(inParms.getPOwnerAuth());
    TcTcsAuth pOwnerAuth = ConvertDataTypesServer.convertTcsAuth(inParms.getPOwnerAuth());
    Object[] retval = null;

    try {
      retval = TcTcsi.TcsipGetCapabilityOwner(hContext, pOwnerAuth);
    } catch (TcTddlException e) {
      throw new RemoteException("", e);
    } catch (TcTpmException e) {
      throw new RemoteException("", e);
    } catch (TcTcsException e) {
      throw new RemoteException("", e);
    } catch (Exception e) {
      e.printStackTrace();
      throw new RemoteException("", e);
    }

    //		return new Object[] { outBlob.getRetCodeAsLong(), outAuth1, version,
    //		new Long(non_volatile_flags), new Long(volatile_flags) };

    GetCapabilityOwnerOutParms outParms = new GetCapabilityOwnerOutParms();
    outParms.setResult(new UnsignedInt((Long) retval[0]));
    outParms.setPOwnerAuth(ConvertDataTypesServer.convertTcsAuth((TcTcsAuth) retval[1]));
    outParms.setPVersion(ConvertDataTypesServer.convertTssVersion((TcTssVersion) retval[1]));
    outParms.setPNonVolatileFlags(new UnsignedInt((Long) retval[3]));
    outParms.setPVolatileFlags(new UnsignedInt((Long) retval[4]));

    return outParms;
  }

  public CreateEndorsementKeyPairOutParms createEndorsementKeyPair(CreateEndorsementKeyPairInParms inParms) throws RemoteException {

    long hContext = inParms.getHContext().longValue();
    TcTpmNonce antiReplay = new TcTpmNonce(TcBlobData.newByteArray(inParms.getAntiReplay()));
    TcTpmKeyParms keyInfo = new TcTpmKeyParms(TcBlobData.newByteArray(inParms.getEndorsementKeyInfo()));
    Object[] retval = null;

    try {
      retval = TcTcsi.TcsipCreateEndorsementKeyPair(hContext, antiReplay, keyInfo);
    } catch (TcTddlException e) {
      throw new RemoteException("", e);
    } catch (TcTpmException e) {
      throw new RemoteException("", e);
    } catch (TcTcsException e) {
      throw new RemoteException("", e);
    } catch (Exception e) {
      e.printStackTrace();
      throw new RemoteException("", e);
    }

    CreateEndorsementKeyPairOutParms outParms = new CreateEndorsementKeyPairOutParms();
    outParms.setResult(new UnsignedInt((Long) retval[0]));
    outParms.setEndorsementKey(retval[1] == null ? null : ((TcTpmPubkey) retval[1]).getEncoded().asByteArray());
    outParms.setChecksum(retval[2] == null ? null : ((TcTpmDigest) retval[2]).getEncoded().asByteArray());

    return outParms;
  }

  public ReadPubekOutParms readPubek(ReadPubekInParms inParms) throws RemoteException {

    long hContext = inParms.getHContext().longValue();
    TcTpmNonce antiReplay = new TcTpmNonce(TcBlobData.newByteArray(inParms.getAntiReplay()));
    Object[] retval = null;

    try {
      retval = TcTcsi.TcsipReadPubek(hContext, antiReplay);
    } catch (TcTddlException e) {
      throw new RemoteException("", e);
    } catch (TcTpmException e) {
      throw new RemoteException("", e);
    } catch (TcTcsException e) {
      throw new RemoteException("", e);
    } catch (Exception e) {
      e.printStackTrace();
      throw new RemoteException("", e);
    }

    ReadPubekOutParms outParms = new ReadPubekOutParms();
    outParms.setResult(new UnsignedInt((Long) retval[0]));
    outParms.setPubEndorsementKey(retval[1] == null ? null : ((TcTpmPubkey) retval[1]).getEncoded().asByteArray());
    outParms.setChecksum(retval[2] == null ? null : ((TcTpmDigest) retval[2]).getEncoded().asByteArray());

    return outParms;
  }

  public DisablePubekReadOutParms disablePubekRead(DisablePubekReadInParms inParms) throws RemoteException {

    long hContext = inParms.getHContext().longValue();
    TcTcsAuth inAuth1 = ConvertDataTypesServer.convertTcsAuth(inParms.getOwnerAuth());
    Object[] retval = null;

    try {
      retval = TcTcsi.TcsipDisablePubekRead(hContext, inAuth1);
    } catch (TcTddlException e) {
      throw new RemoteException("", e);
    } catch (TcTpmException e) {
      throw new RemoteException("", e);
    } catch (TcTcsException e) {
      throw new RemoteException("", e);
    } catch (Exception e) {
      e.printStackTrace();
      throw new RemoteException("", e);
    }

    DisablePubekReadOutParms outParms = new DisablePubekReadOutParms();
    outParms.setResult(new UnsignedInt((Long) retval[0]));
    outParms.setOwnerAuth(ConvertDataTypesServer.convertTcsAuth((TcTcsAuth) retval[1]));

    return outParms;
  }

  public OwnerReadPubekOutParms ownerReadPubek(OwnerReadPubekInParms inParms) throws RemoteException {

    long hContext = inParms.getHContext().longValue();
    TcTcsAuth inAuth1 = ConvertDataTypesServer.convertTcsAuth(inParms.getOwnerAuth());
    Object[] retval = null;

    try {
      retval = TcTcsi.TcsipOwnerReadPubek(hContext, inAuth1);
    } catch (TcTddlException e) {
      throw new RemoteException("", e);
    } catch (TcTpmException e) {
      throw new RemoteException("", e);
    } catch (TcTcsException e) {
      throw new RemoteException("", e);
    } catch (Exception e) {
      e.printStackTrace();
      throw new RemoteException("", e);
    }

    OwnerReadPubekOutParms outParms = new OwnerReadPubekOutParms();
    outParms.setResult(new UnsignedInt((Long) retval[0]));
    outParms.setOwnerAuth(ConvertDataTypesServer.convertTcsAuth((TcTcsAuth) retval[1]));
    outParms.setPubEndorsementKey(retval[2] == null ? null : ((TcTpmPubkey) retval[2]).getEncoded().asByteArray());

    return outParms;
  }

  public SelfTestFullOutParms selfTestFull(SelfTestFullInParms inParms) throws RemoteException {

    long hContext = inParms.getHContext().longValue();
    Object[] retval = null;

    try {
      retval = TcTcsi.TcsipSelfTestFull(hContext);
    } catch (TcTddlException e) {
      throw new RemoteException("", e);
    } catch (TcTpmException e) {
      throw new RemoteException("", e);
    } catch (TcTcsException e) {
      throw new RemoteException("", e);
    } catch (Exception e) {
      e.printStackTrace();
      throw new RemoteException("", e);
    }

    SelfTestFullOutParms outParms = new SelfTestFullOutParms();
    outParms.setResult(new UnsignedInt((Long) retval[0]));

    return outParms;
  }

  public CertifySelfTestOutParms certifySelfTest(CertifySelfTestInParms inParms) throws RemoteException {
    return null;  //TODO - No Implementation on the Client side
  }

  public ContinueSelfTestOutParms continueSelfTest(ContinueSelfTestInParms inParms) throws RemoteException {

    long hContext = inParms.getHContext().longValue();
    Object[] retval = null;

    try {
      retval = TcTcsi.TcsipContinueSelfTest(hContext);
    } catch (TcTddlException e) {
      throw new RemoteException("", e);
    } catch (TcTpmException e) {
      throw new RemoteException("", e);
    } catch (TcTcsException e) {
      throw new RemoteException("", e);
    } catch (Exception e) {
      e.printStackTrace();
      throw new RemoteException("", e);
    }

    ContinueSelfTestOutParms outParms = new ContinueSelfTestOutParms();
    outParms.setResult(new UnsignedInt((Long) retval[0]));

    return outParms;
  }

  public GetTestResultOutParms getTestResult(GetTestResultInParms inParms) throws RemoteException {

    long hContext = inParms.getHContext().longValue();
    Object[] retval = null;

    try {
      retval = TcTcsi.TcsipGetTestResult(hContext);
    } catch (TcTddlException e) {
      throw new RemoteException("", e);
    } catch (TcTpmException e) {
      throw new RemoteException("", e);
    } catch (TcTcsException e) {
      throw new RemoteException("", e);
    } catch (Exception e) {
      e.printStackTrace();
      throw new RemoteException("", e);
    }

    GetTestResultOutParms outParms = new GetTestResultOutParms();
    outParms.setResult(new UnsignedInt((Long) retval[0]));
    outParms.setOutData(retval[1] == null ? null : ((TcBlobData) retval[1]).asByteArray());

    return outParms;
  }

  public OwnerSetDisableOutParms ownerSetDisable(OwnerSetDisableInParms inParms) throws RemoteException {

    long hContext = inParms.getHContext().longValue();
    boolean disableState = ((Byte) inParms.getDisableState() != 0);
    TcTcsAuth inAuth1 = ConvertDataTypesServer.convertTcsAuth(inParms.getOwnerAuth());
    Object[] retval = null;

    try {
      retval = TcTcsi.TcsipOwnerSetDisable(hContext, disableState, inAuth1);
    } catch (TcTddlException e) {
      throw new RemoteException("", e);
    } catch (TcTpmException e) {
      throw new RemoteException("", e);
    } catch (TcTcsException e) {
      throw new RemoteException("", e);
    } catch (Exception e) {
      e.printStackTrace();
      throw new RemoteException("", e);
    }

    OwnerSetDisableOutParms outParms = new OwnerSetDisableOutParms();
    outParms.setResult(new UnsignedInt((Long) retval[0]));
    outParms.setOwnerAuth(ConvertDataTypesServer.convertTcsAuth((TcTcsAuth) retval[1]));

    return outParms;
  }

  public OwnerClearOutParms ownerClear(OwnerClearInParms inParms) throws RemoteException {

    long hContext = inParms.getHContext().longValue();
    TcTcsAuth inAuth1 = ConvertDataTypesServer.convertTcsAuth(inParms.getOwnerAuth());
    Object[] retval = null;

    try {
      retval = TcTcsi.TcsipOwnerClear(hContext, inAuth1);
    } catch (TcTddlException e) {
      throw new RemoteException("", e);
    } catch (TcTpmException e) {
      throw new RemoteException("", e);
    } catch (TcTcsException e) {
      throw new RemoteException("", e);
    } catch (Exception e) {
      e.printStackTrace();
      throw new RemoteException("", e);
    }

    OwnerClearOutParms outParms = new OwnerClearOutParms();
    outParms.setResult(new UnsignedInt((Long) retval[0]));
    outParms.setOwnerAuth(ConvertDataTypesServer.convertTcsAuth((TcTcsAuth) retval[1]));

    return outParms;
  }

  public DisableOwnerClearOutParms disableOwnerClear(DisableOwnerClearInParms inParms) throws RemoteException {

    long hContext = inParms.getHContext().longValue();
    TcTcsAuth inAuth1 = ConvertDataTypesServer.convertTcsAuth(inParms.getOwnerAuth());
    Object[] retval = null;

    try {
      retval = TcTcsi.TcsipDisableOwnerClear(hContext, inAuth1);
    } catch (TcTddlException e) {
      throw new RemoteException("", e);
    } catch (TcTpmException e) {
      throw new RemoteException("", e);
    } catch (TcTcsException e) {
      throw new RemoteException("", e);
    } catch (Exception e) {
      e.printStackTrace();
      throw new RemoteException("", e);
    }

    DisableOwnerClearOutParms outParms = new DisableOwnerClearOutParms();
    outParms.setResult(new UnsignedInt((Long) retval[0]));
    outParms.setOwnerAuth(ConvertDataTypesServer.convertTcsAuth((TcTcsAuth) retval[1]));

    return outParms;
  }

  public ForceClearOutParms forceClear(ForceClearInParms inParms) throws RemoteException {

    long hContext = inParms.getHContext().longValue();
    Object[] retval = null;
    
    try {
      retval = TcTcsi.TcsipForceClear(hContext);
    } catch (TcTddlException e) {
      throw new RemoteException("", e);
    } catch (TcTpmException e) {
      throw new RemoteException("", e);
    } catch (TcTcsException e) {
      throw new RemoteException("", e);
    } catch (Exception e) {
      e.printStackTrace();
      throw new RemoteException("", e);
    }

    ForceClearOutParms outParms = new ForceClearOutParms();
    outParms.setResult(new UnsignedInt((Long) retval[0]));

    return outParms;
  }

  public DisableForceClearOutParms disableForceClear(DisableForceClearInParms inParms) throws RemoteException {
    long hContext = inParms.getHContext().longValue();
    Object[] retval = null;

    try {
      retval = TcTcsi.TcsipDisableForceClear(hContext);
    } catch (TcTddlException e) {
      throw new RemoteException("", e);
    } catch (TcTpmException e) {
      throw new RemoteException("", e);
    } catch (TcTcsException e) {
      throw new RemoteException("", e);
    } catch (Exception e) {
      e.printStackTrace();
      throw new RemoteException("", e);
    }

    DisableForceClearOutParms outParms = new DisableForceClearOutParms();
    outParms.setResult(new UnsignedInt((Long) retval[0]));

    return outParms;
  }

  public PhysicalDisableOutParms physicalDisable(PhysicalDisableInParms inParms) throws RemoteException {

    long hContext = inParms.getHContext().longValue();
    Object[] retval = null;

    try {
      retval = TcTcsi.TcsipPhysicalDisable(hContext);
    } catch (TcTddlException e) {
      throw new RemoteException("", e);
    } catch (TcTpmException e) {
      throw new RemoteException("", e);
    } catch (TcTcsException e) {
      throw new RemoteException("", e);
    } catch (Exception e) {
      e.printStackTrace();
      throw new RemoteException("", e);
    }

    PhysicalDisableOutParms outParms = new PhysicalDisableOutParms();
    outParms.setResult(new UnsignedInt((Long) retval[0]));

    return outParms;
  }

  public PhysicalEnableOutParms physicalEnable(PhysicalEnableInParms inParms) throws RemoteException {

    long hContext = inParms.getHContext().longValue();
    Object[] retval = null;

    try {
      retval = TcTcsi.TcsipPhysicalEnable(hContext);
    } catch (TcTddlException e) {
      throw new RemoteException("", e);
    } catch (TcTpmException e) {
      throw new RemoteException("", e);
    } catch (TcTcsException e) {
      throw new RemoteException("", e);
    } catch (Exception e) {
      e.printStackTrace();
      throw new RemoteException("", e);
    }

    PhysicalEnableOutParms outParms = new PhysicalEnableOutParms();
    outParms.setResult(new UnsignedInt((Long) retval[0]));

    return outParms;
  }

  public PhysicalSetDeactivatedOutParms physicalSetDeactivated(PhysicalSetDeactivatedInParms inParms) throws RemoteException {

    long hContext = inParms.getHContext().longValue();
    boolean state = ((Byte) inParms.getState() != 0);
    Object[] retval = null;

    try {
      retval = TcTcsi.TcsipPhysicalSetDeactivated(hContext, state);
    } catch (TcTddlException e) {
      throw new RemoteException("", e);
    } catch (TcTpmException e) {
      throw new RemoteException("", e);
    } catch (TcTcsException e) {
      throw new RemoteException("", e);
    } catch (Exception e) {
      e.printStackTrace();
      throw new RemoteException("", e);
    }

    PhysicalSetDeactivatedOutParms outParms = new PhysicalSetDeactivatedOutParms();
    outParms.setResult(new UnsignedInt((Long) retval[0]));

    return outParms;
  }

  public SetTempDeactivatedOutParms setTempDeactivated(SetTempDeactivatedInParms inParms) throws RemoteException {

    long hContext = inParms.getHContext().longValue();
    Object[] retval = null;

    try {
      retval = TcTcsi.TcsipSetTempDeactivatedNoAuth(hContext);
    } catch (TcTddlException e) {
      throw new RemoteException("", e);
    } catch (TcTpmException e) {
      throw new RemoteException("", e);
    } catch (TcTcsException e) {
      throw new RemoteException("", e);
    } catch (Exception e) {
      e.printStackTrace();
      throw new RemoteException("", e);
    }

    SetTempDeactivatedOutParms outParms = new SetTempDeactivatedOutParms();
    outParms.setResult(new UnsignedInt((Long) retval[0]));

    return outParms;
  }

  public PhysicalPresenceOutParms physicalPresence(PhysicalPresenceInParms inParms) throws RemoteException {

    long hContext = inParms.getHContext().longValue();
    int physicalPresence = inParms.getFPhysicalPresence().intValue();
    Object[] retval = null;

    try {
      retval = TcTcsi.TcsipPhysicalPresence(hContext, physicalPresence);
    } catch (TcTddlException e) {
      throw new RemoteException("", e);
    } catch (TcTpmException e) {
      throw new RemoteException("", e);
    } catch (TcTcsException e) {
      throw new RemoteException("", e);
    } catch (Exception e) {
      e.printStackTrace();
      throw new RemoteException("", e);
    }

    PhysicalPresenceOutParms outParms = new PhysicalPresenceOutParms();
    outParms.setResult(new UnsignedInt((Long) retval[0]));

    return outParms;
  }

  public FieldUpgradeOutParms fieldUpgrade(FieldUpgradeInParms inParms) throws RemoteException {

    long hContext = inParms.getHContext().longValue();
    TcBlobData inData = TcBlobData.newByteArray(inParms.getDataIn());
    TcTcsAuth ownerAuth = ConvertDataTypesServer.convertTcsAuth(inParms.getOwnerAuth());

    try {
      // Not implemented yet
      TcTcsi.TcsipFieldUpgrade(hContext, inData, ownerAuth);
    } catch (TcTddlException e) {
      throw new RemoteException("", e);
    } catch (TcTpmException e) {
      throw new RemoteException("", e);
    } catch (TcTcsException e) {
      throw new RemoteException("", e);
    } catch (Exception e) {
      e.printStackTrace();
      throw new RemoteException("", e);
    }
    return null;
  }

  public FlushSpecificOutParms flushSpecific(FlushSpecificInParms inParms) throws RemoteException {
    return null;
  }

  public SetRedirectionOutParms setRedirection(SetRedirectionInParms inParms) throws RemoteException {
    
    long hContext = inParms.getHContext().longValue();
    long keyHandle = inParms.getKeyHandle().longValue();

    long redirCmd = inParms.getC1().longValue(); // FIXME
    TcBlobData inputData = null; // FIXME
    TcTcsAuth inAuth1 = ConvertDataTypesServer.convertTcsAuth(inParms.getPrivAuth());
    Object[] retval = null;
    
    try {
      retval = TcTcsi.TcsipSetRedirection(hContext, keyHandle, redirCmd, inputData, inAuth1);
    } catch (TcTddlException e) {
      throw new RemoteException("", e);
    } catch (TcTpmException e) {
      throw new RemoteException("", e);
    } catch (TcTcsException e) {
      throw new RemoteException("", e);
    } catch (Exception e) {
      e.printStackTrace();
      throw new RemoteException("", e);
    }

    SetRedirectionOutParms outParms = new SetRedirectionOutParms();
    outParms.setResult(new UnsignedInt((Long) retval[0]));
    outParms.setPrivAuth(ConvertDataTypesServer.convertTcsAuth((TcTcsAuth) retval[1]));

    return outParms;
  }

  public ResetLockValueOutParms resetLockValue(ResetLockValueInParms inParms) throws RemoteException {
    
    long hContext = inParms.getHContext().longValue();
    TcTcsAuth inAuth1 = ConvertDataTypesServer.convertTcsAuth(inParms.getOwnerAuth());
    Object[] retval = null;
    
    try {
      retval = TcTcsi.TcsipResetLockValue(hContext, inAuth1);
    } catch (TcTddlException e) {
      throw new RemoteException("", e);
    } catch (TcTpmException e) {
      throw new RemoteException("", e);
    } catch (TcTcsException e) {
      throw new RemoteException("", e);
    } catch (Exception e) {
      e.printStackTrace();
      throw new RemoteException("", e);
    }

    ResetLockValueOutParms outParms = new ResetLockValueOutParms();
    outParms.setResult(new UnsignedInt((Long) retval[0]));
    outParms.setOwnerAuth(ConvertDataTypesServer.convertTcsAuth((TcTcsAuth) retval[1]));

    return outParms;
  }

  public CreateMaintenanceArchiveOutParms createMaintenanceArchive(CreateMaintenanceArchiveInParms inParms) throws RemoteException {
    
    long hContext = inParms.getHContext().longValue();
    boolean generateRandom = ((Byte) inParms.getGenerateRandom() != 0);
    TcTcsAuth inAuth1 = ConvertDataTypesServer.convertTcsAuth(inParms.getOwnerAuth());
    Object[] retval = null;
    
    try {
      //{ outBlob.getRetCodeAsLong(), outAuth1, random, archive }
      retval = TcTcsi.TcsipCreateMaintenanceArchive(hContext, generateRandom, inAuth1);
    } catch (TcTddlException e) {
      throw new RemoteException("", e);
    } catch (TcTpmException e) {
      throw new RemoteException("", e);
    } catch (TcTcsException e) {
      throw new RemoteException("", e);
    } catch (Exception e) {
      e.printStackTrace();
      throw new RemoteException("", e);
    }

    CreateMaintenanceArchiveOutParms outParms = new CreateMaintenanceArchiveOutParms();
    outParms.setResult(new UnsignedInt((Long) retval[0]));
    outParms.setOwnerAuth(ConvertDataTypesServer.convertTcsAuth((TcTcsAuth) retval[1]));
    outParms.setRandom(retval[2] == null ? null : ((TcBlobData) retval[2]).asByteArray());
    outParms.setArchive(((TcBlobData) retval[3]).asByteArray());

    return outParms;
  }

  public LoadMaintenanceArchiveOutParms loadMaintenanceArchive(LoadMaintenanceArchiveInParms inParms) throws RemoteException {
    
    long hContext = inParms.getHContext().longValue();
    TcBlobData inData = TcBlobData.newByteArray(inParms.getDataIn());
    TcTcsAuth ownerAuth = ConvertDataTypesServer.convertTcsAuth(inParms.getOwnerAuth());
    Object[] retval = null;
    
    try {
      retval = TcTcsi.TcsipLoadMaintenanceArchive(hContext, inData, ownerAuth);
    } catch (TcTddlException e) {
      throw new RemoteException("", e);
    } catch (TcTpmException e) {
      throw new RemoteException("", e);
    } catch (TcTcsException e) {
      throw new RemoteException("", e);
    } catch (Exception e) {
      e.printStackTrace();
    }

    LoadMaintenanceArchiveOutParms outParms = new LoadMaintenanceArchiveOutParms();
//      outParms.setResult(arg0); //not an element of retval
    outParms.setDataOut(retval[0] == null ? null : ((TcBlobData) retval[0]).asByteArray());
    outParms.setOwnerAuth(ConvertDataTypesServer.convertTcsAuth((TcTcsAuth) retval[1]));

    return outParms;
  }

  public KillMaintenanceFeatureOutParms killMaintenanceFeature(KillMaintenanceFeatureInParms inParms) throws RemoteException {

    long hContext = inParms.getHContext().longValue();
    TcTcsAuth inAuth1 = ConvertDataTypesServer.convertTcsAuth(inParms.getOwnerAuth());
    Object[] retval = null;
    
    try {
      retval = TcTcsi.TcsipKillMaintenanceFeature(hContext, inAuth1);
    } catch (TcTddlException e) {
      throw new RemoteException("", e);
    } catch (TcTpmException e) {
      throw new RemoteException("", e);
    } catch (TcTcsException e) {
      throw new RemoteException("", e);
    } catch (Exception e) {
      e.printStackTrace();
      throw new RemoteException("", e);
    }
    
    KillMaintenanceFeatureOutParms outParms = new KillMaintenanceFeatureOutParms();
    outParms.setOwnerAuth(ConvertDataTypesServer.convertTcsAuth((TcTcsAuth) retval[1]));

    return outParms;
  }

  public LoadManuMaintPubOutParms loadManuMaintPub(LoadManuMaintPubInParms inParms) throws RemoteException {
    
    long hContext = inParms.getHContext().longValue();
    TcTpmNonce antiReplay = new TcTpmNonce(TcBlobData.newByteArray(inParms.getAntiReplay()));
    TcTpmPubkey pubKey = inParms.getPubKey() == null ? null : new TcTpmPubkey(TcBlobData.newByteArray(inParms.getPubKey()));
    Object[] retval = null;

    try {
      retval = TcTcsi.TcsipLoadManuMaintPub(hContext, antiReplay, pubKey);
    } catch (TcTddlException e) {
      throw new RemoteException("", e);
    } catch (TcTpmException e) {
      throw new RemoteException("", e);
    } catch (TcTcsException e) {
      throw new RemoteException("", e);
    } catch (Exception e) {
      e.printStackTrace();
      throw new RemoteException("", e);
    }

    LoadManuMaintPubOutParms outParms = new LoadManuMaintPubOutParms();
    outParms.setResult(new UnsignedInt((Long) retval[0]));
    outParms.setChecksum(retval[1] == null ? null : ((TcTpmDigest) retval[1]).getEncoded().asByteArray());

    return outParms;

  }

  public ReadManuMaintPubOutParms readManuMaintPub(  ReadManuMaintPubInParms inParms) throws RemoteException {
    
    long hContext = inParms.getHContext().longValue();
    TcTpmNonce antiReplay = new TcTpmNonce(TcBlobData.newByteArray(inParms.getAntiReplay()));
    Object[] retval = null;
    
    try {
      retval = TcTcsi.TcsipReadManuMaintPub(hContext, antiReplay);
    } catch (TcTddlException e) {
      throw new RemoteException("", e);
    } catch (TcTpmException e) {
      throw new RemoteException("", e);
    } catch (TcTcsException e) {
      throw new RemoteException("", e);
    } catch (Exception e) {
      e.printStackTrace();
      throw new RemoteException("", e);
    }
    
    ReadManuMaintPubOutParms outParms = new ReadManuMaintPubOutParms();
    outParms.setResult(new UnsignedInt((Long) retval[0]));
    outParms.setChecksum(retval[1] == null ? null : ((TcTpmDigest) retval[1]).getEncoded().asByteArray());

    return outParms;
  }

  public Quote2OutParms quote2( Quote2InParms inParms) throws RemoteException {
    
    long hContext = inParms.getHContext().longValue();
    long keyHandle = inParms.getKeyHandle().longValue();
    TcTpmNonce externalData = new TcTpmNonce(TcBlobData.newByteArray(inParms.getAntiReplay()));
    TcTpmPcrSelection targetPCR = new TcTpmPcrSelection(TcBlobData.newByteArray(inParms.getPcrTarget()));
    boolean addVersion = ((Byte) inParms.getAddVersion() != 0);
    TcTcsAuth inAuth1 = ConvertDataTypesServer.convertTcsAuth(inParms.getPrivAuth());
    Object[] retval = null;
    
    try {
      retval = TcTcsi.TcsipQuote2(hContext, keyHandle, externalData, targetPCR, addVersion, inAuth1);
    } catch (TcTddlException e) {
      throw new RemoteException("", e);
    } catch (TcTpmException e) {
      throw new RemoteException("", e);
    } catch (TcTcsException e) {
      throw new RemoteException("", e);
    } catch (Exception e) {
      e.printStackTrace();
      throw new RemoteException("", e);
    }
    
    Quote2OutParms outParms = new Quote2OutParms();
    outParms.setResult(new UnsignedInt((Long) retval[0]));
    outParms.setPrivAuth(ConvertDataTypesServer.convertTcsAuth((TcTcsAuth) retval[1]));
    outParms.setPcrData(((TcTpmPcrInfoShort) retval[2]).getEncoded().asByteArray());
    outParms.setVersionInfo((retval[3] == null) ? null : ((TcTpmCapVersionInfo) retval[3]).getEncoded().asByteArray());
    outParms.setSig(((TcBlobData) retval[4]).asByteArray());

    return outParms;
  }

  public SealxOutParms sealx(SealxInParms inParms) throws RemoteException {
    
    long hContext = inParms.getHContext().longValue();
    long keyHandle = inParms.getKeyHandle().longValue();
    TcTpmEncauth encAuth = new TcTpmEncauth(TcBlobData.newByteArray(inParms.getEncAuth()));
    TcTpmPcrInfoLong pcrInfo = new TcTpmPcrInfoLong(TcBlobData.newByteArray(inParms.getPcrInfo()));
    TcBlobData inData = TcBlobData.newByteArray(inParms.getInData());
    TcTcsAuth inAuth1 = ConvertDataTypesServer.convertTcsAuth(inParms.getPubAuth());
    Object[] retval = null;
    
    try {
      retval = TcTcsi.TcsipSealx(hContext, keyHandle, encAuth, pcrInfo, inData, inAuth1);
    } catch (TcTddlException e) {
      throw new RemoteException("", e);
    } catch (TcTpmException e) {
      throw new RemoteException("", e);
    } catch (TcTcsException e) {
      throw new RemoteException("", e);
    } catch (Exception e) {
      e.printStackTrace();
      throw new RemoteException("", e);
    }
    
    SealxOutParms outParms = new SealxOutParms();
    outParms.setResult(new UnsignedInt((Long) retval[0]));
    outParms.setPubAuth(ConvertDataTypesServer.convertTcsAuth((TcTcsAuth) retval[1]));
    outParms.setSealedData(retval[2] == null ? null : ((TcITpmStoredData) retval[2]).getEncoded().asByteArray());

    return outParms;
  }

  public LoadKey2ByBlobOutParms loadKey2ByBlob(LoadKey2ByBlobInParms inParms) throws RemoteException {
    
    long hContext = inParms.getHContext().longValue();
    long UnwrappingKey = inParms.getHUnwrappingKey().longValue();

    TcTpmKey wrappedKeyBlob = new TcTpmKey(TcBlobData.newByteArray(inParms.getRgbWrappedKeyBlob()));
    if (wrappedKeyBlob.getPubKey().getKey() == null) {
      wrappedKeyBlob.setPubKey(null);
    }

    TcTcsAuth inAuth = ConvertDataTypesServer.convertTcsAuth(inParms.getPAuth());
    Object[] retval = null;
    
    try {
      retval = TcTcsi.TcsipLoadKey2ByBlob(hContext, UnwrappingKey, wrappedKeyBlob, inAuth);
    } catch (TcTddlException e) {
      throw new RemoteException("", e);
    } catch (TcTpmException e) {
      throw new RemoteException("", e);
    } catch (TcTcsException e) {
      throw new RemoteException("", e);
    } catch (Exception e) {
      e.printStackTrace();
      throw new RemoteException("", e);
    }
    
    LoadKey2ByBlobOutParms outParms = new LoadKey2ByBlobOutParms();
    outParms.setResult(new UnsignedInt((Long) retval[0]));
    outParms.setPAuth(ConvertDataTypesServer.convertTcsAuth((TcTcsAuth) retval[1]));
    outParms.setPhKeyTCSI(new UnsignedInt((Long) (retval[2])));

    return outParms;
  }

  public CertifyKey2OutParms certifyKey2(CertifyKey2InParms inParms) throws RemoteException {
    
    long hContext = inParms.getHContext().longValue();
    long certHandle = inParms.getCertHandle().longValue();
    long keyHandle = inParms.getKeyHandle().longValue();
    TcTpmDigest migrationPubDigest = new TcTpmDigest(TcBlobData.newByteArray(inParms.getMSAdigest()));
    TcTpmNonce antiReplay = new TcTpmNonce(TcBlobData.newByteArray(inParms.getAntiReplay()));
    TcTcsAuth inAuth1 = ConvertDataTypesServer.convertTcsAuth(inParms.getCertAuth());
    TcTcsAuth inAuth2 = ConvertDataTypesServer.convertTcsAuth(inParms.getKeyAuth());
    Object[] retval = null;
    
    try {
      retval = TcTcsi.TcsipCertifyKey2(hContext, certHandle, keyHandle, migrationPubDigest, antiReplay, inAuth1, inAuth2);
    } catch (TcTddlException e) {
      throw new RemoteException("", e);
    } catch (TcTpmException e) {
      throw new RemoteException("", e);
    } catch (TcTcsException e) {
      throw new RemoteException("", e);
    } catch (Exception e) {
      e.printStackTrace();
      throw new RemoteException("", e);
    }
    
    CertifyKey2OutParms outParms = new CertifyKey2OutParms();
    outParms.setResult(new UnsignedInt((Long) retval[0]));
    outParms.setCertAuth(ConvertDataTypesServer.convertTcsAuth((TcTcsAuth) retval[1]));
    outParms.setKeyAuth(ConvertDataTypesServer.convertTcsAuth((TcTcsAuth) retval[2]));
    outParms.setCertifyInfo(retval[3] == null ? null : ((TcTpmCertifyInfo) retval[3]).getEncoded().asByteArray());
    outParms.setOutData(retval[4] == null ? null : ((TcBlobData) retval[4]).asByteArray());

    return outParms;
  }

  public SetTempDeactivated2OutParms setTempDeactivated2(SetTempDeactivated2InParms inParms) throws RemoteException {

    long hContext = inParms.getHContext().longValue();
    TcTcsAuth inAuth1 = ConvertDataTypesServer.convertTcsAuth(inParms.getPOperatorAuth());
    Object[] retval = null;

    try {
      retval = TcTcsi.TcsipSetTempDeactivated(hContext, inAuth1);
    } catch (TcTddlException e) {
      throw new RemoteException("", e);
    } catch (TcTpmException e) {
      throw new RemoteException("", e);
    } catch (TcTcsException e) {
      throw new RemoteException("", e);
    } catch (Exception e) {
      e.printStackTrace();
      throw new RemoteException("", e);
    }

    SetTempDeactivated2OutParms outParms = new SetTempDeactivated2OutParms();
    outParms.setResult(new UnsignedInt((Long) retval[0]));
    outParms.setPOperatorAuth(ConvertDataTypesServer.convertTcsAuth((TcTcsAuth) retval[1]));

    return outParms;
  }

  public OwnerReadInternalPubOutParms ownerReadInternalPub(OwnerReadInternalPubInParms inParms) throws RemoteException {
    
    long hContext = inParms.getHContext().longValue();
    long keyHandle = inParms.getHKey().longValue();
    TcTcsAuth inAuth1 = ConvertDataTypesServer.convertTcsAuth(inParms.getPOwnerAuth());
    Object[] retval = null;
    
    try {
      retval = TcTcsi.TcsipOwnerReadInternalPub(hContext, keyHandle, inAuth1);
    } catch (TcTddlException e) {
      throw new RemoteException("", e);
    } catch (TcTpmException e) {
      throw new RemoteException("", e);
    } catch (TcTcsException e) {
      throw new RemoteException("", e);
    } catch (Exception e) {
      e.printStackTrace();
      throw new RemoteException("", e);
    }

    OwnerReadInternalPubOutParms outParms = new OwnerReadInternalPubOutParms();
    outParms.setResult(new UnsignedInt((Long) retval[0]));
    outParms.setPOwnerAuth(ConvertDataTypesServer.convertTcsAuth((TcTcsAuth) retval[1]));
    outParms.setPpbPubKeyData(retval[2] == null ? null : ((TcTpmPubkey) retval[2]).getEncoded().asByteArray());

    return outParms;
  }

  public DSAPOutParms DSAP(DSAPInParms inParms) throws RemoteException {
    long hContext = inParms.getHContext().longValue();
    int entityType = inParms.getEntityType().intValue();
    long keyHandle = inParms.getKeyHandle().longValue();
    TcTpmNonce nonceOddDSAP = new TcTpmNonce(TcBlobData.newByteArray(inParms.getNonceOddDSAP()));
    TcBlobData entityValue = TcBlobData.newByteArray(inParms.getEntityValue());
    Object[] retval = null;
    
    try {
      //{ outBlob.getRetCodeAsLong(), new Long(authHandle), nonceEven, nonceEvenDSAP };
      retval = TcTcsi.TcsipDSAP(hContext, entityType, keyHandle, nonceOddDSAP, entityValue);
    } catch (TcTddlException e) {
      throw new RemoteException("", e);
    } catch (TcTpmException e) {
      throw new RemoteException("", e);
    } catch (TcTcsException e) {
      throw new RemoteException("", e);
    } catch (Exception e) {
      e.printStackTrace();
      throw new RemoteException("", e);
    }
    
    DSAPOutParms outParms = new DSAPOutParms();
    outParms.setResult(new UnsignedInt((Long) retval[0]));
    outParms.setAuthHandle(new UnsignedInt((Long) retval[1]));
    outParms.setNonceEven(retval[2] == null ? null : ((TcTpmNonce) retval[2]).getEncoded().asByteArray());
    outParms.setNonceEvenDSAP(retval[3] == null ? null : ((TcTpmNonce) retval[3]).getEncoded().asByteArray());

    return outParms;
  }

  public Delegate_ManageOutParms delegate_Manage(Delegate_ManageInParms inParms) throws RemoteException {
    
    long hContext = inParms.getHContext().longValue();
    long familyID = inParms.getFamilyID().longValue();
    long opCode = inParms.getOpFlag().longValue();
    TcBlobData opData = TcBlobData.newByteArray(inParms.getOpData());
    TcTcsAuth inAuth1 = ConvertDataTypesServer.convertTcsAuth(inParms.getOwnerAuth());
    Object[] retval = null;

    try {
      //{ outBlob.getRetCodeAsLong(), outAuth1, retData }
      retval = TcTcsi.TcsipDelegateManage(hContext, familyID, opCode, opData, inAuth1);
    } catch (TcTddlException e) {
      throw new RemoteException("", e);
    } catch (TcTpmException e) {
      throw new RemoteException("", e);
    } catch (TcTcsException e) {
      throw new RemoteException("", e);
    } catch (Exception e) {
      e.printStackTrace();
      throw new RemoteException("", e);
    }

    Delegate_ManageOutParms outParms = new Delegate_ManageOutParms();
    outParms.setResult(new UnsignedInt((Long) retval[0]));
    outParms.setOwnerAuth(ConvertDataTypesServer.convertTcsAuth((TcTcsAuth) retval[1]));
    outParms.setRetData(retval[2] == null ? null : ((TcBlobData) retval[2]).asByteArray());

    return outParms;
  }

  public Delegate_CreateKeyDelegationOutParms delegate_CreateKeyDelegation(Delegate_CreateKeyDelegationInParms inParms) throws RemoteException {
    
    long hContext = inParms.getHContext().longValue();
    long keyHandle = inParms.getHKey().longValue();
    TcTpmDelegatePublic publicInfo = new TcTpmDelegatePublic(TcBlobData.newByteArray(inParms.getPublicInfo()));
    TcTpmEncauth encDelAuth = new TcTpmEncauth(TcBlobData.newByteArray(inParms.getEncDelAuth()));
    TcTcsAuth key = new TcTcsAuth();
    Object[] retval = null;
    
    try {
      //{ outBlob.getRetCodeAsLong(), outAuth1, blob }
      retval = TcTcsi.TcsipDelegateCreateKeyDelegation(hContext, keyHandle, publicInfo, encDelAuth, key);
    } catch (TcTddlException e) {
      throw new RemoteException("", e);
    } catch (TcTpmException e) {
      throw new RemoteException("", e);
    } catch (TcTcsException e) {
      throw new RemoteException("", e);
    } catch (Exception e) {
      e.printStackTrace();
      throw new RemoteException("", e);
    }

    Delegate_CreateKeyDelegationOutParms outParms = new Delegate_CreateKeyDelegationOutParms();
    outParms.setResult(new UnsignedInt((Long) retval[0]));
    outParms.setKeyAuth(ConvertDataTypesServer.convertTcsAuth((TcTcsAuth) retval[1]));
    outParms.setBlob(((TcTpmDelegateKeyBlob) retval[2]).getEncoded().asByteArray());

    return outParms;
  }

  public Delegate_CreateOwnerDelegationOutParms delegate_CreateOwnerDelegation(Delegate_CreateOwnerDelegationInParms inParms) throws RemoteException {
    
    long hContext = inParms.getHContext().longValue();
    boolean increment = ((Byte) inParms.getIncrement() != 0);
    TcTpmDelegatePublic publicInfo = new TcTpmDelegatePublic(TcBlobData.newByteArray(inParms.getPublicInfo()));
    TcTpmEncauth encDelAuth = new TcTpmEncauth(TcBlobData.newByteArray(inParms.getEncDelAuth()));
    TcTcsAuth ownerAuth = ConvertDataTypesServer.convertTcsAuth(inParms.getOwnerAuth());
    Object[] retval = null;
    
    try {
      retval = TcTcsi.TcsipDelegateCreateOwnerDelegation(hContext, increment, publicInfo, encDelAuth, ownerAuth);
    } catch (TcTddlException e) {
      throw new RemoteException("", e);
    } catch (TcTpmException e) {
      throw new RemoteException("", e);
    } catch (TcTcsException e) {
      throw new RemoteException("", e);
    } catch (Exception e) {
      e.printStackTrace();
      throw new RemoteException("", e);
    }

    Delegate_CreateOwnerDelegationOutParms outParms = new Delegate_CreateOwnerDelegationOutParms();
    outParms.setResult(new UnsignedInt((Long) retval[0]));
    outParms.setOwnerAuth(ConvertDataTypesServer.convertTcsAuth((TcTcsAuth) retval[1]));
    outParms.setBlob(((TcTpmDelegateKeyBlob) retval[2]).getEncoded().asByteArray());

    return outParms;
  }

  public Delegate_LoadOwnerDelegationOutParms delegate_LoadOwnerDelegation(Delegate_LoadOwnerDelegationInParms inParms) throws RemoteException {
    
    long hContext = inParms.getHContext().longValue();
    long index = inParms.getIndex().longValue();
    TcTpmDelegateOwnerBlob blob = new TcTpmDelegateOwnerBlob(TcBlobData.newByteArray(inParms.getBlob()));
    TcTcsAuth inAuth1 = ConvertDataTypesServer.convertTcsAuth(inParms.getOwnerAuth());
    Object[] retval = null;
    
    try {
      retval = TcTcsi.TcsipDelegateLoadOwnerDelegation(hContext, index, blob, inAuth1);
    } catch (TcTddlException e) {
      throw new RemoteException("", e);
    } catch (TcTpmException e) {
      throw new RemoteException("", e);
    } catch (TcTcsException e) {
      throw new RemoteException("", e);
    } catch (Exception e) {
      e.printStackTrace();
      throw new RemoteException("", e);
    }

    Delegate_LoadOwnerDelegationOutParms outParms = new Delegate_LoadOwnerDelegationOutParms();
    outParms.setResult(new UnsignedInt((Long) retval[0]));
    outParms.setOwnerAuth(ConvertDataTypesServer.convertTcsAuth((TcTcsAuth) retval[1]));

    return outParms;
  }

  public Delegate_UpdateVerificationCountOutParms delegate_UpdateVerificationCount(Delegate_UpdateVerificationCountInParms inParms) throws RemoteException {
    
    long hContext = inParms.getHContext().longValue();
    TcBlobData inputData = TcBlobData.newByteArray(inParms.getInput());
    TcTcsAuth inAuth1 = ConvertDataTypesServer.convertTcsAuth(inParms.getOwnerAuth());
    Object[] retval = null;
    
    try {
      retval = TcTcsi.TcsipDelegateUpdateVerificationCount(hContext, inputData, inAuth1);
    } catch (TcTddlException e) {
      throw new RemoteException("", e);
    } catch (TcTpmException e) {
      throw new RemoteException("", e);
    } catch (TcTcsException e) {
      throw new RemoteException("", e);
    } catch (Exception e) {
      e.printStackTrace();
      throw new RemoteException("", e);
    }

    Delegate_UpdateVerificationCountOutParms outParms = new Delegate_UpdateVerificationCountOutParms();
    outParms.setResult(new UnsignedInt((Long) retval[0]));
    outParms.setOutput(retval[1] == null ? null : ((TcBlobData) retval[1]).asByteArray());
    outParms.setOwnerAuth(ConvertDataTypesServer.convertTcsAuth((TcTcsAuth) retval[2]));

    return outParms;
  }

  public Delegate_VerifyDelegationOutParms delegate_VerifyDelegation( Delegate_VerifyDelegationInParms inParms) throws RemoteException {
    
    long hContext = inParms.getHContext().longValue();
    TcBlobData delegation = TcBlobData.newByteArray(inParms.getDelegate());
    Object[] retval = null;
    
    try {
      retval = TcTcsi.TcsipDelegateVerifyDelegation(hContext, delegation);
    } catch (TcTddlException e) {
      throw new RemoteException("", e);
    } catch (TcTpmException e) {
      throw new RemoteException("", e);
    } catch (TcTcsException e) {
      throw new RemoteException("", e);
    } catch (Exception e) {
      e.printStackTrace();
      throw new RemoteException("", e);
    }

    Delegate_VerifyDelegationOutParms outParms = new Delegate_VerifyDelegationOutParms();
    outParms.setResult(new UnsignedInt((Long) retval[0]));

    return outParms;
  }

  public Delegate_ReadTableOutParms delegate_ReadTable( Delegate_ReadTableInParms inParms) throws RemoteException {
    
    long hContext = inParms.getHContext().longValue();
    Object[] retval = null;
    
    try {
      retval = TcTcsi.TcsipDelegateReadTable(hContext);
    } catch (TcTddlException e) {
      throw new RemoteException("", e);
    } catch (TcTpmException e) {
      throw new RemoteException("", e);
    } catch (TcTcsException e) {
      throw new RemoteException("", e);
    } catch (Exception e) {
      e.printStackTrace();
      throw new RemoteException("", e);
    }

    Delegate_ReadTableOutParms outParms = new Delegate_ReadTableOutParms();
    outParms.setResult(new UnsignedInt((Long) retval[0]));
    outParms.setPpFamilyTable(retval[1] == null ? null : ((TcBlobData) retval[1]).asByteArray());
    outParms.setPpDelegateTable(retval[2] == null ? null : ((TcBlobData) retval[2]).asByteArray());

    return outParms;
  }

  public NV_DefineOrReleaseSpaceOutParms NV_DefineOrReleaseSpace( NV_DefineOrReleaseSpaceInParms inParms) throws RemoteException {
    
    long hContext = inParms.getHContext().longValue();
    TcTpmNvDataPublic pubInfo = new TcTpmNvDataPublic(TcBlobData.newByteArray(inParms.getPPubInfo()));
    TcTpmEncauth encAuth = new TcTpmEncauth(TcBlobData.newByteArray(inParms.getEncAuth()));
    TcTcsAuth inAuth1 = ConvertDataTypesServer.convertTcsAuth(inParms.getPAuth());
    Object[] retval = null;
    
    try {
      retval = TcTcsi.TcsipNvDefineOrReleaseSpace(hContext, pubInfo, encAuth, inAuth1);
    } catch (TcTddlException e) {
      throw new RemoteException("", e);
    } catch (TcTpmException e) {
      throw new RemoteException("", e);
    } catch (TcTcsException e) {
      throw new RemoteException("", e);
    } catch (Exception e) {
      e.printStackTrace();
      throw new RemoteException("", e);
    }

    NV_DefineOrReleaseSpaceOutParms outParms = new NV_DefineOrReleaseSpaceOutParms();
    outParms.setResult(new UnsignedInt((Long) retval[0]));
    outParms.setPAuth(ConvertDataTypesServer.convertTcsAuth((TcTcsAuth) retval[1]));

    return outParms;
  }

  public NV_WriteValueOutParms NV_WriteValue( NV_WriteValueInParms inParms) throws RemoteException {
    
    long hContext = inParms.getHContext().longValue();
    long nvIndex = inParms.getHNVStore().longValue();
    long offset = inParms.getOffset().longValue();
    TcBlobData data = TcBlobData.newByteArray(inParms.getRgbDataToWrite());
    TcTcsAuth inAuth1 = ConvertDataTypesServer.convertTcsAuth(inParms.getPrivAuth());
    Object[] retval = null;
    
    try {
      retval = TcTcsi.TcsipNvWriteValue(hContext, nvIndex, offset, data, inAuth1);
    } catch (TcTddlException e) {
      throw new RemoteException("", e);
    } catch (TcTpmException e) {
      throw new RemoteException("", e);
    } catch (TcTcsException e) {
      throw new RemoteException("", e);
    } catch (Exception e) {
      e.printStackTrace();
      throw new RemoteException("", e);
    }

    NV_WriteValueOutParms outParms = new NV_WriteValueOutParms();
    outParms.setResult(new UnsignedInt((Long) retval[0]));
    outParms.setPrivAuth(ConvertDataTypesServer.convertTcsAuth((TcTcsAuth) retval[1]));

    return outParms;
  }

  public NV_WriteValueAuthOutParms NV_WriteValueAuth( NV_WriteValueAuthInParms inParms) throws RemoteException {
    
    long hContext = inParms.getHContext().longValue();
    long nvIndex = inParms.getHNVStore().longValue();
    long offset = inParms.getOffset().longValue();
    TcBlobData data = TcBlobData.newByteArray(inParms.getRgbDataToWrite());
    TcTcsAuth inAuth1 = ConvertDataTypesServer.convertTcsAuth(inParms.getNVAuth());
    Object[] retval = null;
    
    try {
      retval = TcTcsi.TcsipNvWriteValueAuth(hContext, nvIndex, offset, data, inAuth1);
    } catch (TcTddlException e) {
      throw new RemoteException("", e);
    } catch (TcTpmException e) {
      throw new RemoteException("", e);
    } catch (TcTcsException e) {
      throw new RemoteException("", e);
    } catch (Exception e) {
      e.printStackTrace();
      throw new RemoteException("", e);
    }

    NV_WriteValueAuthOutParms outParms = new NV_WriteValueAuthOutParms();
    outParms.setResult(new UnsignedInt((Long) retval[0]));
    outParms.setNVAuth(ConvertDataTypesServer.convertTcsAuth((TcTcsAuth) retval[1]));

    return outParms;
  }

  public NV_ReadValueOutParms NV_ReadValue(NV_ReadValueInParms inParms) throws RemoteException {
    
    long hContext = inParms.getHContext().longValue();
    long nvIndex = inParms.getHNVStore().longValue();
    long offset = inParms.getOffset().longValue();
    long dataSz = inParms.getPulDataLength().longValue();
    TcTcsAuth inAuth1 = inParms.getPrivAuth() == null ? null : ConvertDataTypesServer.convertTcsAuth(inParms.getPrivAuth());
    Object[] retval = null;
    
    try {
      retval = TcTcsi.TcsipNvReadValue(hContext, nvIndex, offset, dataSz, inAuth1);
    } catch (TcTddlException e) {
      throw new RemoteException("", e);
    } catch (TcTpmException e) {
      throw new RemoteException("", e);
    } catch (TcTcsException e) {
      throw new RemoteException("", e);
    } catch (Exception e) {
      e.printStackTrace();
      throw new RemoteException("", e);
    }

    NV_ReadValueOutParms outParms = new NV_ReadValueOutParms();
    outParms.setResult(new UnsignedInt((Long) retval[0]));
    outParms.setPrivAuth(retval[1] == null ? null : ConvertDataTypesServer.convertTcsAuth((TcTcsAuth) retval[1]));
    outParms.setRgbDataRead(retval[2] == null ? null : ((TcBlobData) retval[2]).asByteArray());

    return outParms;
  }

  public NV_ReadValueAuthOutParms NV_ReadValueAuth(NV_ReadValueAuthInParms inParms) throws RemoteException {
    
    long hContext = inParms.getHContext().longValue();
    long nvIndex = inParms.getHNVStore().longValue();
    long offset = inParms.getOffset().longValue();
    long dataSz = inParms.getPulDataLength().longValue();
    TcTcsAuth inAuth1 = ConvertDataTypesServer.convertTcsAuth(inParms.getNVAuth());
    Object[] retval = null;
    
    try {
      retval = TcTcsi.TcsipNvReadValueAuth(hContext, nvIndex, offset, dataSz, inAuth1);
    } catch (TcTddlException e) {
      throw new RemoteException("", e);
    } catch (TcTpmException e) {
      throw new RemoteException("", e);
    } catch (TcTcsException e) {
      throw new RemoteException("", e);
    } catch (Exception e) {
      e.printStackTrace();
      throw new RemoteException("", e);
    }

    NV_ReadValueAuthOutParms outParms = new NV_ReadValueAuthOutParms();
    outParms.setResult(new UnsignedInt((Long) retval[0]));
    outParms.setNVAuth(ConvertDataTypesServer.convertTcsAuth((TcTcsAuth) retval[1]));
    outParms.setRgbDataRead(retval[2] == null ? null : ((TcBlobData) retval[2]).asByteArray());

    return outParms;
  }

  public TPM_DAA_JoinOutParms TPM_DAA_Join(TPM_DAA_JoinInParms inParms) throws RemoteException {

    long hContext = inParms.getHContext().longValue();
    long handle = inParms.getHandle().longValue();
    short stage = new Short(inParms.getStage());
    TcBlobData inputData0 = TcBlobData.newByteArray(inParms.getInputData0());
    TcBlobData inputData1 = TcBlobData.newByteArray(inParms.getInputData1());
    TcTcsAuth ownerAuth = ConvertDataTypesServer.convertTcsAuth(inParms.getOwnerAuth());
    Object[] retval = null;
    
    try {
      retval = TcTcsi.TcsipDaaJoin(hContext, handle, stage, inputData0, inputData1, ownerAuth);
    } catch (TcTddlException e) {
      throw new RemoteException("", e);
    } catch (TcTpmException e) {
      throw new RemoteException("", e);
    } catch (TcTcsException e) {
      throw new RemoteException("", e);
    } catch (Exception e) {
      e.printStackTrace();
      throw new RemoteException("", e);
    }

    TPM_DAA_JoinOutParms outParms = new TPM_DAA_JoinOutParms();
    outParms.setResult(new UnsignedInt((Long) retval[0]));
    outParms.setOwnerAuth(ConvertDataTypesServer.convertTcsAuth((TcTcsAuth) retval[1]));
    outParms.setOutputData(retval[2] == null ? null : ((TcBlobData) retval[2]).asByteArray());

    return outParms;
  }

  public SignOutParms sign(SignInParms inParms) throws RemoteException {
    
    long hContext = inParms.getHContext().longValue();
    long keyHandle = inParms.getKeyHandle().longValue();
    TcBlobData areaToSign = TcBlobData.newByteArray(inParms.getAreaToSign());
    TcTcsAuth inAuth1 = ConvertDataTypesServer.convertTcsAuth(inParms.getPrivAuth());
    Object[] retval = null;
    
    try {
      retval = TcTcsi.TcsipSign(hContext, keyHandle, areaToSign, inAuth1);
    } catch (TcTddlException e) {
      throw new RemoteException("", e);
    } catch (TcTpmException e) {
      throw new RemoteException("", e);
    } catch (TcTcsException e) {
      throw new RemoteException("", e);
    } catch (Exception e) {
      e.printStackTrace();
      throw new RemoteException("", e);
    }

    SignOutParms outParms = new SignOutParms();
    outParms.setResult(new UnsignedInt((Long) retval[0]));
    outParms.setPrivAuth(ConvertDataTypesServer.convertTcsAuth((TcTcsAuth) retval[1]));
    outParms.setSig(((TcBlobData) retval[2]).asByteArray());

    return outParms;
  }

  public TPM_DAA_SignOutParms TPM_DAA_Sign(TPM_DAA_SignInParms inParms) throws RemoteException {
    
    long hContext = inParms.getHContext().longValue();
    long handle = inParms.getHandle().longValue();
    short stage = new Short(inParms.getStage());
    TcBlobData inputData0 = TcBlobData.newByteArray(inParms.getInputData0());
    TcBlobData inputData1 = TcBlobData.newByteArray(inParms.getInputData1());
    TcTcsAuth ownerAuth = ConvertDataTypesServer.convertTcsAuth(inParms.getOwnerAuth());
    Object[] retval = null;
    
    try {
      retval = TcTcsi.TcsipDaaSign(hContext, handle, stage, inputData0, inputData1, ownerAuth);
    } catch (TcTddlException e) {
      throw new RemoteException("", e);
    } catch (TcTpmException e) {
      throw new RemoteException("", e);
    } catch (TcTcsException e) {
      throw new RemoteException("", e);
    } catch (Exception e) {
      e.printStackTrace();
      throw new RemoteException("", e);
    }

    TPM_DAA_SignOutParms outParms = new TPM_DAA_SignOutParms();
    outParms.setResult(new UnsignedInt((Long) retval[0]));
    outParms.setOwnerAuth(ConvertDataTypesServer.convertTcsAuth((TcTcsAuth) retval[1]));
    outParms.setOutputData(retval[2] == null ? null : ((TcBlobData) retval[2]).asByteArray());

    return outParms;
  }

  public SetCapabilityOutParms setCapability(SetCapabilityInParms inParms) throws RemoteException {
    
    long hContext = inParms.getHContext().longValue();
    long capArea = inParms.getCapArea().longValue();
    TcBlobData subCap = TcBlobData.newByteArray(inParms.getSubCap());
    TcBlobData setValue = TcBlobData.newByteArray(inParms.getValue());
    TcTcsAuth inAuth1 = ConvertDataTypesServer.convertTcsAuth(inParms.getOwnerAuth());
    Object[] retval = null;
    
    try {
      retval = TcTcsi.TcsipSetCapability(hContext, capArea, subCap, setValue, inAuth1);
    } catch (TcTddlException e) {
      throw new RemoteException("", e);
    } catch (TcTpmException e) {
      throw new RemoteException("", e);
    } catch (TcTcsException e) {
      throw new RemoteException("", e);
    } catch (Exception e) {
      e.printStackTrace();
      throw new RemoteException("", e);
    }

    SetCapabilityOutParms outParms = new SetCapabilityOutParms();
    outParms.setResult(new UnsignedInt((Long) retval[0]));
    outParms.setOwnerAuth(ConvertDataTypesServer.convertTcsAuth((TcTcsAuth) retval[1]));

    return outParms;
  }

  public GetAuditDigestOutParms getAuditDigest(GetAuditDigestInParms inParms) throws RemoteException {
    
    long hContext = inParms.getHContext().longValue();
    long startOrdinal = inParms.getStartOrdinal().longValue();
    Object[] retval = null;
    
    try {
      retval = TcTcsi.TcsipGetAuditDigest(hContext, startOrdinal);
    } catch (TcTddlException e) {
      throw new RemoteException("", e);
    } catch (TcTpmException e) {
      throw new RemoteException("", e);
    } catch (TcTcsException e) {
      throw new RemoteException("", e);
    } catch (Exception e) {
      e.printStackTrace();
      throw new RemoteException("", e);
    }

    GetAuditDigestOutParms outParms = new GetAuditDigestOutParms();
    outParms.setResult(new UnsignedInt((Long) retval[0]));
    outParms.setCounterValue(((TcBlobData) retval[1]).asByteArray());
    outParms.setAuditDigest(retval[2] == null ? null : ((TcTpmDigest) retval[2]).getEncoded().asByteArray());
    outParms.setMore((Boolean) retval[3] ? (byte) 1 : (byte) 0);
    byte[] tempByte = ((TcBlobData) retval[4]).asByteArray();

    UnsignedInt[] tempUnsigned = new UnsignedInt[tempByte.length];
    for (int i = 0; i < tempByte.length; i++) {
      tempUnsigned[i] = new UnsignedInt(tempByte[i]);
    }
    outParms.setOrdList(tempUnsigned);

    return outParms;
  }

  public GetAuditDigestSignedOutParms getAuditDigestSigned(GetAuditDigestSignedInParms inParms) throws RemoteException {
    
    long hContext = inParms.getHContext().longValue();
    long keyHandle = inParms.getKeyHandle().longValue();
    boolean closeAudit = ((Byte) inParms.getCloseAudit() != 0);
    TcTpmNonce antiReplay = new TcTpmNonce(TcBlobData.newByteArray(inParms.getAntiReplay()));
    TcTcsAuth inAuth1 = ConvertDataTypesServer.convertTcsAuth(inParms.getPrivAuth());
    Object[] retval = null;
    
    try {
      retval = TcTcsi.TcsipGetAuditDigestSigned(hContext, keyHandle, closeAudit, antiReplay, inAuth1);
    } catch (TcTddlException e) {
      throw new RemoteException("", e);
    } catch (TcTpmException e) {
      throw new RemoteException("", e);
    } catch (TcTcsException e) {
      throw new RemoteException("", e);
    } catch (Exception e) {
      e.printStackTrace();
      throw new RemoteException("", e);
    }

    GetAuditDigestSignedOutParms outParms = new GetAuditDigestSignedOutParms();
    outParms.setResult(new UnsignedInt((Long) retval[0]));
    outParms.setPrivAuth(ConvertDataTypesServer.convertTcsAuth((TcTcsAuth) retval[1]));
    outParms.setCounterValue(((TcBlobData) retval[2]).asByteArray());
    outParms.setAuditDigest(retval[3] == null ? null : ((TcTpmDigest) retval[3]).getEncoded().asByteArray());
    outParms.setOrdinalDigest(retval[4] == null ? null : ((TcTpmDigest) retval[4]).getEncoded().asByteArray());
    outParms.setSig(((TcBlobData) retval[2]).asByteArray());

    return outParms;
  }

  public SetOrdinalAuditStatusOutParms setOrdinalAuditStatus(SetOrdinalAuditStatusInParms inParms) throws RemoteException {
    
    long hContext = inParms.getHContext().longValue();
    TcTcsAuth inAuth1 = ConvertDataTypesServer.convertTcsAuth(inParms.getOwnerAuth());
    long ordinalToAudit = inParms.getOrdinalToAudit().longValue();
    boolean auditState = ((Byte) inParms.getAuditState() != 0);
    Object[] retval = null;
    
    try {
      retval = TcTcsi.TcsipSetOrdinalAuditStatus(hContext, inAuth1, ordinalToAudit, auditState);
    } catch (TcTddlException e) {
      throw new RemoteException("", e);
    } catch (TcTpmException e) {
      throw new RemoteException("", e);
    } catch (TcTcsException e) {
      throw new RemoteException("", e);
    } catch (Exception e) {
      e.printStackTrace();
      throw new RemoteException("", e);
    }

    SetOrdinalAuditStatusOutParms outParms = new SetOrdinalAuditStatusOutParms();
    outParms.setResult(new UnsignedInt((Long) retval[0]));
    outParms.setOwnerAuth(ConvertDataTypesServer.convertTcsAuth((TcTcsAuth) retval[1]));

    return outParms;
  }

  public GetCapabilitySignedOutParms getCapabilitySigned(GetCapabilitySignedInParms inParms) throws RemoteException {
    //TODO - no implementation on the Client side.
    return null;
  }

  public CreateRevocableEndorsementKeyPairOutParms createRevocableEndorsementKeyPair(CreateRevocableEndorsementKeyPairInParms inParms) throws RemoteException {
    
    long hContext = inParms.getHContext().longValue();
    TcTpmNonce antiReplay = new TcTpmNonce(TcBlobData.newByteArray(inParms.getAntiReplay()));
    TcTpmKeyParms keyInfo = new TcTpmKeyParms(TcBlobData.newByteArray(inParms.getEndorsementKeyInfo()));
    boolean generateReset = ((Byte) inParms.getGenResetAuth() != 0);
    TcTpmNonce inputEKreset = new TcTpmNonce(TcBlobData.newByteArray(inParms.getEKResetAuth()));
    Object[] retval = null;
    
    try {

      //{ outBlob.getRetCodeAsLong(), pubEndorsementKey, checksum, outputEKreset };
      retval = TcTcsi.TcsipCreateRevocableEK(hContext, antiReplay, keyInfo, generateReset, inputEKreset);
    } catch (TcTddlException e) {
      throw new RemoteException("", e);
    } catch (TcTpmException e) {
      throw new RemoteException("", e);
    } catch (TcTcsException e) {
      throw new RemoteException("", e);
    } catch (Exception e) {
      e.printStackTrace();
      throw new RemoteException("", e);
    }

    CreateRevocableEndorsementKeyPairOutParms outParms = new CreateRevocableEndorsementKeyPairOutParms();
    outParms.setResult(new UnsignedInt((Long) retval[0]));
    outParms.setEndorsementKey(retval[1] == null ? null : ((TcTpmPubkey) retval[1]).getEncoded().asByteArray());
    outParms.setChecksum(retval[2] == null ? null : ((TcTpmDigest) retval[2]).getEncoded().asByteArray());
    outParms.setEKResetAuth(((TcBlobData) retval[3]).asByteArray());

    return outParms;
  }

  public RevokeEndorsementKeyPairOutParms revokeEndorsementKeyPair(RevokeEndorsementKeyPairInParms inParms) throws RemoteException {
    
    long hContext = inParms.getHContext().longValue();
    TcTpmNonce EKReset = new TcTpmNonce(TcBlobData.newByteArray(inParms.getEKResetAuth()));
    Object[] retval = null;
    
    try {
      retval = TcTcsi.TcsipRevokeEndorsementKeyPair(hContext, EKReset);
    } catch (TcTddlException e) {
      throw new RemoteException("", e);
    } catch (TcTpmException e) {
      throw new RemoteException("", e);
    } catch (TcTcsException e) {
      throw new RemoteException("", e);
    } catch (Exception e) {
      e.printStackTrace();
    }

    RevokeEndorsementKeyPairOutParms outParms = new RevokeEndorsementKeyPairOutParms();
    outParms.setResult(new UnsignedInt((Long) retval[0]));
    
    return outParms;
  }

  public PcrResetOutParms pcrReset(PcrResetInParms inParms) throws RemoteException {
    
    long hContext = inParms.getHContext().longValue();
    TcTpmPcrSelection pcrSelection = new TcTpmPcrSelection(TcBlobData.newByteArray(inParms.getPcrTarget()));
    Object[] retval = null;
    
    try {
      retval = TcTcsi.TcsipPcrReset(hContext, pcrSelection);
    } catch (TcTddlException e) {
      throw new RemoteException("", e);
    } catch (TcTpmException e) {
      throw new RemoteException("", e);
    } catch (TcTcsException e) {
      throw new RemoteException("", e);
    } catch (Exception e) {
      e.printStackTrace();
      throw new RemoteException("", e);
    }

    PcrResetOutParms outParms = new PcrResetOutParms();
    outParms.setResult(new UnsignedInt((Long) retval[0]));

    return outParms;
  }

  public ReadCounterOutParms readCounter(ReadCounterInParms inParms) throws RemoteException {
    
    long hContext = inParms.getHContext().longValue();
    long countID = inParms.getIdCounter().longValue();
    Object[] retval = null;
    
    try {
      retval = TcTcsi.TcsipReadCounter(hContext, countID);
    } catch (TcTddlException e) {
      throw new RemoteException("", e);
    } catch (TcTpmException e) {
      throw new RemoteException("", e);
    } catch (TcTcsException e) {
      throw new RemoteException("", e);
    } catch (Exception e) {
      e.printStackTrace();
      throw new RemoteException("", e);
    }

    ReadCounterOutParms outParms = new ReadCounterOutParms();
    outParms.setResult(new UnsignedInt((Long) retval[0]));
    outParms.setCounterValue(ConvertDataTypesServer.convertTpmCounterValue((TcTpmCounterValue) retval[1]));

    return outParms;
  }

  public CreateCounterOutParms createCounter(CreateCounterInParms inParms) throws RemoteException {
    
    long hContext = inParms.getHContext().longValue();
    TcBlobData label = TcBlobData.newByteArray(inParms.getPLabel());
    TcTpmEncauth encAuth = new TcTpmEncauth(TcBlobData.newByteArray(inParms.getCounterAuth()));
    TcTcsAuth inAuth1 = ConvertDataTypesServer.convertTcsAuth(inParms.getPOwnerAuth());
    Object[] retval = null;
    
    try {
      //{ outBlob.getRetCodeAsLong(), outAuth1, new Long(countID), counterValue };
      retval = TcTcsi.TcsipCreateCounter(hContext, label, encAuth, inAuth1);
    } catch (TcTddlException e) {
      throw new RemoteException("", e);
    } catch (TcTpmException e) {
      throw new RemoteException("", e);
    } catch (TcTcsException e) {
      throw new RemoteException("", e);
    } catch (Exception e) {
      e.printStackTrace();
      throw new RemoteException("", e);
    }

    CreateCounterOutParms outParms = new CreateCounterOutParms();
    outParms.setResult(new UnsignedInt((Long) retval[0]));
    outParms.setPOwnerAuth(ConvertDataTypesServer.convertTcsAuth((TcTcsAuth) retval[1]));
    outParms.setIdCounter(new UnsignedInt((Long) retval[2]));
    outParms.setCounterValue(ConvertDataTypesServer.convertTpmCounterValue((TcTpmCounterValue) retval[3]));

    return outParms;
  }

  public IncrementCounterOutParms incrementCounter(IncrementCounterInParms inParms) throws RemoteException {
    
    long hContext = inParms.getHContext().longValue();
    long countID = inParms.getIdCounter().longValue();
    TcTcsAuth inAuth1 = ConvertDataTypesServer.convertTcsAuth(inParms.getPCounterAuth());
    Object[] retval = null;
    
    try {
      //{ outBlob.getRetCodeAsLong(), outAuth1, count }
      retval = TcTcsi.TcsipIncrementCounter(hContext, countID, inAuth1);
    } catch (TcTddlException e) {
      throw new RemoteException("", e);
    } catch (TcTpmException e) {
      throw new RemoteException("", e);
    } catch (TcTcsException e) {
      throw new RemoteException("", e);
    } catch (Exception e) {
      e.printStackTrace();
      throw new RemoteException("", e);
    }

    IncrementCounterOutParms outParms = new IncrementCounterOutParms();
    outParms.setResult(new UnsignedInt((Long) retval[0]));
    outParms.setPCounterAuth(ConvertDataTypesServer.convertTcsAuth((TcTcsAuth) retval[1]));
    outParms.setCounterValue(ConvertDataTypesServer.convertTpmCounterValue((TcTpmCounterValue) retval[2]));

    return outParms;
  }

  public ReleaseCounterOutParms releaseCounter(ReleaseCounterInParms inParms) throws RemoteException {
    
    long hContext = inParms.getHContext().longValue();
    long countID = inParms.getIdCounter().longValue();
    TcTcsAuth inAuth1 = ConvertDataTypesServer.convertTcsAuth(inParms.getPCounterAuth());
    Object[] retval = null;
    
    try {
      retval = TcTcsi.TcsipReleaseCounter(hContext, countID, inAuth1);
    } catch (TcTddlException e) {
      throw new RemoteException("", e);
    } catch (TcTpmException e) {
      throw new RemoteException("", e);
    } catch (TcTcsException e) {
      throw new RemoteException("", e);
    } catch (Exception e) {
      e.printStackTrace();
      throw new RemoteException("", e);
    }

    ReleaseCounterOutParms outParms = new ReleaseCounterOutParms();
    outParms.setResult(new UnsignedInt((Long) retval[0]));
    outParms.setPCounterAuth(ConvertDataTypesServer.convertTcsAuth((TcTcsAuth) retval[1]));

    return outParms;
  }

  public ReleaseCounterOwnerOutParms releaseCounterOwner(ReleaseCounterOwnerInParms inParms) throws RemoteException {
    
    long hContext = inParms.getHContext().longValue();
    long countID = inParms.getIdCounter().longValue();
    TcTcsAuth inAuth1 = ConvertDataTypesServer.convertTcsAuth(inParms.getPOwnerAuth());
    Object[] retval = null;
    
    try {
      retval = TcTcsi.TcsipReleaseCounterOwner(hContext, countID, inAuth1);
    } catch (TcTddlException e) {
      throw new RemoteException("", e);
    } catch (TcTpmException e) {
      throw new RemoteException("", e);
    } catch (TcTcsException e) {
      throw new RemoteException("", e);
    } catch (Exception e) {
      e.printStackTrace();
      throw new RemoteException("", e);
    }

    ReleaseCounterOwnerOutParms outParms = new ReleaseCounterOwnerOutParms();
    outParms.setResult(new UnsignedInt((Long) retval[0]));
    outParms.setPOwnerAuth(ConvertDataTypesServer.convertTcsAuth((TcTcsAuth) retval[1]));

    return outParms;
  }

  public ReadCurrentTicksOutParms readCurrentTicks(ReadCurrentTicksInParms inParms) throws RemoteException {
    
    long hContext = inParms.getHContext().longValue();
    Object[] retval = null;
    
    try {
      retval = TcTcsi.TcsipReadCurrentTicks(hContext);
    } catch (TcTddlException e) {
      throw new RemoteException("", e);
    } catch (TcTpmException e) {
      throw new RemoteException("", e);
    } catch (TcTcsException e) {
      throw new RemoteException("", e);
    } catch (Exception e) {
      e.printStackTrace();
      throw new RemoteException("", e);
    }
    
    ReadCurrentTicksOutParms outParms = new ReadCurrentTicksOutParms();
    outParms.setResult(new UnsignedInt((Long) retval[0]));
    outParms.setPrgbCurrentTime(((TcTpmCurrentTicks) retval[1]).getEncoded().asByteArray());

    return outParms;
  }

  public TickStampBlobOutParms tickStampBlob(TickStampBlobInParms inParms) throws RemoteException {
    
    long hContext = inParms.getHContext().longValue();
    long keyHandle = inParms.getHKey().longValue();
    TcTpmNonce antiReplay = new TcTpmNonce(TcBlobData.newByteArray(inParms.getAntiReplay()));
    TcTpmDigest digestToStamp = new TcTpmDigest(TcBlobData.newByteArray(inParms.getDigestToStamp()));
    TcTcsAuth inAuth1 = ConvertDataTypesServer.convertTcsAuth(inParms.getPrivAuth());
    Object[] retval = null;
    
    try {
      retval = TcTcsi.TcsipTickStampBlob(hContext, keyHandle, antiReplay, digestToStamp, inAuth1);
    } catch (TcTddlException e) {
      throw new RemoteException("", e);
    } catch (TcTpmException e) {
      throw new RemoteException("", e);
    } catch (TcTcsException e) {
      throw new RemoteException("", e);
    } catch (Exception e) {
      e.printStackTrace();
      throw new RemoteException("", e);
    }

    TickStampBlobOutParms outParms = new TickStampBlobOutParms();
    outParms.setResult(new UnsignedInt((Long) retval[0]));
    outParms.setPrivAuth(ConvertDataTypesServer.convertTcsAuth((TcTcsAuth) retval[1]));
    outParms.setPrgbTickCount(((TcTpmCurrentTicks) retval[2]).getEncoded().asByteArray());
    outParms.setPrgbSignature(((TcBlobData) retval[3]).asByteArray());

    return outParms;
  }

  public MigrateKeyOutParms migrateKey(MigrateKeyInParms inParms) throws RemoteException {
    
    long hContext = inParms.getHContext().longValue();
    long maKeyHandle = inParms.getHMaKey().longValue();
    TcTpmPubkey pubKey = new TcTpmPubkey(TcBlobData.newByteArray(inParms.getPublicKey()));
    TcBlobData inData = TcBlobData.newByteArray(inParms.getInData());
    TcTcsAuth inAuth1 = ConvertDataTypesServer.convertTcsAuth(inParms.getOwnerAuth());
    Object[] retval = null;
    
    try {
      retval = TcTcsi.TcsipMigrateKey(hContext, maKeyHandle, pubKey, inData, inAuth1);

    } catch (TcTddlException e) {
      throw new RemoteException("", e);
    } catch (TcTpmException e) {
      throw new RemoteException("", e);
    } catch (TcTcsException e) {
      throw new RemoteException("", e);
    } catch (Exception e) {
      e.printStackTrace();
      throw new RemoteException("", e);
    }

    MigrateKeyOutParms outParms = new MigrateKeyOutParms();
    outParms.setResult(new UnsignedInt((Long) retval[0]));
    outParms.setOwnerAuth(ConvertDataTypesServer.convertTcsAuth((TcTcsAuth) retval[1]));
    outParms.setOutData(retval[2] == null ? null : ((TcBlobData) retval[2]).asByteArray());

    return outParms;
  }

  public CMK_SetRestrictionsOutParms CMK_SetRestrictions(CMK_SetRestrictionsInParms inParms) throws RemoteException {
    
    long hContext = inParms.getHContext().longValue();
    long restriction = inParms.getRestriction().longValue();
    TcTcsAuth inAuth1 = ConvertDataTypesServer.convertTcsAuth(inParms.getOwnerAuth());
    Object[] retval = null;
    
    try {
      retval = TcTcsi.TcsipCmkSetRestrictions(hContext, restriction, inAuth1);
    } catch (TcTddlException e) {
      throw new RemoteException("", e);
    } catch (TcTpmException e) {
      throw new RemoteException("", e);
    } catch (TcTcsException e) {
      throw new RemoteException("", e);
    } catch (Exception e) {
      e.printStackTrace();
      throw new RemoteException("", e);
    }
    
    CMK_SetRestrictionsOutParms outParms = new CMK_SetRestrictionsOutParms();
    outParms.setResult(new UnsignedInt((Long) retval[0]));
    outParms.setOwnerAuth(ConvertDataTypesServer.convertTcsAuth((TcTcsAuth) retval[1]));

    return outParms;
  }

  public CMK_ApproveMAOutParms CMK_ApproveMA(CMK_ApproveMAInParms inParms) throws RemoteException {
    
    long hContext = inParms.getHContext().longValue();
    TcTpmDigest migrationAuthorityDigest = new TcTpmDigest(TcBlobData.newByteArray(inParms.getMigAuthorityDigest()));
    TcTcsAuth inAuth1 = ConvertDataTypesServer.convertTcsAuth(inParms.getOwnerAuth());
    Object[] retval = null;
    
    try {
      retval = TcTcsi.TcsipCmkApproveMA(hContext, migrationAuthorityDigest, inAuth1);
    } catch (TcTddlException e) {
      throw new RemoteException("", e);
    } catch (TcTpmException e) {
      throw new RemoteException("", e);
    } catch (TcTcsException e) {
      throw new RemoteException("", e);
    } catch (Exception e) {
      e.printStackTrace();
      throw new RemoteException("", e);
    }

    CMK_ApproveMAOutParms outParms = new CMK_ApproveMAOutParms();
    outParms.setResult(new UnsignedInt((Long) retval[0]));
    outParms.setOwnerAuth(ConvertDataTypesServer.convertTcsAuth((TcTcsAuth) retval[1]));
    outParms.setHmacMigAuthDigest(retval[2] == null ? null : ((TcBlobData) retval[2]).asByteArray());

    return outParms;
  }

  public CMK_CreateKeyOutParms CMK_CreateKey(CMK_CreateKeyInParms inParms) throws RemoteException {
    
    long hContext = inParms.getHContext().longValue();
    long parentHandle = inParms.getHWrappingKey().longValue();
    TcTpmEncauth dataUsageAuth = new TcTpmEncauth(TcBlobData.newByteArray(inParms.getKeyUsageAuth()));
    TcTpmDigest migrationAuthorityApproval = new TcTpmDigest(TcBlobData.newByteArray(inParms.getMigAuthApproval()));
    TcTpmDigest migrationAuthorityDigest = new TcTpmDigest(TcBlobData.newByteArray(inParms.getMigAuthorityDigest()));
    TcTpmKey12 keyInfo = new TcTpmKey12(TcBlobData.newByteArray(inParms.getPrgbKeyData()));
    TcTcsAuth inAuth1 = ConvertDataTypesServer.convertTcsAuth(inParms.getPAuth());
    Object[] retval = null;

    try {
      retval = TcTcsi.TcsipCmkCreateKey(hContext, parentHandle, dataUsageAuth, migrationAuthorityApproval, migrationAuthorityDigest, keyInfo, inAuth1);
    } catch (TcTddlException e) {
      throw new RemoteException("", e);
    } catch (TcTpmException e) {
      throw new RemoteException("", e);
    } catch (TcTcsException e) {
      throw new RemoteException("", e);
    } catch (Exception e) {
      e.printStackTrace();
      throw new RemoteException("", e);
    }

    CMK_CreateKeyOutParms outParms = new CMK_CreateKeyOutParms();
    outParms.setResult(new UnsignedInt((Long) retval[0]));
    outParms.setPAuth(ConvertDataTypesServer.convertTcsAuth((TcTcsAuth) retval[1]));
    outParms.setPrgbKeyData(retval[2] == null ? null : ((TcBlobData) retval[2]).asByteArray());

    return outParms;
  }

  public CMK_CreateTicketOutParms CMK_CreateTicket(CMK_CreateTicketInParms inParms) throws RemoteException {
    
    long hContext = inParms.getHContext().longValue();
    TcTpmPubkey verificationKey = new TcTpmPubkey(TcBlobData.newByteArray(inParms.getPublicVerifyKey()));
    TcTpmDigest signedData = new TcTpmDigest(TcBlobData.newByteArray(inParms.getSignedData()));
    TcBlobData signatureValue = TcBlobData.newByteArray(inParms.getSigValue());
    TcTcsAuth inAuth1 = ConvertDataTypesServer.convertTcsAuth(inParms.getPOwnerAuth());
    Object[] retval = null;
    
    try {
      retval = TcTcsi.TcsipCmkCreateTicket(hContext, verificationKey, signedData, signatureValue, inAuth1);
    } catch (TcTddlException e) {
      throw new RemoteException("", e);
    } catch (TcTpmException e) {
      throw new RemoteException("", e);
    } catch (TcTcsException e) {
      throw new RemoteException("", e);
    } catch (Exception e) {
      e.printStackTrace();
      throw new RemoteException("", e);
    }
    
    CMK_CreateTicketOutParms outParms = new CMK_CreateTicketOutParms();
    outParms.setResult(new UnsignedInt((Long) retval[0]));
    outParms.setPOwnerAuth(ConvertDataTypesServer.convertTcsAuth((TcTcsAuth) retval[1]));
    outParms.setSigTicket(retval[2] == null ? null : ((TcBlobData) retval[2]).asByteArray());

    return outParms;
  }

  public CMK_CreateBlobOutParms CMK_CreateBlob(CMK_CreateBlobInParms inParms) throws RemoteException {
    
    long hContext = inParms.getHContext().longValue();
    long parentHandle = inParms.getParentHandle().longValue();
    int migrationType = inParms.getMigrationType().intValue();
    TcTpmMigrationkeyAuth migrationKeyAuth = new TcTpmMigrationkeyAuth(TcBlobData.newByteArray(inParms.getMigrationKeyAuth()));
    TcTpmDigest pubSourceKeyDigest = new TcTpmDigest(TcBlobData.newByteArray(inParms.getPubSourceKeyDigest()));
    TcTpmMsaComposite msaList = new TcTpmMsaComposite(TcBlobData.newByteArray(inParms.getMsaList()));
    TcBlobData restrictTicket = TcBlobData.newByteArray(inParms.getRestrictTicket());
    TcBlobData sigTicket = TcBlobData.newByteArray(inParms.getSigTicket());
    TcBlobData encData = TcBlobData.newByteArray(inParms.getEncData());
    TcTcsAuth inAuth1 = ConvertDataTypesServer.convertTcsAuth(inParms.getParentAuth());
    Object[] retval = null;

    try {
      retval = TcTcsi.TcsipCmkCreateBlob(hContext, parentHandle, migrationType, migrationKeyAuth, pubSourceKeyDigest, msaList, restrictTicket, sigTicket, encData, inAuth1);
    } catch (TcTddlException e) {
      throw new RemoteException("", e);
    } catch (TcTpmException e) {
      throw new RemoteException("", e);
    } catch (TcTcsException e) {
      throw new RemoteException("", e);
    } catch (Exception e) {
      e.printStackTrace();
      throw new RemoteException("", e);
    }
    
    CMK_CreateBlobOutParms outParms = new CMK_CreateBlobOutParms();
    outParms.setResult(new UnsignedInt((Long) retval[0]));
    outParms.setParentAuth(ConvertDataTypesServer.convertTcsAuth((TcTcsAuth) retval[1]));
    outParms.setRandom(retval[2] == null ? null : ((TcBlobData) retval[2]).asByteArray());
    outParms.setOutData(retval[3] == null ? null : ((TcBlobData) retval[3]).asByteArray());

    return outParms;
  }

  public CMK_ConvertMigrationOutParms CMK_ConvertMigration(CMK_ConvertMigrationInParms inParms) throws RemoteException {
    
    long hContext = inParms.getHContext().longValue();
    long parentHandle = inParms.getParentHandle().longValue();
    TcTpmCmkAuth restrictTicket = ConvertDataTypesServer.convertTpmCmkAuth(inParms.getRestrictTicket());
    TcTpmDigest sigTicket = new TcTpmDigest(TcBlobData.newByteArray(inParms.getSigTicket()));
    TcTpmMsaComposite msaList = new TcTpmMsaComposite(TcBlobData.newByteArray(inParms.getMsaList()));
    TcTpmKey12 migratedKey = new TcTpmKey12(TcBlobData.newByteArray(inParms.getPrgbKeyData()));
    TcBlobData random = TcBlobData.newByteArray(inParms.getRandom());
    TcTcsAuth inAuth1 = ConvertDataTypesServer.convertTcsAuth(inParms.getParentAuth());
    Object[] retval = null;

    try {
      retval = TcTcsi.TcsipCmkConvertMigration(hContext, parentHandle, restrictTicket, sigTicket, migratedKey, msaList, random, inAuth1);
    } catch (TcTddlException e) {
      throw new RemoteException("", e);
    } catch (TcTpmException e) {
      throw new RemoteException("", e);
    } catch (TcTcsException e) {
      throw new RemoteException("", e);
    } catch (Exception e) {
      e.printStackTrace();
      throw new RemoteException("", e);
    }
      
    CMK_ConvertMigrationOutParms outParms = new CMK_ConvertMigrationOutParms();
    outParms.setResult(new UnsignedInt((Long) retval[0]));
    outParms.setParentAuth(ConvertDataTypesServer.convertTcsAuth((TcTcsAuth) retval[1]));
    outParms.setOutData(retval[2] == null ? null : ((TcBlobData) retval[2]).asByteArray());

    return outParms;
  }

  public EstablishTransportOutParms establishTransport(EstablishTransportInParms inParms) throws RemoteException {
    
    long hContext = inParms.getHContext().longValue();
    long tcsEncKeyHandle = inParms.getHEncKey().longValue();
    TcTcsAuth inAuth1 = ConvertDataTypesServer.convertTcsAuth(inParms.getPEncKeyAuth());
    TcBlobData secret = TcBlobData.newByteArray(inParms.getRgbSecret());
    TcTpmTransportPublic transPublic = new TcTpmTransportPublic(TcBlobData.newByteArray(inParms.getRgbTransSessionInfo()));
    Object[] retval = null;

    try {
      retval = TcTcsi.TcsEstablishTransport(hContext, tcsEncKeyHandle, transPublic, secret, inAuth1);
    } catch (TcTddlException e) {
      throw new RemoteException("", e);
    } catch (TcTpmException e) {
      throw new RemoteException("", e);
    } catch (TcTcsException e) {
      throw new RemoteException("", e);
    } catch (Exception e) {
      e.printStackTrace();
      throw new RemoteException("", e);
    }

    EstablishTransportOutParms outParms = new EstablishTransportOutParms();
    outParms.setResult(new UnsignedInt((Long) retval[0]));
    outParms.setPEncKeyAuth(ConvertDataTypesServer.convertTcsAuth((TcTcsAuth) retval[1]));
    outParms.setHTransSession(new UnsignedInt((Long) retval[2]));
    outParms.setPbLocality(new UnsignedInt((Long) retval[3]));
    outParms.setPrgbCurrentTicks(((TcTpmCurrentTicks) retval[4]).getEncoded().asByteArray());
    outParms.setPTransNonce(((TcTpmNonce) retval[5]).getEncoded().asByteArray());

    return outParms;
  }

  public ExecuteTransportOutParms executeTransport(ExecuteTransportInParms inParms) throws RemoteException {

    long hContext = inParms.getHContext().longValue();
    TcTcsAuth inAuth1 = ConvertDataTypesServer.convertTcsAuth(inParms.getPTransAuth());
    TcBlobData wrappedCmd = TcBlobData.newByteArray(inParms.getRgbWrappedCmdParamIn());
    long transHandle = inParms.getUnWrappedCommandOrdinal().longValue();
    Object[] retval = null;

    try {
      retval = TcTcsi.TcsExecuteTransport(hContext, wrappedCmd, transHandle, inAuth1);
    } catch (TcTddlException e) {
      throw new RemoteException("", e);
    } catch (TcTpmException e) {
      throw new RemoteException("", e);
    } catch (TcTcsException e) {
      throw new RemoteException("", e);
    } catch (Exception e) {
      e.printStackTrace();
      throw new RemoteException("", e);
    }

    ExecuteTransportOutParms outParms = new ExecuteTransportOutParms();
    outParms.setResult(new UnsignedInt((Long) retval[0]));
    outParms.setPTransAuth(ConvertDataTypesServer.convertTcsAuth((TcTcsAuth) retval[1]));
    outParms.setPunCurrentTicks(new UnsignedLong((Long) retval[2]));
    outParms.setPbLocality(new UnsignedInt((Long) retval[3]));
    outParms.setRgbWrappedCmdParamOut(((TcBlobData) retval[4]).asByteArray());

    return outParms;
  }

  public ReleaseTransportSignedOutParms releaseTransportSigned(ReleaseTransportSignedInParms inParms) throws RemoteException {
    
    long hContext = inParms.getHContext().longValue();
    long tcsKeyHandle = inParms.getHSignatureKey().longValue();
    TcTpmNonce antiReplay = new TcTpmNonce(TcBlobData.newByteArray(inParms.getAntiReplayNonce()));
    TcTcsAuth inAuth1 = ConvertDataTypesServer.convertTcsAuth(inParms.getPKeyAuth());
    TcTcsAuth inAuth2 = ConvertDataTypesServer.convertTcsAuth(inParms.getPTransAuth());
    long transHandle = 0l; //Fixme - not specified in the inParms object.
    Object[] retval = null;

    try {
      retval = TcTcsi.TcsReleaseTransportSigned(hContext, tcsKeyHandle, antiReplay, transHandle, inAuth1, inAuth2);
    } catch (TcTddlException e) {
      throw new RemoteException("", e);
    } catch (TcTpmException e) {
      throw new RemoteException("", e);
    } catch (TcTcsException e) {
      throw new RemoteException("", e);
    } catch (Exception e) {
      e.printStackTrace();
      throw new RemoteException("", e);
    }

    ReleaseTransportSignedOutParms outParms = new ReleaseTransportSignedOutParms();
    outParms.setResult(new UnsignedInt((Long) retval[0]));
    outParms.setPTransAuth(ConvertDataTypesServer.convertTcsAuth((TcTcsAuth) retval[1]));
    outParms.setPKeyAuth(ConvertDataTypesServer.convertTcsAuth((TcTcsAuth) retval[2]));
    outParms.setPbLocality(new UnsignedInt((Long) retval[3]));
    outParms.setPrgbCurrentTicks(((TcTpmCurrentTicks) retval[4]).getEncoded().asByteArray());
    outParms.setPrgbSignature(((TcBlobData) retval[5]).asByteArray());

    return outParms;
  }

  public Admin_TSS_SessionsPerLocalityOutParms admin_TSS_SessionsPerLocality(Admin_TSS_SessionsPerLocalityInParms inParms) throws RemoteException {
    //TODO - No implementation on the Client side.
    return null;
  }

  public SetOwnerPointerOutParms setOwnerPointer(SetOwnerPointerInParms inParms) throws RemoteException {
    //TODO - No implementation on the Client side.
    return null;
  }
}
