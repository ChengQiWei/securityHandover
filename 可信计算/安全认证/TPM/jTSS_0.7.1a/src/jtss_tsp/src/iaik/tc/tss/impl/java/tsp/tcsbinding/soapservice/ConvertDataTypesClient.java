/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 */

package iaik.tc.tss.impl.java.tsp.tcsbinding.soapservice;

import org.apache.axis.types.UnsignedByte;
import org.apache.axis.types.UnsignedInt;
import org.apache.axis.types.UnsignedShort;

import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.tss.api.structs.tcs.TcTcsAuth;
import iaik.tc.tss.api.structs.tcs.TcTcsLoadkeyInfo;
import iaik.tc.tss.api.structs.tpm.TcTpmAuthdata;
import iaik.tc.tss.api.structs.tpm.TcTpmCmkAuth;
import iaik.tc.tss.api.structs.tpm.TcTpmCounterValue;
import iaik.tc.tss.api.structs.tpm.TcTpmDigest;
import iaik.tc.tss.api.structs.tpm.TcTpmNonce;
import iaik.tc.tss.api.structs.tsp.TcTssKmKeyinfo;
import iaik.tc.tss.api.structs.tsp.TcTssPcrEvent;
import iaik.tc.tss.api.structs.tsp.TcTssUuid;
import iaik.tc.tss.api.structs.tsp.TcTssVersion;
import iaik.tc.tss.impl.java.tsp.tcsbinding.soapservice.clientstubs.*;

public class ConvertDataTypesClient {
//	------------------------------------------------------------------------------------------------//
//	<complexType name="TSS-PCR-EVENT">
//	<sequence>
//	<element name="versionInfo" type="tcs:TSS-VERSION" minOccurs="1" maxOccurs="1"/>
//	<element name="ulPcrIndex" type="xsd:unsignedInt" minOccurs="1" maxOccurs="1"/>
//	<element name="eventType" type="xsd:unsignedInt" minOccurs="1" maxOccurs="1"/>
//	<element name="rgbPcrValue" type="xsd:base64Binary" minOccurs="1" maxOccurs="1" nillable="false"/>
//	<element name="rgbEvent" type="xsd:base64Binary" minOccurs="0" maxOccurs="1" nillable="true"/>
//	</sequence>
//	</complexType>
//	------------------------------------------------------------------------------------------------//
	static public TcTssPcrEvent convertTcTssPcrEvent(TSSPCREVENT in) {
		TcTssPcrEvent retval = new TcTssPcrEvent();

		retval.setVersionInfo(convertTssVersion(in.getVersionInfo()));
		retval.setPcrIndex(in.getUlPcrIndex().longValue());
		retval.setEventType(in.getEventType().longValue());
		retval.setPcrValue(TcBlobData.newByteArray(in.getRgbPcrValue()));
		retval.setEvent(TcBlobData.newByteArray(in.getRgbEvent()));

		return retval;
	}

	static public TSSPCREVENT convertTcTssPcrEvent(TcTssPcrEvent  in) {
		TSSPCREVENT retval = new TSSPCREVENT();

		retval.setVersionInfo(convertTssVersion(in.getVersionInfo()));
		retval.setUlPcrIndex(new UnsignedInt(in.getPcrIndex()));
		retval.setEventType(new UnsignedInt(in.getEventType()));
		retval.setRgbPcrValue(in.getPcrValue().asByteArray());
		retval.setRgbEvent(in.getEvent().asByteArray());

		return retval;
	}


//	------------------------------------------------------------------------------------------------//
//	<complexType name="TSS-VERSION">
//	<sequence>
//	<element name="bMajor" type="xsd:unsignedByte" minOccurs="1" maxOccurs="1"/>
//	<element name="bMinor" type="xsd:unsignedByte" minOccurs="1" maxOccurs="1"/>
//	<element name="bRevMajor" type="xsd:unsignedByte" minOccurs="1" maxOccurs="1"/>
//	<element name="bRevMinor" type="xsd:unsignedByte" minOccurs="1" maxOccurs="1"/>
//	</sequence>
//	</complexType>
//	------------------------------------------------------------------------------------------------//
	static public TcTssVersion convertTssVersion(TSSVERSION in) {
		TcTssVersion retval = new TcTssVersion();

		retval.setMajor(in.getBMajor().shortValue());
		retval.setMinor(in.getBMinor().shortValue());
		retval.setRevMajor(in.getBRevMajor().shortValue());
		retval.setRevMinor(in.getBRevMinor().shortValue());

		return retval;
	}

	static public TSSVERSION convertTssVersion(TcTssVersion in) {
		TSSVERSION retval = new TSSVERSION();

		retval.setBMajor(new UnsignedByte(in.getMajor()));
		retval.setBMinor(new UnsignedByte(in.getMinor()));
		retval.setBRevMajor(new UnsignedByte(in.getRevMajor()));
		retval.setBRevMinor(new UnsignedByte(in.getRevMinor()));

		return retval;
	}  


//	------------------------------------------------------------------------------------------------//
//	<complexType name="TPM-COUNTER-VALUE">
//	<sequence>
//	<element name="tag" type="xsd:unsignedShort" minOccurs="1" maxOccurs="1"/>
//	<element name="label" type="xsd:base64Binary" minOccurs="1" maxOccurs="1"/>
//	<element name="counter" type="xsd:unsignedInt" minOccurs="1" maxOccurs="1"/>
//	</sequence>
//	</complexType>
//	------------------------------------------------------------------------------------------------//
	static public TcTpmCounterValue convertTpmCounterValue(TPMCOUNTERVALUE in) {
		TcTpmCounterValue retval = new TcTpmCounterValue();

		retval.setTag(in.getTag().intValue());
		retval.setLabel(new String(in.getLabel()));
		retval.setCounter(in.getCounter().longValue());

		return retval;
	}

	static public TPMCOUNTERVALUE convertTpmCounterValue(TcTpmCounterValue in) {
		TPMCOUNTERVALUE retval = new TPMCOUNTERVALUE();

		retval.setTag(new UnsignedShort(in.getTag()));
		retval.setLabel(in.getLabel().toString().getBytes());
		retval.setCounter(new UnsignedInt(in.getCounter()));

		return retval;
	}


//	------------------------------------------------------------------------------------------------//
//	<complexType name="TSS-UUID">                                                                   //
//	<sequence>                                                                                      //
//	<element name="ulTimeLow" type="xsd:unsignedInt" minOccurs="1" maxOccurs="1"/>                //
//	<element name="usTimeMid" type="xsd:unsignedShort" minOccurs="1" maxOccurs="1"/>              //
//	<element name="usTimeHigh" type="xsd:unsignedShort" minOccurs="1" maxOccurs="1"/>             //
//	<element name="bClockSeqHigh" type="xsd:byte" minOccurs="1" maxOccurs="1"/>                   //
//	<element name="bClockSeqLow" type="xsd:byte" minOccurs="1" maxOccurs="1"/>                    //
//	<element name="rgbNode" type="xsd:base64Binary" minOccurs="1" maxOccurs="1"/>                 //
//	</sequence>                                                                                     //
//	</complexType>                                                                                  //
//	------------------------------------------------------------------------------------------------//
	static public TcTssUuid convertTssUuid(TSSUUID in) {
	
    TcTssUuid retval = new TcTssUuid();
    
		retval.setClockSeqHigh(new Integer(in.getBClockSeqHigh() & 0xff).shortValue());
		retval.setClockSeqLow(new Integer(in.getBClockSeqLow() & 0xff).shortValue());

		byte[] byteArray = in.getRgbNode();             //convert the 'byte' array to a 'short' array
		short[] shortArray = new short[byteArray.length];
		for(int i = 0; i < byteArray.length; i++) {
			shortArray[i] = new Integer(byteArray[i] & 0xff).shortValue();
		}

		retval.setNode(shortArray);
		retval.setTimeHigh(in.getUsTimeHigh().intValue() & 0xffff);
		retval.setTimeLow(in.getUlTimeLow().longValue() & 0xffffffff);
		retval.setTimeMid(in.getUsTimeMid().intValue() & 0xffff);

    
		return retval;
	}

	static public TSSUUID convertTssUuid(TcTssUuid in) {
		TSSUUID retval = new TSSUUID();

		retval.setBClockSeqHigh(((Short)in.getClockSeqHigh()).byteValue());
		retval.setBClockSeqLow(((Short)in.getClockSeqLow()).byteValue());

		short[] shortArray = in.getNode();              //convert the 'short' array to a 'byte' array
		byte[] byteArray = new byte[shortArray.length];
		for(int i = 0; i < shortArray.length; i++) {
			byteArray[i] = new Short(shortArray[i]).byteValue();
		}

		retval.setRgbNode(byteArray);
		retval.setUsTimeHigh(new UnsignedShort(in.getTimeHigh()));
		retval.setUlTimeLow(new UnsignedInt(in.getTimeLow()));
		retval.setUsTimeMid(new UnsignedShort(in.getTimeMid()));

		return retval;
	}


//	------------------------------------------------------------------------------------------------//
//	<complexType name="TCS-LOADKEY-INFO">
//	<sequence>
//	<element name="keyUUID" type="tcs:TSS-UUID" minOccurs="1" maxOccurs="1"/>
//	<element name="parentKeyUUID" type="tcs:TSS-UUID" minOccurs="1" maxOccurs="1"/>
//	<element name="paramDigest" type="xsd:base64Binary" minOccurs="1" maxOccurs="1"/>
//	<element name="authData" type="tcs:TPM-AUTH" minOccurs="1" maxOccurs="1"/>
//	</sequence>
//	</complexType>    
//	------------------------------------------------------------------------------------------------//
	static public TcTcsLoadkeyInfo convertTcsLoadkeyInfo(TCSLOADKEYINFO in){
		TcTcsLoadkeyInfo retval = new TcTcsLoadkeyInfo();

		retval.setAuthData(convertTcsAuth(in.getAuthData()));
		retval.setKeyUuid(convertTssUuid(in.getKeyUUID()));
		retval.setParamDigest(new TcTpmDigest(TcBlobData.newByteArray(in.getParamDigest())));
		retval.setParentKeyUuid(convertTssUuid(in.getParentKeyUUID()));

		return retval;
	}

	static public TCSLOADKEYINFO convertTcsLoadkeyInfo(TcTcsLoadkeyInfo in){
		TCSLOADKEYINFO retval = new TCSLOADKEYINFO();

		retval.setAuthData(convertTcsAuth(in.getAuthData()));
		retval.setKeyUUID(convertTssUuid(in.getKeyUuid()));
		retval.setParamDigest(in.getParamDigest().getEncoded().asByteArray());
		retval.setParentKeyUUID(convertTssUuid(in.getKeyUuid()));

		return retval;
	}


//	------------------------------------------------------------------------------------------------//
//	<complexType name="TPM-AUTH">
//	<sequence>
//	<element name="AuthHandle" type="xsd:unsignedInt" minOccurs="1" maxOccurs="1"/>
//	<element name="NonceOdd" type="xsd:base64Binary" minOccurs="1" maxOccurs="1" nillable="false"/>
//	<element name="NonceEven" type="xsd:base64Binary" minOccurs="1" maxOccurs="1" nillable="false"/>
//	<element name="fContinueAuthSession" type="xsd:byte" minOccurs="1" maxOccurs="1"/>
//	<element name="HMAC" type="xsd:base64Binary" minOccurs="1" maxOccurs="1" nillable="false"/>
//	</sequence>
//	</complexType>
//	------------------------------------------------------------------------------------------------//
	static public TcTcsAuth convertTcsAuth(TPMAUTH in){
		TcTcsAuth retval = new TcTcsAuth();

		retval.setAuthHandle(in.getAuthHandle().longValue());
		retval.setContAuthSession(in.getFContinueAuthSession() == 1 ? true : false);
		retval.setHmac(new TcTpmAuthdata(TcBlobData.newByteArray(in.getHMAC())));
		retval.setNonceEven(new TcTpmNonce(TcBlobData.newByteArray(in.getNonceEven())));
		retval.setNonceOdd(new TcTpmNonce(TcBlobData.newByteArray(in.getNonceOdd())));

		return retval;
	}

	static public TPMAUTH convertTcsAuth(TcTcsAuth in){
		TPMAUTH  retval = new TPMAUTH();

		retval.setAuthHandle(new UnsignedInt(in.getAuthHandle()));

		retval.setFContinueAuthSession(in.getContAuthSession() ? (byte)1 : (byte)0);
		retval.setHMAC(in.getHmac().getEncoded().asByteArray());
		retval.setNonceEven(in.getNonceEven().getEncoded().asByteArray());
		retval.setNonceOdd(in.getNonceOdd().getEncoded().asByteArray());

		return retval;
	}


//	------------------------------------------------------------------------------------------------//
//	<complexType name="TPM-CMK-AUTH">
//	<sequence>
//	<element name="migrationAuthorityDigest" type="xsd:base64Binary" minOccurs="1" maxOccurs="1"/>
//	<element name="destinationKeyDigest" type="xsd:base64Binary" minOccurs="1" maxOccurs="1"/>
//	<element name="sourceKeyDigest" type="xsd:base64Binary" minOccurs="1" maxOccurs="1"/>
//	</sequence>
//	</complexType>
//	------------------------------------------------------------------------------------------------//
	static public TcTpmCmkAuth convertTpmCmkAuth(TPMCMKAUTH in) {
		TcTpmCmkAuth retval = new TcTpmCmkAuth();

		retval.setDestinationKeyDigest(new TcTpmDigest(TcBlobData.newByteArray(in.getDestinationKeyDigest())));
		retval.setMigrationAuthorityDigest(new TcTpmDigest(TcBlobData.newByteArray(in.getMigrationAuthorityDigest())));
		retval.setSourceKeyDigest(new TcTpmDigest(TcBlobData.newByteArray(in.getSourceKeyDigest())));

		return retval;
	}

	static public TPMCMKAUTH convertTpmCmkAuth(TcTpmCmkAuth in) {
		TPMCMKAUTH retval = new TPMCMKAUTH();

		retval.setDestinationKeyDigest(in.getDestinationKeyDigest().getEncoded().asByteArray());
		retval.setMigrationAuthorityDigest(in.getMigrationAuthorityDigest().getEncoded().asByteArray());
		retval.setSourceKeyDigest(in.getSourceKeyDigest().getEncoded().asByteArray());

		return retval;
	}


//	------------------------------------------------------------------------------------------------//
//	<complexType name="TSS-KM-KEYINFO">
//	<sequence>
//	<element name="versionInfo" type="tcs:TSS-VERSION" minOccurs="1" maxOccurs="1"/>
//	<element name="keyUUID" type="tcs:TSS-UUID" minOccurs="1" maxOccurs="1"/>
//	<element name="parentKeyUUID" type="tcs:TSS-UUID" minOccurs="1" maxOccurs="1"/>
//	<element name="bAuthDataUsage" type="xsd:byte" minOccurs="1" maxOccurs="1"/>
//	<element name="fIsLoaded" type="xsd:byte" minOccurs="1" maxOccurs="1"/>
//	<element name="rgbVendorData" type="xsd:base64Binary" minOccurs="0" maxOccurs="1" nillable="true"/>
//	</sequence>
//	</complexType>
//	------------------------------------------------------------------------------------------------//
	static public TcTssKmKeyinfo convertTssKmKeyinfo(TSSKMKEYINFO in) {
		TcTssKmKeyinfo retval = new TcTssKmKeyinfo();

		retval.setVersionInfo(convertTssVersion(in.getVersionInfo()));
		retval.setKeyUuid(in.getKeyUUID() == null ? null : convertTssUuid(in.getKeyUUID()));
		retval.setParentKeyUuid(in.getParentKeyUUID() == null ? null : convertTssUuid(in.getParentKeyUUID()));
		retval.setAuthDataUsage(new Short(in.getBAuthDataUsage()));
		retval.setLoaded(in.getFIsLoaded() == 1 ? true : false);
		retval.setVendorData(TcBlobData.newByteArray(in.getRgbVendorData()));

		return retval;
	}

	static public TSSKMKEYINFO convertTssKmKeyinfo(TcTssKmKeyinfo in) {
		TSSKMKEYINFO retval = new TSSKMKEYINFO();

		retval.setVersionInfo(convertTssVersion(in.getVersionInfo()));
		retval.setKeyUUID(convertTssUuid(in.getKeyUuid()));
		retval.setParentKeyUUID(convertTssUuid(in.getParentKeyUuid()));
		retval.setBAuthDataUsage(((Short)in.getAuthDataUsage()).byteValue());
		retval.setFIsLoaded(in.isLoaded() ? (byte)1 : (byte)0);
		retval.setRgbVendorData(in.getVendorData().asByteArray());

		return retval;
	}
}