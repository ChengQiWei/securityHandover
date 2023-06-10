///*
// * Copyright (C) 2007 IAIK, Graz University of Technology
// * authors: Thomas Winkler
// */
//
//package iaik.tc.tss.impl.java.tsp;
//
//
//import iaik.tc.tss.api.constants.tpm.TcTpmConstants;
//import iaik.tc.tss.api.constants.tsp.TcTssConstants;
//import iaik.tc.tss.api.constants.tsp.TcTssErrors;
//import iaik.tc.tss.api.exceptions.common.TcTssException;
//import iaik.tc.tss.api.exceptions.tsp.TcTspException;
//import iaik.tc.tss.api.structs.common.TcBlobData;
//import iaik.tc.tss.api.structs.tpm.TcTpmNvAttributes;
//import iaik.tc.tss.api.structs.tpm.TcTpmNvDataPublic;
//import iaik.tc.tss.api.structs.tpm.TcTpmPcrInfoShort;
//import iaik.tc.tss.api.tspi.TcIAuthObject;
//import iaik.tc.tss.api.tspi.TcIContext;
//import iaik.tc.tss.api.tspi.TcINvRam;
//import iaik.tc.tss.api.tspi.TcIPcrComposite;
//import iaik.tc.tss.api.tspi.TcIPolicy;
//import iaik.tc.utils.misc.Utils;
//
//public class TcNvRam_Experimental extends TcAuthObject implements TcINvRam {
//
//	// TODO: do not ship this class!
//	
//	/**
//	 * Internal data structure holding all information required for the NV area.
//	 */
//	protected TcTpmNvDataPublic nvDataPub_ = new TcTpmNvDataPublic();
//
//	protected Boolean nvAreaDefined_ = new Boolean(false);
//
//
//	/*************************************************************************************************
//	 * Hidden constructor (factory pattern).
//	 */
//	protected TcNvRam_Experimental(TcIContext context) throws TcTssException
//	{
//		super(context);
//
//		TcPcrCompositeInfoShort pcrComp = (TcPcrCompositeInfoShort) context_
//				.createPcrCompositeObject(TcTssConstants.TSS_PCRS_STRUCT_INFO_SHORT);
//		TcBlobData pcrCompBlob = pcrComp.getPcrStructEncoded();
//
//		TcTpmPcrInfoShort pcrInfoRead = new TcTpmPcrInfoShort(pcrCompBlob);
//		TcTpmPcrInfoShort pcrInfoWrite = new TcTpmPcrInfoShort((TcBlobData) pcrCompBlob.clone());
//
//		// --
//
//		TcTpmNvAttributes permission = new TcTpmNvAttributes();
//		permission.setTag(TcTpmConstants.TPM_TAG_NV_ATTRIBUTES);
//		permission.setAttributes(0);
//
//		// --
//
//		nvDataPub_.setTag(TcTpmConstants.TPM_TAG_NV_DATA_PUBLIC);
//		nvDataPub_.setDataSize(0);
//		nvDataPub_.setNvIndex(TcTpmConstants.TPM_NV_INDEX_TRIAL);
//		nvDataPub_.setPcrInfoRead(pcrInfoRead);
//		nvDataPub_.setPcrInfoWrite(pcrInfoWrite);
//		nvDataPub_.setPermission(permission);
//		nvDataPub_.setReadSTClear(false);
//		nvDataPub_.setWriteDefine(false);
//		nvDataPub_.setWriteSTClear(false);
//	}
//
//	/*
//	 * (non-Javadoc)
//	 * @see iaik.tss.api.tspi.TcINvRam#defineSpace(iaik.tss.api.tspi.TcIPcrComposite, iaik.tss.api.tspi.TcIPcrComposite)
//	 */
//	public void defineSpace(TcIPcrComposite readPcrComposite, TcIPcrComposite writePcrComposite)
//		throws TcTssException
//	{
//		throw new TcTspException(TcTssErrors.TSS_E_NOTIMPL, "Not implemented");
//
////		checkContext();
////
////		synchronized (nvDataPub_) {
////			synchronized (nvAreaDefined_) {
////				if (nvAreaDefined_.booleanValue()) {
////					throw new TcTspException(TcTssErrors.TSS_E_NV_AREA_EXIST,
////							"NV area already defined for this NV object.");
////				}
////
////				// read or writePcrComposite is null: set empty PCR structures
////				if (readPcrComposite == null || writePcrComposite == null) {
////					TcPcrCompositeInfoShort pcrComp = (TcPcrCompositeInfoShort) context_
////							.createPcrCompositeObject(TcTssConstants.TSS_PCRS_STRUCT_INFO_SHORT);
////					TcBlobData pcrCompBlob = pcrComp.getPcrStructEncoded();
////
////					if (readPcrComposite == null) {
////						TcTpmPcrInfoShort pcrInfoRead = new TcTpmPcrInfoShort(pcrCompBlob);
////						nvDataPub_.setPcrInfoRead(pcrInfoRead);
////					}
////					if (writePcrComposite == null) {
////						TcTpmPcrInfoShort pcrInfoWrite = new TcTpmPcrInfoShort((TcBlobData) pcrCompBlob.clone());
////						nvDataPub_.setPcrInfoWrite(pcrInfoWrite);
////					}
////				}
////
////				Object[] osapData = createOsapSession(TcTpmConstants.TPM_ET_NV, nvDataPub_.getNvIndex(),
////						getUsagePolicy());
////				TcTcsAuth osapSession = (TcTcsAuth) osapData[0];
////				TcTpmEncauth encAuth = (TcTpmEncauth) osapData[1];
////				TcTpmSecret osapSecret = (TcTpmSecret) osapData[2];
////
////				TcTspInternal.TspNvDefineSpace_Internal(context_, nvDataPub_, encAuth, osapSession,
////						osapSecret);
////
////				nvAreaDefined_ = new Boolean(true);
////			}
////		}
//
//	}
//
//
//	/*
//	 * (non-Javadoc)
//	 * 
//	 * @see iaik.tss.api.tspi.TcINvRam#readValue(long, long)
//	 */
//	public TcBlobData readValue(long offset, long dataLength)
//		throws TcTssException
//	{
//		checkContextOpenAndConnected();
//
//		synchronized (nvDataPub_) {
//			synchronized (nvAreaDefined_) {
//				if (!nvAreaDefined_.booleanValue()) {
//					throw new TcTspException(TcTssErrors.TSS_E_NV_AREA_NOT_EXIST,
//							"No NV area defined for this NV object.");
//				}
//
//				// nvAreaDefined_ = new Boolean(false);
//			}
//		}
//
//		throw new TcTspException(TcTssErrors.TSS_E_NOTIMPL, "Not implemented");
//	}
//
//
//	/*
//	 * (non-Javadoc)
//	 * 
//	 * @see iaik.tss.api.tspi.TcINvRam#releaseSpace()
//	 */
//	public void releaseSpace() throws TcTssException
//	{
//		checkContextOpenAndConnected();
//		throw new TcTspException(TcTssErrors.TSS_E_NOTIMPL, "Not implemented");
//	}
//
//
//	/*
//	 * (non-Javadoc)
//	 * 
//	 * @see iaik.tss.api.tspi.TcINvRam#writeValue(long, iaik.tss.api.structs.TcBlobData)
//	 */
//	public void writeValue(long offset, TcBlobData dataToWrite)
//		throws TcTssException
//	{
//		checkContextOpenAndConnected();
//		throw new TcTspException(TcTssErrors.TSS_E_NOTIMPL, "Not implemented");
//	}
//
//
//	public void changeAuth(TcIAuthObject parentObject, TcIPolicy newPolicy) throws TcTssException
//	{
//		
//	}
//	
//	
//	// - - - - - Getters and Setter - - - - -
//
//	/*************************************************************************************************
//	 * Initialize getter methods.
//	 */
//
//	protected void initAttribGetters()
//	{
//		addGetterUINT32(TcTssConstants.TSS_TSPATTRIB_NV_DATASIZE, "getAttribNvDataSize");
//		addGetterUINT32(TcTssConstants.TSS_TSPATTRIB_NV_INDEX, "getAttribNvIndex");
//		addGetterUINT32(TcTssConstants.TSS_TSPATTRIB_NV_PCR, "getAttribNvPcrUint32");
//		addGetterUINT32(TcTssConstants.TSS_TSPATTRIB_NV_PERMISSIONS, "getAttribNvPermissions");
//		addGetterUINT32(TcTssConstants.TSS_TSPATTRIB_NV_STATE, "getAttribNvState");
//
//		addGetterData(TcTssConstants.TSS_TSPATTRIB_NV_PCR, "getAttribNvPcrData");
//
//	}
//
//
//	/*************************************************************************************************
//	 * Initialize setter methods.
//	 */
//	protected void initAttribSetters()
//	{
//		addSetterData(TcTssConstants.TSS_TSPATTRIB_NV_INDEX, "setAttribNvIndex");
//		addSetterData(TcTssConstants.TSS_TSPATTRIB_NV_PERMISSIONS, "setAttribNvPermissions");
//		addSetterData(TcTssConstants.TSS_TSPATTRIB_NV_DATASIZE, "setAttrivNvDatasize");
//	}
//
//
//	/*************************************************************************************************
//	 * This method sets the {@link TcTssConstants#TSS_TSPATTRIB_NV_INDEX} attribute. Note that this
//	 * method is not standardized as part of the TSPI.
//	 * 
//	 * @TSS_1_2_EA 377
//	 * 
//	 * @param subFlag Ignored.
//	 * @param attrib The index of the NV storage area associated with this object.
//	 */
//	public void setAttribNvIndex(long subFlag, long attrib)
//	{
//		synchronized (nvDataPub_) {
//			nvDataPub_.setNvIndex(attrib);
//		}
//	}
//
//
//	/*************************************************************************************************
//	 * This method sets the value of the permissions. Note that this method is not standardized as
//	 * part of the TSPI.
//	 * 
//	 * @TSS_1_2_EA 377
//	 * 
//	 * @param subFlag Ignored.
//	 * @param attrib The value of the permissions.
//	 */
//	public void setAttribNvPermissions(long subFlag, long attrib)
//	{
//		synchronized (nvDataPub_) {
//			nvDataPub_.getPermission().setAttributes(attrib);
//		}
//	}
//
//
//	/*************************************************************************************************
//	 * This method sets the size of the defined NV storage area. Note that this method is not
//	 * standardized as part of the TSPI.
//	 * 
//	 * @TSS_1_2_EA 377
//	 * 
//	 * @param subFlag Ignored.
//	 * @param attrib The size of the NV storage area.
//	 */
//	public void setAttrivNvDatasize(long subFlag, long attrib)
//	{
//		synchronized (nvDataPub_) {
//			nvDataPub_.setDataSize(attrib);
//		}
//	}
//
//
//	/*************************************************************************************************
//	 * This method returns the nvIndex currently set for this object. Note that this method is not
//	 * standardized as part of the TSPI.
//	 * 
//	 * @TSS_1_2_EA 378
//	 * 
//	 * @param subFlag Ignored.
//	 * 
//	 * @return The NV index.
//	 */
//	public long getAttribNvIndex(long subFlag)
//	{
//		synchronized (nvDataPub_) {
//			return nvDataPub_.getNvIndex();
//		}
//	}
//
//
//	/*************************************************************************************************
//	 * This method returns the nvPermissions currently set for this object. Note that this method is
//	 * not standardized as part of the TSPI.
//	 * 
//	 * @TSS_1_2_EA 378
//	 * 
//	 * @param subFlag Ignored.
//	 * 
//	 * @return The NV permissions.
//	 */
//	public long getAttribNvPermissions(long subFlag)
//	{
//		synchronized (nvDataPub_) {
//			return nvDataPub_.getPermission().getAttributes();
//		}
//	}
//
//
//	/*************************************************************************************************
//	 * This method returns the NV data size currently set for this object. Note that this method is
//	 * not standardized as part of the TSPI.
//	 * 
//	 * @TSS_1_2_EA 378
//	 * 
//	 * @param subFlag Ignored.
//	 * 
//	 * @return The NV data size.
//	 */
//	public long getAttribNvDataSize(long subFlag)
//	{
//		synchronized (nvDataPub_) {
//			return nvDataPub_.getDataSize();
//		}
//	}
//
//
//	/*************************************************************************************************
//	 * This method returns NV state information as specified by subFlag. Note that this method is not
//	 * standardized as part of the TSPI.
//	 * 
//	 * @TSS_1_2_EA 378
//	 * 
//	 * @param subFlag Valid subFlags are:
//	 *          <ul>
//	 *          <li> {@link TcTssConstants#TSS_TSPATTRIB_NVSTATE_READSTCLEAR} (returns boolean)
//	 *          <li> {@link TcTssConstants#TSS_TSPATTRIB_NVSTATE_WRITESTCLEAR} (returns boolean)
//	 *          <li> {@link TcTssConstants#TSS_TSPATTRIB_NVSTATE_WRITEDEFINE} (returns boolean)
//	 *          </ul>
//	 * 
//	 * @return The requested data.
//	 * 
//	 * @throws {@link TcTssException}
//	 */
//	public long getAttribNvState(long subFlag) throws TcTssException
//	{
//		long retVal = 0;
//
//		synchronized (nvDataPub_) {
//
//			if (subFlag == TcTssConstants.TSS_TSPATTRIB_NVSTATE_READSTCLEAR) {
//				retVal = Utils.booleanToByte(nvDataPub_.getReadSTClear());
//
//			} else if (subFlag == TcTssConstants.TSS_TSPATTRIB_NVSTATE_WRITESTCLEAR) {
//				retVal = Utils.booleanToByte(nvDataPub_.getWriteSTClear());
//
//			} else if (subFlag == TcTssConstants.TSS_TSPATTRIB_NVSTATE_WRITEDEFINE) {
//				retVal = Utils.booleanToByte(nvDataPub_.getWriteDefine());
//
//			} else {
//				throw new TcTspException(TcTssErrors.TSS_E_INVALID_ATTRIB_SUBFLAG);
//			}
//		}
//		return retVal;
//	}
//
//
//	/*************************************************************************************************
//	 * This method returns PCR information as specified by subFlag. Note that this method is not
//	 * standardized as part of the TSPI.
//	 * 
//	 * @TSS_1_2_EA 378
//	 * 
//	 * @param subFlag Valid subFlags are:
//	 *          <ul>
//	 *          <li> {@link TcTssConstants#TSS_TSPATTRIB_NVPCR_READLOCALITYATRELEASE}
//	 *          <li> {@link TcTssConstants#TSS_TSPATTRIB_NVPCR_WRITELOCALITYATRELEASE}
//	 *          </ul>
//	 * 
//	 * @return The requested data.
//	 * 
//	 * @throws {@link TcTssException}
//	 */
//	public long getAttribNvPcrUint32(long subFlag) throws TcTssException
//	{
//		long retVal = 0;
//
//		synchronized (nvDataPub_) {
//			if (subFlag == TcTssConstants.TSS_TSPATTRIB_NVPCR_READLOCALITYATRELEASE) {
//				retVal = nvDataPub_.getPcrInfoRead().getLocalityAtRelease();
//
//			} else if (subFlag == TcTssConstants.TSS_TSPATTRIB_NVPCR_WRITELOCALITYATRELEASE) {
//				retVal = nvDataPub_.getPcrInfoWrite().getLocalityAtRelease();
//
//			} else {
//				throw new TcTspException(TcTssErrors.TSS_E_INVALID_ATTRIB_SUBFLAG);
//			}
//		}
//
//		return retVal;
//	}
//
//
//	/*************************************************************************************************
//	 * This method returns PCR information as specified by subFlag. Note that this method is not
//	 * standardized as part of the TSPI.
//	 * 
//	 * @TSS_1_2_EA 380
//	 * 
//	 * @param subFlag Valid subFlags are:
//	 *          <ul>
//	 *          <li> {@link TcTssConstants#TSS_TSPATTRIB_NVPCR_READPCRSELECTION}
//	 *          <li> {@link TcTssConstants#TSS_TSPATTRIB_NVPCR_READDIGESTATRELEASE}
//	 *          <li> {@link TcTssConstants#TSS_TSPATTRIB_NVPCR_WRITEPCRSELECTION}
//	 *          <li> {@link TcTssConstants#TSS_TSPATTRIB_NVPCR_WRITEDIGESTATRELEASE}
//	 *          </ul>
//	 * 
//	 * @return The requested data.
//	 * 
//	 * @throws {@link TcTssException}
//	 */
//	public TcBlobData getAttribNvPcrData(long subFlag) throws TcTssException
//	{
//		TcBlobData retVal = null;
//
//		synchronized (nvDataPub_) {
//			if (subFlag == TcTssConstants.TSS_TSPATTRIB_NVPCR_READPCRSELECTION) {
//				retVal = nvDataPub_.getPcrInfoRead().getPcrSelection().getEncoded();
//
//			} else if (subFlag == TcTssConstants.TSS_TSPATTRIB_NVPCR_READDIGESTATRELEASE) {
//				retVal = nvDataPub_.getPcrInfoRead().getDigestAtRelease().getEncoded();
//
//			} else if (subFlag == TcTssConstants.TSS_TSPATTRIB_NVPCR_WRITEPCRSELECTION) {
//				retVal = nvDataPub_.getPcrInfoWrite().getPcrSelection().getEncoded();
//
//			} else if (subFlag == TcTssConstants.TSS_TSPATTRIB_NVPCR_WRITEDIGESTATRELEASE) {
//				retVal = nvDataPub_.getPcrInfoWrite().getDigestAtRelease().getEncoded();
//
//			} else {
//				throw new TcTspException(TcTssErrors.TSS_E_INVALID_ATTRIB_SUBFLAG);
//			}
//		}
//
//		return retVal;
//	}
//}
