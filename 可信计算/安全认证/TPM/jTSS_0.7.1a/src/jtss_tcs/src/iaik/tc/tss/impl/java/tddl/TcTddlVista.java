/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.impl.java.tddl;


import iaik.tc.tss.api.constants.tcs.TcTddlErrors;
import iaik.tc.tss.api.exceptions.tcs.TcTddlException;
import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.utils.logging.Log;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;

/**
 * TDDL library for use with Windows Vista. This library used the Java Native Interface (JNI) to
 * access the TPM Base Services (TBS) that are part of Windows Vista. TBS provides access to 1.2
 * TPMs using a TIS driver that is shipped together with Windows Vista or higher.
 * This class first attempts to use a 32-bit support Dynamic LinK Library and a 64-bit version as fallback.
 */
public class TcTddlVista extends TcTddl {

	protected static String LIB_NAME = "jTssTddlVista";
	protected static String LIB_NAME_x64 = "jTssTddlVistax64";
	
	protected static String LIB_SUFFIX = ".dll";

	static {

			Log.info("Windows Vista or higher detected. Using TBS based TPM access.");
			if (loadLibFromPath()) {
				Log.info("Native Windows DLL loaded from library path.");
			} else {
				if (loadLibFromJar()) {
					Log.info("Native Windows DLL loaded from jar file.");
				} else {
					Log.err("Unable to load native (32-bit or 64-bit) Vista DLL (neither from library path nor from jar file).");
					System.exit(0);
				}
			}
		
	}


	protected static boolean loadLibFromPath()
	{
		String libName = LIB_NAME + LIB_SUFFIX;
		String libName64 = LIB_NAME_x64 + LIB_SUFFIX;
		
		boolean result = false;
		
		try {
			System.loadLibrary(libName);
			result = true;
		} catch (UnsatisfiedLinkError e) {
			Log.info("Native 32-bit Windows DLL loading from path failed. Attempting 64-bit version.");
			try {
				System.loadLibrary(libName64);
				result = true;
			} catch (UnsatisfiedLinkError f)
			{
				//no further attempts
			}
			
		}
		
		return result;
	}


	protected static boolean loadLibFromJar()
	{
		String libName = LIB_NAME + LIB_SUFFIX;
		String libName64 = LIB_NAME_x64 + LIB_SUFFIX;
		
				
		if (loadLibFromJarHelper(libName)) {
			return true;
		} else {
			Log.info("Native 32-bit Windows DLL loading from jar file failed. Attempting 64-bit version.");
			return loadLibFromJarHelper(libName64);
		}
				
		
	}
	
	
	protected static boolean loadLibFromJarHelper(String resourceName)
	{
		InputStream is = ClassLoader.getSystemClassLoader().getResourceAsStream(resourceName);
		if (is == null) {
			Log.debug("Unable to get native library from jar file.");
			return false;
		}

		File tmpLibFile = null;
		try {
			byte[] lib = new byte[is.available()];
			is.read(lib);
			String path = System.getProperty("java.io.tmpdir");
			path = new File(path).getAbsolutePath();
			tmpLibFile = new File(path + File.separator + resourceName);
			FileOutputStream os = new FileOutputStream(tmpLibFile);
			os.write(lib);
			os.close();
		} catch (IOException e) {
			Log.debug("Unable to write native library to temporary directory.");
			return false;
		}

		try {
			System.load(tmpLibFile.getAbsolutePath().toString());
		} catch (UnsatisfiedLinkError e) {
			Log.debug("Loading native library failed.");
			return false;
		} finally {
			tmpLibFile.deleteOnExit();
		}

		return true;
	}

	protected boolean open_ = false;

	protected long tbsContext_ = -1;


	public void open() throws TcTddlException
	{
		tbsContext_ = tbsContextCreate();
		open_ = true;
	}


	public boolean isOpen()
	{
		return open_;
	}


	public void close() throws TcTddlException
	{
		if (isOpen()) {
			tbsContextClose(tbsContext_);
			open_ = false;
		}
	}


	protected void finalize() throws Throwable
	{
		close();
	}


	public TcBlobData transmitData(TcBlobData command) throws TcTddlException
	{
		if (isOpen()) {
			byte[] tpmOutData = tbsSubmitCommand(tbsContext_, command.asByteArray());
			return TcBlobData.newByteArray(tpmOutData);
		} else {
			throw new TcTddlException(TcTddlErrors.TDDL_E_FAIL, "TDDL connection is not open");
		}
	}


	protected native long tbsContextCreate() throws TcTddlException;


	protected native void tbsContextClose(long tbsContext) throws TcTddlException;


	protected native byte[] tbsSubmitCommand(long tbsContext, byte[] command) throws TcTddlException;


	// This TDDL does not implement the functionality that is not absolutely required by a TSS.

	/*************************************************************************************************
	 * This method is not implemented by this TDDL.
	 */
	public void cancel() throws TcTddlException
	{
		throw new TcTddlException(TcTddlErrors.TDDL_E_FAIL, "The cancel method is not implemented.");
	}


	/*************************************************************************************************
	 * This method is not implemented by this TDDL.
	 */
	public void getCapability() throws TcTddlException
	{
		throw new TcTddlException(TcTddlErrors.TDDL_E_FAIL,
				"The getCapability method is not implemented.");
	}


	/*************************************************************************************************
	 * This method is not implemented by this TDDL.
	 */
	public void setCapability() throws TcTddlException
	{
		throw new TcTddlException(TcTddlErrors.TDDL_E_FAIL,
				"The setCapability method is not implemented.");
	}


	/*************************************************************************************************
	 * This method is not implemented by this TDDL.
	 */
	public void getStatus() throws TcTddlException
	{
		throw new TcTddlException(TcTddlErrors.TDDL_E_FAIL, "The getStatus method is not implemented.");
	}


	/*************************************************************************************************
	 * This method is not implemented by this TDDL.
	 */
	public void setStatus() throws TcTddlException
	{
		throw new TcTddlException(TcTddlErrors.TDDL_E_FAIL, "The setStatus method is not implemented.");
	}


	/*************************************************************************************************
	 * This method is not implemented by this TDDL.
	 */
	public void powerManagement() throws TcTddlException
	{
		throw new TcTddlException(TcTddlErrors.TDDL_E_FAIL,
				"The powerManagement method is not implemented.");
	}


	/*************************************************************************************************
	 * This method is not implemented by this TDDL.
	 */
	public void powerManagementControl() throws TcTddlException
	{
		throw new TcTddlException(TcTddlErrors.TDDL_E_FAIL,
				"The powerManagementControl method is not implemented.");
	}

}
