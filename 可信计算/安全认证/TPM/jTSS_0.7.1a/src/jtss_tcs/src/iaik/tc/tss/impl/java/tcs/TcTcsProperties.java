/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Thomas Winkler
 */

package iaik.tc.tss.impl.java.tcs;

import iaik.tc.tss.api.constants.tcs.TcTcsErrors;
import iaik.tc.tss.api.exceptions.tcs.TcTcsException;
import iaik.tc.utils.properties.Properties;
import iaik.tc.utils.logging.Log;

import java.io.File;
import java.net.URL;

public class TcTcsProperties {

	public static String TCS_INI_SEC_PS = "PersistentStorage";

	public static String TCS_INI_KEY_PS_TYPE = "type";

	protected static String TCS_INI_FILE = "jtss_tcs.ini";

	protected static String PROPERTY_TCS_INI_FILE = "jtss.tcs.ini.file";

	public static String TCS_INI_SEC_EVENTMGR = "EventManager";

	public static String TCS_INI_KEY_EVENTMGR_TYPE = "type";

	
	public static String TCS_INI_SEC_TPMDEVICE = "TDDLLinuxDevice";

	public static String TCS_INI_KEY_LINUX_TPMDEVICE = "LinuxTpmDevice";
	
	
	public static String TCS_INI_SEC_TPMSOCKET = "TDDLSocket";

	public static String TCS_INI_KEY_TPMSOCKET_TPMSERVER_NAME = "TPMServerName";
	public static String TCS_INI_KEY_TPMSOCKET_TPMSERVER_PORT = "TPMServerPort";
	
	
	public static String TCS_INI_SEC_TDDL = "TDDL";
	
	public static String TCS_INI_KEY_TDDL_TDDLIMPLEMENTATION = "TDDLImplementation";
	
	
	protected static Properties instance_ = null;

	private TcTcsProperties() {
	}

	protected static Properties getTcsProperties() throws TcTcsException {

		if (System.getProperty(PROPERTY_TCS_INI_FILE) != null) {
			String filename = "";

			try {

				filename = System.getProperty(PROPERTY_TCS_INI_FILE);
				return new Properties(filename);

			} catch (Exception e) {
				String msg = "Failed to find or open ini file specified as "
						+ PROPERTY_TCS_INI_FILE + " at: " + filename;
				Log.err(msg);
				throw new TcTcsException(TcTcsErrors.TCS_E_FAIL, msg);
			}
		}

		// get the path where the classes/the jar file is located
		// This is a tricky case when all four possible combinations of
		// .class/.jar and linux/windows are considered

		String className = TcTcsProperties.class.getName().replace(".",
				File.separator)
				+ ".class";

		URL url;

		url = TcTcsProperties.class.getClassLoader().getResource(className);

		if (url == null) // special case: Windows AND from jar
		{
			String classNameInJar = TcTcsProperties.class.getName().replace(
					".", "/")
					+ ".class";
			url = TcTcsProperties.class.getClassLoader().getResource(classNameInJar);
		}

		try {

			String iniPath;
			String urlString = url.toString();

			if (urlString.substring(0, 4).equals("jar:")) // from jar file
			{

				urlString = urlString.substring("jar:".length(), urlString
						.length());
				urlString = urlString.substring(0, urlString.lastIndexOf("!"));
				urlString = urlString.substring(0, urlString.lastIndexOf("/"));

				URL iniPathURL = new URL(urlString);
				File f = new File(iniPathURL.toURI());
				iniPath = f.getPath() + File.separator;

			} else // from class file
			{
				File f = new File(url.toURI());
				String path = f.getPath();
				iniPath = path.substring(0, path.length() - className.length());

			}
			
			if(new File(iniPath + TCS_INI_FILE).isFile()) {
				Properties prop = new Properties(iniPath + TCS_INI_FILE);
				return prop;
			}
			
			// third option: get Default TCS Properties
			return getDefaultTcsProperties();


		} catch (Exception e) {
			String msg = "Failed to find or open ini file: " + TCS_INI_FILE;
			throw new TcTcsException(TcTcsErrors.TCS_E_FAIL, msg);
		}
	}

	public static Properties getInstance() throws TcTcsException {
		if (instance_ == null) {
			instance_ = getTcsProperties();
		}

		return instance_;
	}
	
	protected static Properties getDefaultTcsProperties() throws TcTcsException {
		
		Properties prop = new Properties();
		
		prop.addSection("PersistentStorage");
		prop.setProperty("PersistentStorage", "type",
				"iaik.tc.tss.impl.ps.TcTssSystemPsDatabase");
		
		prop.addSection("EventManager");
		prop.setProperty("EventManager", "type",
				"iaik.tc.tss.impl.java.tcs.eventmgr.TcTssEventMgrFlatFile");
		
		prop.addSection("TcTssSystemPsFileSystem");
		//prop.setProperty("TcTssSystemPsFileSystem", "folder",
		//		(getDefaultHomejTSSPath() + File.separator + "ps" + File.separator + "system"));
		
		prop.addSection("TcTssSystemPsDatabase");
		prop.setProperty("TcTssSystemPsDatabase", "database",
				(getDefaultHomejTSSPath() + File.separator + "ps" + File.separator + "system"));
		
		prop.addSection("TcTssSystemPsTrousers");
		
		prop.addSection("TcTcsEventMgrFlatFile");
		prop.setProperty("TcTcsEventMgrFlatFile", "file", 
				(getDefaultHomejTSSPath() + File.separator + "eventlog.sml"));
		
		prop.addSection("SOAP");
		prop.setProperty("SOAP", "portnumber", "30004");
		prop.setProperty("SOAP", "debug", "true");	
		
		prop.addSection("TDDL");
		prop.setProperty("TDDL", "TDDLImplementation", "");	
		
		prop.addSection("TDDLLinuxDevice");
		prop.setProperty("TDDLLinuxDevice", "LinuxTpmDevice", "");
		
		prop.addSection("TDDLSocket");
		prop.setProperty("TDDLSocket", "TPMServerName", "localhost");
		prop.setProperty("TDDLSocket", "TPMServerPort", "30005");
		
		return prop;
	}
	
	
	protected static String getDefaultHomejTSSPath() {
			
		String osName = System.getProperty("os.name");
		
		//default path for Windows
		if(osName.contains("Windows")) {
			String appData = System.getenv("APPDATA");
			return (appData + File.separator + "jTSS");
		}
		//default path for Linux
		if(osName.contains("Linux")) {
			String homePath = System.getProperty("user.home");
			return (homePath + File.separator + ".jTSS");
		}
		
		//default path rest
		return (System.getProperty("user.home") + File.separator + "jTSS");
	}
}
