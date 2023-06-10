/*
 * Copyright (C) 2007 IAIK, Graz University of Technology
 * authors: Ronald Toegl, Thomas Winkler
 */

package iaik.tc.tss.impl.java.tsp.internal;

import iaik.tc.tss.api.exceptions.tsp.TcTspException;
import iaik.tc.utils.logging.Log;
import iaik.tc.utils.properties.Properties;

import java.io.File;
import java.net.URL;

public class TcTspProperties {

	public static String TSP_INI_SEC_PS = "PersistentStorage";

	public static String TSP_INI_KEY_PS_TYPE = "type";

	protected static String TSP_INI_FILE = "jtss_tsp.ini";

	protected static String PROPERTY_TSP_INI_FILE = "jtss.tsp.ini.file";

	protected static Properties instance_ = null;

	private TcTspProperties() {
	}

	protected static Properties getTspProperties() throws TcTspException {
		
		// fist option: look if TSP Properties already exist
		if (System.getProperty(PROPERTY_TSP_INI_FILE) != null) {
			String filename = "";

			try {

				filename = System.getProperty(PROPERTY_TSP_INI_FILE);
				return new Properties(filename);

			} catch (Exception e) {
				String msg = "Failed to find or open ini file specified as "
						+ PROPERTY_TSP_INI_FILE + " at: " + filename;
				Log.err(msg);
			}
		}

		// second option: read *.ini file if available
		
		// get the path where the classes/the jar file is located
		// This is a tricky case when all four possible combinations of
		// .class/.jar and linux/windows are considered

		String className = TcTspProperties.class.getName().replace(".",
				File.separator)
				+ ".class";

		URL url;

		url = TcTspProperties.class.getClassLoader().getResource(className);

		if (url == null) // special case: Windows AND from jar
		{
			String classNameInJar = TcTspProperties.class.getName().replace(
					".", "/")
					+ ".class";
			url = TcTspProperties.class.getClassLoader().getResource(classNameInJar);
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
				String path = new File(url.toURI()).getPath();
				iniPath = path.substring(0, path.length() - className.length());

			}

			String iniFilePath = iniPath + TSP_INI_FILE;
			String iniFilePathDebian = iniPath + "ini" + File.separator
					+ TSP_INI_FILE;
			if (new File(iniFilePath).isFile()) {
				return new Properties(iniFilePath);
			} else if (new File(iniFilePathDebian).isFile()) {
				return new Properties(iniFilePathDebian);
			} else {
				Log.debug("tried to load configuration from " + iniFilePath
						+ " and " + iniFilePathDebian + " - file not found");
			}

		} catch (Exception e) {
			Log.info("Failed to find or open ini file: " + TSP_INI_FILE);
		}

		// third option: get Default TSP Properties
		Log.info("Could not load configuration from " + TSP_INI_FILE
				+ " - using default config.");
		return getDefaultTspProperties();
	}

	public static Properties getInstance() throws TcTspException {
		
		if (instance_ == null) {
			instance_ = getTspProperties();
		}
		return instance_;
	}
	
	protected static Properties getDefaultTspProperties() throws TcTspException {
		
		Properties prop = new Properties();
		
		prop.addSection("PersistentStorage");
		prop.setProperty("PersistentStorage", "type",
				"iaik.tc.tss.impl.ps.TcTssUserPsDatabase");
		
		prop.addSection("TcTssUserPsFileSystem");
		prop.setProperty("TcTssUserPsFileSystem", "folder",
				(getDefaultHomejTSSPath() + File.separator + "ps" + File.separator + "user"));
		
		prop.addSection("TcTssUserPsDatabase");
		prop.setProperty("TcTssUserPsDatabase", "database",
				(getDefaultHomejTSSPath() + File.separator + "ps" + File.separator + "user"));
		
		prop.addSection("TcTssUserPsTrousers");
		
		prop.addSection("BindingFactory");
		prop.setProperty("BindingFactory", "type", 
				"iaik.tc.tss.impl.java.tsp.TcTssSOAPCallFactory");
		
		prop.addSection("SOAP");
		prop.setProperty("SOAP", "portnumber", "30004");
		prop.setProperty("SOAP", "relativepath", 
				"/axis/services/TSSCoreServiceBindingImpl");
		prop.setProperty("SOAP", "useremotehost", "false");
		prop.setProperty("SOAP", "remotehost", "http://127.0.0.1");	
		
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

