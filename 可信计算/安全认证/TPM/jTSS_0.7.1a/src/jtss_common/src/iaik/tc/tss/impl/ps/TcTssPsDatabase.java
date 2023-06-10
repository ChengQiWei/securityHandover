/*
 * Copyright (C) 2008 IAIK, Graz University of Technology
 * authors: Thomas Holzmann
 */

package iaik.tc.tss.impl.ps;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;

import iaik.tc.tss.api.constants.tcs.TcTcsErrors;
import iaik.tc.tss.api.constants.tpm.TcTpmConstants;
import iaik.tc.tss.api.exceptions.common.TcTssException;
import iaik.tc.tss.api.exceptions.tcs.TcTcsException;
import iaik.tc.tss.api.structs.common.TcBlobData;
import iaik.tc.tss.api.structs.tpm.TcTpmKey;
import iaik.tc.tss.api.structs.tpm.TcTpmKey12;
import iaik.tc.tss.api.structs.tpm.TcTpmStructVer;
import iaik.tc.tss.api.structs.tsp.TcTssKmKeyinfo;
import iaik.tc.tss.api.structs.tsp.TcTssUuid;
import iaik.tc.utils.properties.Properties;
import iaik.tc.utils.logging.Log;
import iaik.tc.utils.misc.Utils;

public abstract class TcTssPsDatabase extends TcTssPersistentStorage {
	String databasePath_ = null;
	String keysTable_ = null;
	String parentsTable_ = null;
	Connection dbConnection_ = null;

	/**
	 * The constructor. It calls the parent constructor, tries to get the
	 * database name out of the properties, connects to the database and creates
	 * the key table if it not exists.
	 * 
	 * @param properties
	 *            contains the configuration data
	 */
	public TcTssPsDatabase(Properties properties) {
		super(properties);

		try {
			databasePath_ = properties_.getProperty(this.getClass()
					.getSimpleName(), "database");
		} catch (IllegalArgumentException e) {
			Log.warn(this.getClass().getSimpleName()
					+ " section or 'database' key not found in ");
			throw e;
		}
		keysTable_ = "keys";

		// load the DB driver
		try {
			Class.forName("org.hsqldb.jdbcDriver");
			dbConnection_ = getConnection();
			if (!tableExists(dbConnection_, keysTable_)) {
				Statement statement = dbConnection_.createStatement();
				statement.executeQuery("CREATE TABLE " + keysTable_
						+ " (uuid VARCHAR(36) NOT NULL, "
						+ "key LONGVARCHAR NOT NULL, "
						+ "uuid_parent VARCHAR(36) NOT NULL,  "
						+ "PRIMARY KEY (uuid))");
			}
		} catch (Exception e) {
			Log.err("Unable to initialize database.");
			e.printStackTrace();
		} finally {
			try {
				dbConnection_.close();
			} catch (Exception e) {e.printStackTrace();}
		}

	}

	//--------------------------------------------------------------------------
	// --------------------
	// Methods for connecting to database and closing the connection
	//--------------------------------------------------------------------------
	// --------------------

	protected void preOperations() throws TcTssException {
		try {
			dbConnection_ = getConnection();
		} catch (SQLException e) {
			throw new TcTcsException(TcTcsErrors.TCS_E_INTERNAL_ERROR, e
					.getMessage());
		}
	}

	protected void postOperations() throws TcTssException {
		try {
			// dbConnection_.commit();
			dbConnection_.close();
		} catch (SQLException e) {
			throw new TcTcsException(TcTcsErrors.TCS_E_INTERNAL_ERROR, e
					.getMessage());
		}
	}

	// ///////////////////////////////////////////////////////////////
	//
	// The implementation methods.
	// 
	// ///////////////////////////////////////////////////////////////

	/*
	 * (non-Javadoc)
	 * 
	 * @see iaik.tc.tss.impl.ps.TcTssPersistentStorage#registerKeyImpl()
	 */
	protected void registerKeyImpl(TcTssUuid parentUuid, TcTssUuid keyUuid,
			TcBlobData key) throws TcTssException {
		// check if this UUID is already registered
		boolean alreadyRegistered = false;
		try {
			getRegisteredKeyBlobImpl(keyUuid);
			alreadyRegistered = true;
		} catch (TcTssException e) {
			alreadyRegistered = false;
		}
		if (alreadyRegistered)
			throw new TcTcsException(TcTcsErrors.TCS_E_KEY_ALREADY_REGISTERED,
					"The UUID " + keyUuid.toStringNoPrefix()
							+ " is already registered.");

		try {
			Statement statement = dbConnection_.createStatement();
			statement.executeUpdate("INSERT INTO " + keysTable_ + " VALUES ( '"
					+ keyUuid.toStringNoPrefix() + "', '"
					+ key.toHexStringNoWrap().replace(" ", "") + "', '"
					+ parentUuid.toStringNoPrefix() + "')");
		} catch (SQLException e) {
			throw new TcTcsException(TcTcsErrors.TCS_E_INTERNAL_ERROR, e
					.getMessage());
		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * iaik.tc.tss.impl.ps.TcTssPersistentStorage#unregisterKeyImpl(iaik.tc.
	 * tss.api.structs.tsp.TcTssUuid)
	 */
	protected void unregisterKeyImpl(TcTssUuid keyUuid) throws TcTssException {
		try {
			PreparedStatement statement = dbConnection_
					.prepareStatement("DELETE FROM " + keysTable_
							+ " WHERE uuid='" + keyUuid.toStringNoPrefix()
							+ "'");
			// deletes the actual key
			statement.executeUpdate();

		} catch (SQLException e) {
			throw new TcTcsException(TcTcsErrors.TCS_E_INTERNAL_ERROR, e
					.getMessage());
		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * iaik.tc.tss.impl.ps.TcTssPersistentStorage#getRegisteredKeyBlobImpl(iaik
	 * .tc.tss.api.structs.tsp.TcTssUuid)
	 */
	protected TcBlobData getRegisteredKeyBlobImpl(TcTssUuid keyUuid)
			throws TcTssException {
		TcBlobData key = null;
		String keyString = null;
		try {
			Statement statement = dbConnection_.createStatement();
			String queryString = "SELECT key FROM " + keysTable_
					+ " WHERE uuid='" + keyUuid.toStringNoPrefix() + "'";
			ResultSet result = statement.executeQuery(queryString);
			if (!result.next())
				throw new TcTcsException(TcTcsErrors.TCS_E_KEY_NOT_REGISTERED,
						"Key is not registered:" + keyUuid.toString());
			keyString = result.getString("key");
		} catch (SQLException e) {
			throw new TcTcsException(TcTcsErrors.TCS_E_INTERNAL_ERROR, e
					.getMessage());
		}

		key = TcBlobData.newByteArray(Utils.hexStringToByteArray(keyString));
		return key;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * iaik.tc.tss.impl.ps.TcTssPersistentStorage#enumRegisteredKeysImpl(iaik
	 * .tc.tss.api.structs.tsp.TcTssUuid)
	 */
	protected abstract TcTssKmKeyinfo[] enumRegisteredKeysImpl(TcTssUuid keyUuid)
			throws TcTssException;

	// ///////////////////////////////////////////////////////////////
	//
	// Helper methods
	//
	// ///////////////////////////////////////////////////////////////

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * iaik.tc.tss.impl.ps.TcTssPersistentStorage#getKeyHierarachyforRegisteredKey
	 * (iaik.tc.tss.api.structs.tsp.TcTssUuid)
	 */
	protected ArrayList<String> getHierarchyForRegisteredKey(TcTssUuid keyUuid)
			throws TcTssException {
		ArrayList<String> keyUuids = new ArrayList<String>();
		TcTssUuid currentUuid = keyUuid;
		TcTssUuid currentParent = null;

		ArrayList<String> allUuids = getAllRegisteredKeyUuids();
		while (allUuids.contains(currentUuid.toStringNoPrefix())) {
			keyUuids.add(currentUuid.toStringNoPrefix());
			currentParent = getParentUuid(currentUuid);
			currentUuid = currentParent;
		}
		return keyUuids;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * iaik.tc.tss.impl.ps.TcTssPersistentStorage#getParentUuid(iaik.tc.tss.
	 * api.structs.tsp.TcTssUuid)
	 */
	protected TcTssUuid getParentUuid(TcTssUuid childUuid)
			throws TcTssException {
		TcTssUuid parent = new TcTssUuid();
		try {
			// if its the SRK just create a dummy parent
			if (getUuidSRK().equals(childUuid)) {
				parent = new TcTssUuid().init(0L, 0, 0, (short) 0, (short) 0,
						new short[] { 0, 0, 0, 0, 0, 0 });
			} else {
				Statement stmt = dbConnection_.createStatement();
				ResultSet result = stmt.executeQuery("SELECT uuid_parent FROM "
						+ keysTable_ + " WHERE uuid='"
						+ childUuid.toStringNoPrefix() + "'");
				result.next();
				String resultString = result.getString("uuid_parent");
				parent.initString(resultString);
			}
		} catch (SQLException e) {
			throw new TcTcsException(TcTcsErrors.TCS_E_INTERNAL_ERROR, e
					.getMessage());
		}

		return parent;

	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see iaik.tc.tss.impl.ps.TcTssPersistentStorage#enforceConsistency()
	 */
	protected void enforceConsistency() throws TcTssException {
		ArrayList<String> keyUuids = new ArrayList<String>();

		try {
			dbConnection_ = getConnection();
			Statement stmt = dbConnection_.createStatement();
			ResultSet result = stmt.executeQuery("SELECT COUNT(*) FROM "
					+ keysTable_);
			int counter;
			if (result.next()) {
				counter = Integer.parseInt(result.getString(1));
			} else
				throw new Exception();
			result = stmt.executeQuery("SELECT uuid FROM " + keysTable_);
			for (int i = 0; i < counter; i++) {
				result.next();
				String uuid = result.getString("uuid");
				keyUuids.add(uuid);
			}

			for (int i = 0; i < keyUuids.size(); i++) {
				TcTssUuid currentUuid = new TcTssUuid();
				currentUuid.initString(keyUuids.get(i));

				// first check if every UUID has a valid parent UUID (i.e. that
				// a UUID object
				// can be created out of the UUID string in the database.
				try {
					getParentUuid(currentUuid);

					// then check if the key is valid

					TcBlobData currentKeyBlob = getRegisteredKeyBlobImpl(currentUuid);

					// get a valid key structure

					TcBlobData tagKey12 = TcBlobData.newByteArray(new byte[] {
							0x00, TcTpmConstants.TPM_TAG_KEY12 });
					TcBlobData tag = TcBlobData.newByteArray(currentKeyBlob
							.getRange(0, 2));

					if (tag.equals(tagKey12)) {

						new TcTpmKey12(currentKeyBlob);

					} else {
						TcBlobData ver = TcBlobData.newByteArray(currentKeyBlob
								.getRange(0, 4));
						if (new TcTpmStructVer(ver)
								.equalsMinMaj(TcTpmStructVer.TPM_V1_1)) {
							new TcTpmKey(currentKeyBlob);
						} else {
							throw new TcTcsException(
									TcTcsErrors.TCS_E_BAD_PARAMETER,
									"The given blob seems to be neither a 1.1 nor a 1.2 TPM key blob.");
						}
					}

				} catch (Exception e) {
					throw e;
				}
			}

		} catch (TcTssException e) {
			throw e;
		} catch (Exception e) {
			throw new TcTcsException(TcTcsErrors.TCS_E_INTERNAL_ERROR, e
					.getMessage());
		} finally {
			try {
				dbConnection_.close();
			} catch (SQLException e) {
				throw new TcTcsException(TcTcsErrors.TCS_E_INTERNAL_ERROR, e
						.getMessage());
			}
		}
	}

	/**
	 * checks if the requested table exists
	 * 
	 * @param conn
	 *            the database connection
	 * @param tableName
	 *            the name of the table
	 * @return true if the table exists
	 */
	final protected boolean tableExists(final Connection conn,
			final String tableName) {
		PreparedStatement stmt = null;
		ResultSet results = null;
		try {
			stmt = conn.prepareStatement("SELECT COUNT(*) FROM " + tableName
					+ " WHERE 1 = 1");
			results = stmt.executeQuery();
			return true; // if table does exist, no rows will ever be returned
		} catch (SQLException e) {
			return false; // if table does not exist, an exception will be
							// thrown
		}
	}

	/**
	 * Attempts to connect to the database and returns the connection.
	 * 
	 * @return the new database connection
	 * @throws SQLException
	 *             if a database access error occurs
	 */
	protected Connection getConnection() throws SQLException {
		try {
			// stantalone mode
			// NOTE: for 1.8 you have to write jdbc:hsqldb:file:
			java.util.Properties property = new java.util.Properties();
			property.setProperty("shutdown", "true");
			Connection conn = DriverManager.getConnection("jdbc:hsqldb:file:"
					+ databasePath_, property);
			// server mode (for testing purposes)
			// Connection conn =
			// DriverManager.getConnection("jdbc:hsqldb:hsql://localhost/xdb",
			// "sa", "");
			// conn.setAutoCommit(true);
			return conn;
		} catch (SQLException e) {
			throw e;
		}
	}

	/**
	 * Returns all UUIDs stored in the database as ArrayList
	 * 
	 * @return all UUIDs
	 * @throws TcTssException
	 *             if a database error occurs
	 */
	protected ArrayList<String> getAllRegisteredKeyUuids()
			throws TcTssException {
		ArrayList<String> uuids = new ArrayList<String>();
		try {
			Statement stmt = dbConnection_.createStatement();
			ResultSet result = stmt.executeQuery("SELECT uuid FROM "
					+ keysTable_);
			String resultString;
			while (result.next()) {
				resultString = result.getString("uuid");
				uuids.add(resultString);
			}
		} catch (SQLException e) {
			throw new TcTcsException(TcTcsErrors.TCS_E_INTERNAL_ERROR, e
					.getMessage());
		}
		return uuids;
	}

	/**
	 * Checks if the database is empty
	 * 
	 * @return true if it is empty
	 * @throws TcTssException
	 *             if a database error occurs
	 */
	protected boolean isRepositoryEmpty() throws TcTssException {

		ArrayList<String> registeredKeys = getAllRegisteredKeyUuids();

		return registeredKeys.size() == 0;

	}

}
