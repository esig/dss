/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 *
 * This file is part of the "DSS - Digital Signature Services" project.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.client.crl;

import java.security.cert.X509CRL;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Date;
import java.util.List;

import javax.sql.DataSource;

import org.apache.commons.collections.CollectionUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.x509.CertificateToken;
import eu.europa.esig.dss.x509.crl.CRLSource;
import eu.europa.esig.dss.x509.crl.CRLToken;
import eu.europa.esig.dss.x509.crl.CRLUtils;
import eu.europa.esig.dss.x509.crl.CRLValidity;

/**
 * CRLSource that retrieve information from a JDBC datasource
 *
 *
 */

public class JdbcCacheCRLSource implements CRLSource {

	private static final Logger LOG = LoggerFactory.getLogger(JdbcCacheCRLSource.class);

	/**
	 * used in the init method to check if the table exists
	 */
	public static final String SQL_INIT_CHECK_EXISTENCE = "SELECT COUNT(*) FROM CACHED_CRL";

	/**
	 * used in the init method to create the table, if not existing: ID (char40  = SHA1 length) and DATA (blob)
	 */
	public static final String SQL_INIT_CREATE_TABLE = "CREATE TABLE CACHED_CRL (ID CHAR(40), DATA LONGVARBINARY)";

	/**
	 * used in the find method to select the crl via the id
	 */
	public static final String SQL_FIND_QUERY = "SELECT * FROM CACHED_CRL WHERE ID = ?";

	/**
	 * used in the find method when selecting the crl via the id to get the ID (char20) from the resultset
	 */
	public static final String SQL_FIND_QUERY_ID = "ID";

	/**
	 * used in the find method when selecting the crl via the id to get the DATA (blob) from the resultset
	 */
	public static final String SQL_FIND_QUERY_DATA = "DATA";

	/**
	 * used via the find method to insert a new record
	 */
	public static final String SQL_FIND_INSERT = "INSERT INTO CACHED_CRL (ID, DATA) VALUES (?, ?)";

	/**
	 * used via the find method to update an existing record via the id
	 */
	public static final String SQL_FIND_UPDATE = "UPDATE CACHED_CRL SET DATA = ? WHERE ID = ?";

	private OnlineCRLSource cachedSource;

	private DataSource dataSource;

	private String sqlInitCheckExistence = SQL_INIT_CHECK_EXISTENCE;

	private String sqlInitCreateTable = SQL_INIT_CREATE_TABLE;

	private String sqlFindQuery = SQL_FIND_QUERY;

	private String sqlFindQueryId = SQL_FIND_QUERY_ID;

	private String sqlFindQueryData = SQL_FIND_QUERY_DATA;

	private String sqlFindInsert = SQL_FIND_INSERT;

	private String sqlFindUpdate = SQL_FIND_UPDATE;

	/**
	 * The default constructor for JdbcCRLSource.
	 */
	public JdbcCacheCRLSource() {

	}

	@Override
	public CRLToken findCrl(final CertificateToken certificateToken) throws DSSException {

		if (certificateToken == null) {
			return null;
		}
		final CertificateToken issuerToken = certificateToken.getIssuerToken();
		if (issuerToken == null) {
			return null;
		}
		final List<String> crlUrls = cachedSource.getCrlUrl(certificateToken);
		if (CollectionUtils.isEmpty(crlUrls)) {
			return null;
		}
		final String crlUrl = crlUrls.get(0);
		LOG.info("CRL's URL for " + certificateToken.getAbbreviation() + " : " + crlUrl);
		try {

			final String key = DSSUtils.getSHA1Digest(crlUrl);
			final CachedCRL dbCrl = findCrlInDB(key);
			if (dbCrl != null) {

				X509CRL x509Crl = DSSUtils.loadCRL(dbCrl.getCrl());
				if (x509Crl.getNextUpdate().after(new Date())) {

					LOG.debug("CRL in cache");
					final CRLValidity crlValidity = CRLUtils.isValidCRL(x509Crl, issuerToken);
					final CRLToken crlToken = new CRLToken(certificateToken, crlValidity);
					if (crlToken.isValid()) {

						return crlToken;
					}
				}
			}
			final CRLToken crlToken = cachedSource.findCrl(certificateToken);
			if ((crlToken != null) && crlToken.isValid()) {

				if (dbCrl == null) {

					LOG.info("CRL not in cache");
					insertCrlInDb(key, crlToken.getEncoded());
				} else {

					LOG.debug("CRL expired");
					updateCrlInDb(key, crlToken.getEncoded());
				}
			}
			return crlToken;
		} catch (SQLException e) {

			LOG.info("Error with the cache data store");
		}
		return null;
	}

	/**
	 * @param cachedSource the cachedSource to set
	 */
	public void setCachedSource(OnlineCRLSource cachedSource) {

		this.cachedSource = cachedSource;
	}

	/**
	 * Initialise the DAO by creating the table if it does not exist.
	 *
	 * @throws Exception
	 */
	private void initDao() throws Exception {

		/* Create the table iff it doesn't exist. */
		if (!tableExists()) {
			createTable();
		}
	}

	/**
	 * Create the cache crl table if it does not exist
	 *
	 * @throws java.sql.SQLException
	 */
	private void createTable() throws SQLException {

		Connection c = null;
		Statement s = null;
		try {
			c = getDataSource().getConnection();
			s = c.createStatement();
			s.executeQuery(sqlInitCreateTable);
			c.commit();
		} finally {
			closeQuietly(c, s, null);
		}

	}

	/**
	 * Check if the cache table exists
	 *
	 * @return true if the table exists.
	 */
	private boolean tableExists() {

		Connection c = null;
		Statement s = null;
		boolean tableExists;
		try {
			c = getDataSource().getConnection();
			s = c.createStatement();
			s.executeQuery(sqlInitCheckExistence);
			tableExists = true;
		} catch (SQLException e) {
			tableExists = false;
		} finally {
			closeQuietly(c, s, null);
		}
		return tableExists;
	}

	/**
	 * Get the cached CRL from the datasource
	 *
	 * @param key the key of the CRL
	 * @return the cached crl
	 * @throws java.sql.SQLException
	 */
	private CachedCRL findCrlInDB(String key) throws SQLException {

		Connection c = null;
		PreparedStatement s = null;
		ResultSet rs = null;
		try {
			c = getDataSource().getConnection();
			s = c.prepareStatement(sqlFindQuery);
			s.setString(1, key);
			rs = s.executeQuery();
			if (rs.next()) {
				CachedCRL cached = new CachedCRL();
				cached.setKey(rs.getString(sqlFindQueryId));
				cached.setCrl(rs.getBytes(sqlFindQueryData));
				return cached;
			}
		} finally {
			closeQuietly(c, s, rs);
		}

		return null;
	}

	/**
	 * Insert a new CRL into the cache
	 *
	 * @param key     the key
	 * @param encoded the encoded CRL
	 * @throws java.sql.SQLException
	 */
	private void insertCrlInDb(String key, byte[] encoded) throws SQLException {

		Connection c = null;
		PreparedStatement s = null;
		ResultSet rs = null;
		try {
			c = getDataSource().getConnection();
			s = c.prepareStatement(sqlFindInsert);
			s.setString(1, key);
			s.setBytes(2, encoded);
			s.executeUpdate();
		} finally {
			closeQuietly(c, s, rs);
		}
	}

	/**
	 * Update the cache with the CRL
	 *
	 * @param key     the key
	 * @param encoded the encoded CRL
	 * @throws java.sql.SQLException
	 */
	private void updateCrlInDb(String key, byte[] encoded) throws SQLException {

		Connection c = null;
		PreparedStatement s = null;
		ResultSet rs = null;
		try {
			c = getDataSource().getConnection();
			s = c.prepareStatement(sqlFindUpdate);
			s.setBytes(1, encoded);
			s.setString(2, key);
			s.executeUpdate();
		} finally {
			closeQuietly(c, s, rs);
		}

	}

	/**
	 * @return the dataSource
	 */
	private DataSource getDataSource() {

		return dataSource;
	}

	/**
	 * @param dataSource the dataSource to set
	 * @throws Exception
	 */
	public void setDataSource(DataSource dataSource) throws Exception {

		this.dataSource = dataSource;
		initDao();
	}

	/**
	 * used in the init method to check if the table exists
	 *
	 * @return the value
	 */
	public String getSqlInitCheckExistence() {

		return sqlInitCheckExistence;
	}

	/**
	 * used in the init method to check if the table exists
	 *
	 * @param sqlInitCheckExistence the value
	 */
	public void setSqlInitCheckExistence(final String sqlInitCheckExistence) {

		this.sqlInitCheckExistence = sqlInitCheckExistence;
	}

	/**
	 * used in the init method to create the table, if not existing: ID (char20) and DATA (blob)
	 *
	 * @return the value
	 */
	public String getSqlInitCreateTable() {

		return sqlInitCreateTable;
	}

	/**
	 * used in the init method to create the table, if not existing: ID (char20) and DATA (blob)
	 *
	 * @param sqlInitCreateTable the value
	 */
	public void setSqlInitCreateTable(final String sqlInitCreateTable) {

		this.sqlInitCreateTable = sqlInitCreateTable;
	}

	/**
	 * used in the find method to select the crl via the id
	 *
	 * @return the value
	 */
	public String getSqlFindQuery() {

		return sqlFindQuery;
	}

	/**
	 * used in the find method to select the crl via the id
	 *
	 * @param sqlFindQuery the value
	 */
	public void setSqlFindQuery(final String sqlFindQuery) {

		this.sqlFindQuery = sqlFindQuery;
	}

	/**
	 * used in the find method when selecting the crl via the id to get the ID (char20) from the resultset
	 *
	 * @return the value
	 */
	public String getSqlFindQueryId() {

		return sqlFindQueryId;
	}

	/**
	 * used in the find method when selecting the crl via the id to get the ID (char20) from the resultset
	 *
	 * @param sqlFindQueryId the value
	 */
	public void setSqlFindQueryId(final String sqlFindQueryId) {

		this.sqlFindQueryId = sqlFindQueryId;
	}

	/**
	 * used in the find method when selecting the crl via the id to get the DATA (blob) from the resultset
	 *
	 * @return the value
	 */
	public String getSqlFindQueryData() {

		return sqlFindQueryData;
	}

	/**
	 * used in the find method when selecting the crl via the id to get the DATA (blob) from the resultset
	 *
	 * @param sqlFindQueryData the value
	 */
	public void setSqlFindQueryData(final String sqlFindQueryData) {

		this.sqlFindQueryData = sqlFindQueryData;
	}

	/**
	 * used via the find method to insert a new record
	 *
	 * @return the value
	 */
	public String getSqlFindInsert() {

		return sqlFindInsert;
	}

	/**
	 * used via the find method to insert a new record
	 *
	 * @param sqlFindInsert the value
	 */
	public void setSqlFindInsert(final String sqlFindInsert) {

		this.sqlFindInsert = sqlFindInsert;
	}

	/**
	 * used via the find method to update an existing record via the id
	 *
	 * @return the value
	 */
	public String getSqlFindUpdate() {

		return sqlFindUpdate;
	}

	/**
	 * used via the find method to update an existing record via the id
	 *
	 * @param sqlFindUpdate the value
	 */
	public void setSqlFindUpdate(final String sqlFindUpdate) {

		this.sqlFindUpdate = sqlFindUpdate;
	}

	/**
	 * Close the statement and connection and resultset without throwing the exception
	 *
	 * @param c  the connection
	 * @param s  the statement
	 * @param rs the ResultSet
	 */
	private void closeQuietly(Connection c, Statement s, ResultSet rs) {

		try {
			if (rs != null) {
				rs.close();
			}
			if (s != null) {
				s.close();
			}
			if (c != null) {
				c.close();
			}
		} catch (SQLException e) {
			// purposely empty
		}

	}
}