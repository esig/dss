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

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Timestamp;
import java.sql.Types;
import java.util.Date;
import java.util.List;

import javax.sql.DataSource;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSASN1Utils;
import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.SignatureAlgorithm;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.x509.CertificateToken;
import eu.europa.esig.dss.x509.crl.CRLSource;
import eu.europa.esig.dss.x509.crl.CRLToken;
import eu.europa.esig.dss.x509.crl.CRLValidity;

/**
 * CRLSource that retrieve information from a JDBC datasource
 */
public class JdbcCacheCRLSource implements CRLSource {

	private static final Logger LOG = LoggerFactory.getLogger(JdbcCacheCRLSource.class);

	/**
	 * used in the init method to check if the table exists
	 */
	private static final String SQL_INIT_CHECK_EXISTENCE = "SELECT COUNT(*) FROM CACHED_CRL";

	/**
	 * used in the init method to create the table, if not existing: ID (char40 = SHA1 length) and DATA (blob)
	 */
	private static final String SQL_INIT_CREATE_TABLE = "CREATE TABLE CACHED_CRL (ID CHAR(40), DATA LONGVARBINARY, SIGNATURE_ALGORITHM VARCHAR(20), THIS_UPDATE TIMESTAMP, NEXT_UPDATE TIMESTAMP, EXPIRED_CERTS_ON_CRL TIMESTAMP, ISSUER LONGVARBINARY, ISSUER_PRINCIPAL_MATCH BOOLEAN, SIGNATURE_INTACT BOOLEAN, CRL_SIGN_KEY_USAGE BOOLEAN, UNKNOWN_CRITICAL_EXTENSION BOOLEAN, SIGNATURE_INVALID_REASON VARCHAR(256))";

	/**
	 * used in the find method to select the crl via the id
	 */
	private static final String SQL_FIND_QUERY = "SELECT * FROM CACHED_CRL WHERE ID = ?";

	/**
	 * used in the find method when selecting the crl via the id to get the ID (char20) from the resultset
	 */
	private static final String SQL_FIND_QUERY_ID = "ID";

	/**
	 * used in the find method when selecting the crl via the id to get the DATA (blob) from the resultset
	 */
	private static final String SQL_FIND_QUERY_DATA = "DATA";

	/**
	 * used in the find method when selecting the issuer certificate via the id to get the ISSUER (blob) from the
	 * resultset
	 */
	private static final String SQL_FIND_QUERY_ISSUER = "ISSUER";

	private static final String SQL_FIND_QUERY_THIS_UPDATE = "THIS_UPDATE";

	private static final String SQL_FIND_QUERY_NEXT_UPDATE = "NEXT_UPDATE";

	private static final String SQL_FIND_QUERY_EXPIRED_CERTS_ON_CRL = "EXPIRED_CERTS_ON_CRL";

	private static final String SQL_FIND_QUERY_SIGNATURE_ALGO = "SIGNATURE_ALGORITHM";

	private static final String SQL_FIND_QUERY_ISSUER_PRINCIPAL_MATCH = "ISSUER_PRINCIPAL_MATCH";

	private static final String SQL_FIND_QUERY_SIGNATURE_INTACT = "SIGNATURE_INTACT";

	private static final String SQL_FIND_QUERY_CRL_SIGN_KEY_USAGE = "CRL_SIGN_KEY_USAGE";

	private static final String SQL_FIND_QUERY_UNKNOWN_CRITICAL_EXTENSION = "UNKNOWN_CRITICAL_EXTENSION";

	private static final String SQL_FIND_QUERY_SIGNATURE_INVALID_REASON = "SIGNATURE_INVALID_REASON";

	/**
	 * used via the find method to insert a new record
	 */
	private static final String SQL_FIND_INSERT = "INSERT INTO CACHED_CRL (ID, DATA, SIGNATURE_ALGORITHM, THIS_UPDATE, NEXT_UPDATE, EXPIRED_CERTS_ON_CRL, ISSUER, ISSUER_PRINCIPAL_MATCH, SIGNATURE_INTACT, CRL_SIGN_KEY_USAGE, UNKNOWN_CRITICAL_EXTENSION, SIGNATURE_INVALID_REASON) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";

	/**
	 * used via the find method to update an existing record via the id
	 */
	private static final String SQL_FIND_UPDATE = "UPDATE CACHED_CRL SET DATA = ?, SIGNATURE_ALGORITHM = ?, THIS_UPDATE = ?, NEXT_UPDATE = ?, EXPIRED_CERTS_ON_CRL = ?, ISSUER = ?, ISSUER_PRINCIPAL_MATCH = ?, SIGNATURE_INTACT = ?, CRL_SIGN_KEY_USAGE = ?, UNKNOWN_CRITICAL_EXTENSION = ?, SIGNATURE_INVALID_REASON = ?  WHERE ID = ?";

	private OnlineCRLSource cachedSource;

	private DataSource dataSource;

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
		final List<String> crlUrls = DSSASN1Utils.getCrlUrls(certificateToken);
		if (Utils.isCollectionEmpty(crlUrls)) {
			return null;
		}
		final String crlUrl = crlUrls.get(0);
		LOG.info("CRL's URL for " + certificateToken.getAbbreviation() + " : " + crlUrl);
		try {

			final String key = DSSUtils.getSHA1Digest(crlUrl);
			final CRLValidity storedValidity = findCrlInDB(key);
			if (storedValidity != null) {
				if (storedValidity.getNextUpdate().after(new Date())) {
					LOG.debug("CRL in cache");
					final CRLToken crlToken = new CRLToken(certificateToken, storedValidity);
					crlToken.setSourceURL(crlUrl);
					if (crlToken.isValid()) {
						return crlToken;
					}
				}
			}
			final CRLToken crlToken = cachedSource.findCrl(certificateToken);
			if ((crlToken != null) && crlToken.isValid()) {
				if (storedValidity == null) {
					LOG.info("CRL '{}' not in cache", crlUrl);
					insertCrlInDb(key, crlToken.getCrlValidity());
				} else {
					LOG.debug("CRL '{}' expired", crlUrl);
					updateCrlInDb(key, crlToken.getCrlValidity());
				}
			}
			return crlToken;
		} catch (SQLException e) {
			LOG.info("Error with the cache data store", e);
		}
		return null;
	}

	/**
	 * @param cachedSource
	 *            the cachedSource to set
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
		/* Create the table if it doesn't exist. */
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
			s.executeQuery(SQL_INIT_CREATE_TABLE);
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
			s.executeQuery(SQL_INIT_CHECK_EXISTENCE);
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
	 * @param key
	 *            the key of the CRL
	 * @return the cached crl
	 * @throws java.sql.SQLException
	 */
	private CRLValidity findCrlInDB(String key) throws SQLException {
		Connection c = null;
		PreparedStatement s = null;
		ResultSet rs = null;
		try {
			c = getDataSource().getConnection();
			s = c.prepareStatement(SQL_FIND_QUERY);
			s.setString(1, key);
			rs = s.executeQuery();
			if (rs.next()) {
				CRLValidity cached = new CRLValidity();
				cached.setKey(rs.getString(SQL_FIND_QUERY_ID));
				cached.setCrlEncoded(rs.getBytes(SQL_FIND_QUERY_DATA));
				cached.setSignatureAlgorithm(SignatureAlgorithm.valueOf(rs.getString(SQL_FIND_QUERY_SIGNATURE_ALGO)));
				cached.setThisUpdate(rs.getTimestamp(SQL_FIND_QUERY_THIS_UPDATE));
				cached.setNextUpdate(rs.getTimestamp(SQL_FIND_QUERY_NEXT_UPDATE));
				cached.setExpiredCertsOnCRL(rs.getTimestamp(SQL_FIND_QUERY_EXPIRED_CERTS_ON_CRL));
				cached.setIssuerToken(DSSUtils.loadCertificate(rs.getBytes(SQL_FIND_QUERY_ISSUER)));
				cached.setCrlSignKeyUsage(rs.getBoolean(SQL_FIND_QUERY_CRL_SIGN_KEY_USAGE));
				cached.setUnknownCriticalExtension(rs.getBoolean(SQL_FIND_QUERY_UNKNOWN_CRITICAL_EXTENSION));
				cached.setIssuerX509PrincipalMatches(rs.getBoolean(SQL_FIND_QUERY_ISSUER_PRINCIPAL_MATCH));
				cached.setSignatureIntact(rs.getBoolean(SQL_FIND_QUERY_SIGNATURE_INTACT));
				cached.setSignatureInvalidityReason(rs.getString(SQL_FIND_QUERY_SIGNATURE_INVALID_REASON));
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
	 * @param key
	 *            the key
	 * @param encoded
	 *            the encoded CRL
	 * @throws java.sql.SQLException
	 */
	private void insertCrlInDb(String key, CRLValidity token) throws SQLException {
		Connection c = null;
		PreparedStatement s = null;
		ResultSet rs = null;
		try {
			c = getDataSource().getConnection();
			s = c.prepareStatement(SQL_FIND_INSERT);

			s.setString(1, key);

			s.setBytes(2, token.getCrlEncoded());

			s.setString(3, token.getSignatureAlgorithm().name());

			if (token.getThisUpdate() != null) {
				s.setTimestamp(4, new Timestamp(token.getThisUpdate().getTime()));
			} else {
				s.setNull(4, Types.TIMESTAMP);
			}

			if (token.getNextUpdate() != null) {
				s.setTimestamp(5, new Timestamp(token.getNextUpdate().getTime()));
			} else {
				s.setNull(5, Types.TIMESTAMP);
			}

			if (token.getExpiredCertsOnCRL() != null) {
				s.setTimestamp(6, new Timestamp(token.getExpiredCertsOnCRL().getTime()));
			} else {
				s.setNull(6, Types.TIMESTAMP);
			}

			s.setBytes(7, token.getIssuerToken().getEncoded());
			s.setBoolean(8, token.isIssuerX509PrincipalMatches());
			s.setBoolean(9, token.isSignatureIntact());
			s.setBoolean(10, token.isCrlSignKeyUsage());
			s.setBoolean(11, token.isUnknownCriticalExtension());
			s.setString(12, token.getSignatureInvalidityReason());
			s.executeUpdate();
		} finally {
			closeQuietly(c, s, rs);
		}
	}

	/**
	 * Update the cache with the CRL
	 *
	 * @param key
	 *            the key
	 * @param encoded
	 *            the encoded CRL
	 * @throws java.sql.SQLException
	 */
	private void updateCrlInDb(String key, CRLValidity token) throws SQLException {
		Connection c = null;
		PreparedStatement s = null;
		ResultSet rs = null;
		try {
			c = getDataSource().getConnection();
			s = c.prepareStatement(SQL_FIND_UPDATE);
			s.setBytes(1, token.getCrlEncoded());

			s.setString(2, token.getSignatureAlgorithm().name());

			if (token.getThisUpdate() != null) {
				s.setTimestamp(3, new Timestamp(token.getThisUpdate().getTime()));
			} else {
				s.setNull(3, Types.TIMESTAMP);
			}

			if (token.getNextUpdate() != null) {
				s.setTimestamp(4, new Timestamp(token.getNextUpdate().getTime()));
			} else {
				s.setNull(4, Types.TIMESTAMP);
			}

			if (token.getExpiredCertsOnCRL() != null) {
				s.setTimestamp(5, new Timestamp(token.getExpiredCertsOnCRL().getTime()));
			} else {
				s.setNull(5, Types.TIMESTAMP);
			}

			s.setBytes(6, token.getIssuerToken().getEncoded());
			s.setBoolean(7, token.isIssuerX509PrincipalMatches());
			s.setBoolean(8, token.isSignatureIntact());
			s.setBoolean(9, token.isCrlSignKeyUsage());
			s.setBoolean(10, token.isUnknownCriticalExtension());
			s.setString(11, token.getSignatureInvalidityReason());

			s.setString(12, key);
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
	 * @param dataSource
	 *            the dataSource to set
	 * @throws Exception
	 */
	public void setDataSource(DataSource dataSource) throws Exception {
		this.dataSource = dataSource;
		initDao();
	}

	/**
	 * Close the statement and connection and resultset without throwing the exception
	 *
	 * @param c
	 *            the connection
	 * @param s
	 *            the statement
	 * @param rs
	 *            the ResultSet
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