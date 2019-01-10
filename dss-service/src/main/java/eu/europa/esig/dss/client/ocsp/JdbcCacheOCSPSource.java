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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */
package eu.europa.esig.dss.client.ocsp;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Timestamp;
import java.sql.Types;
import java.util.Date;

import javax.sql.DataSource;

import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSRevocationUtils;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.x509.CertificateToken;
import eu.europa.esig.dss.x509.ocsp.OCSPRespStatus;
import eu.europa.esig.dss.x509.ocsp.OCSPSource;
import eu.europa.esig.dss.x509.ocsp.OCSPToken;

/**
 * OCSPSource that retrieve information from a JDBC data-source.
 *
 * @version 1.0
 * @author akoepe
 */
public class JdbcCacheOCSPSource implements OCSPSource {
	private static final long serialVersionUID = 10480458323923489L;

	private static final Logger LOG = LoggerFactory.getLogger(JdbcCacheOCSPSource.class);

	/**
	 * used in the init method to check if the table exists
	 */
	private static final String SQL_INIT_CHECK_EXISTENCE = "SELECT COUNT(*) FROM CACHED_OCSP";

	/**
	 * used in the init method to create the table, if not existing: ID (char40
	 * = SHA1 length) and DATA (blob)
	 */
	private static final String SQL_INIT_CREATE_TABLE = "CREATE TABLE CACHED_OCSP (ID VARCHAR(100), DATA BLOB, LOC VARCHAR(200), STATUS INT, THIS_UPDATE TIMESTAMP, NEXT_UPDATE TIMESTAMP)";

	/**
	 * used in the find method to select the OCSP via the id
	 */
	private static final String SQL_FIND_QUERY = "SELECT * FROM CACHED_OCSP WHERE ID = ?";

	/**
	 * used in the find method when selecting the OCSP via the id to get the
	 * DATA (blob) from the resultSet
	 */
	private static final String SQL_FIND_QUERY_DATA = "DATA";

	private static final String SQL_FIND_QUERY_LOC = "LOC";

	private static final String SQL_FIND_QUERY_STATUS = "STATUS";

	/**
	 * used via the find method to insert a new record
	 */
	private static final String SQL_FIND_INSERT = "INSERT INTO CACHED_OCSP (ID, DATA, LOC, STATUS, THIS_UPDATE, NEXT_UPDATE) VALUES (?, ?, ?, ?, ?, ?)";

	/**
	 * used via the find method to update an existing record via the id
	 */
	private static final String SQL_FIND_UPDATE = "UPDATE CACHED_OCSP SET DATA = ?, LOC = ?, STATUS = ?, THIS_UPDATE = ?, NEXT_UPDATE = ?  WHERE ID = ?";

	private OnlineOCSPSource cachedSource;

	private DataSource dataSource;

	private Long cacheExpirationTime;

	/**
	 * Constructor.
	 */
	public JdbcCacheOCSPSource() {
	}

	/**
	 * Sets the expiration time for the cached files in milliseconds. If more
	 * time has passed from the cache file's last modified time, then a fresh
	 * copy is downloaded and cached, otherwise a cached copy is used.
	 *
	 * If the expiration time is not set, then the cache does not expire.
	 *
	 * @param cacheExpirationTimeInMilliseconds
	 */
	public void setCacheExpirationTime(final long cacheExpirationTimeInMilliseconds) {
		this.cacheExpirationTime = cacheExpirationTimeInMilliseconds;
	}

	/**
	 * Set the OnlineOCSPSource to use for getting the OCSP token / response.
	 *
	 * @param cachedSource
	 *            the cachedSource to set
	 */
	public void setCachedSource(final OnlineOCSPSource cachedSource) {
		this.cachedSource = cachedSource;
	}

	/**
	 * @param dataSource
	 *            the dataSource to set
	 * @throws Exception
	 */
	public void setDataSource(final DataSource dataSource) throws Exception {
		this.dataSource = dataSource;
		initDao();
	}

	/**
	 * {@inheritDoc}
	 * 
	 * @see eu.europa.esig.dss.x509.RevocationSource#getRevocationToken(eu.europa.esig.dss.x509.CertificateToken,
	 *      eu.europa.esig.dss.x509.CertificateToken)
	 */
	@Override
	public OCSPToken getRevocationToken(final CertificateToken certificateToken,
			final CertificateToken issuerCertificateToken) {
		if ((certificateToken == null) || (issuerCertificateToken == null)) {
			return null;
		}

		final CertificateID certId = DSSRevocationUtils.getOCSPCertificateID(certificateToken, issuerCertificateToken);
		final String key = DSSUtils.getSHA1Digest(getJdbcKey(certId));
		LOG.trace("--> JdbcCacheOCSPSource queried for {}", key);
		final OCSPToken token = findOCSPInDB(key, certId);
		if (token != null) {
			final Date nextUpdate = token.getNextUpdate();
			if ((nextUpdate != null) && nextUpdate.after(new Date())) {
				LOG.debug("OCSP token is in cache");
				return token;
			} else {
				LOG.debug("OCSP token not valid, get new one...");
			}
		}

		final OCSPToken newToken = cachedSource.getRevocationToken(certificateToken, issuerCertificateToken);
		if ((newToken != null) && newToken.isValid()) {
			newToken.extractInfo();
			if (token == null) {
				insertOCSPInDb(key, newToken);
			} else {
				updateOCSPInDb(key, newToken);
			}
		}

		return newToken;
	}

	/**
	 * Initialize the DAO by creating the table if it does not exist.
	 *
	 * @throws SQLException
	 *             if any error occurs
	 */
	private void initDao() throws SQLException {
		/* Create the table if it doesn't exist. */
		if (!tableExists()) {
			createTable();
		}
	}

	/**
	 * Create the cache OCSP table if it does not exist
	 *
	 * @throws SQLException
	 *             if any error occurs
	 */
	private void createTable() throws SQLException {
		Connection c = null;
		Statement s = null;
		try {
			c = getDataSource().getConnection();
			s = c.createStatement();
			s.executeQuery(SQL_INIT_CREATE_TABLE);
			c.commit();
		} catch (final SQLException e) {
			rollback(c);
			throw e;
		} finally {
			closeQuietly(c, s, null);
		}
	}

	/**
	 * Checks if the cache table exists.
	 *
	 * @return true if the table exists, otherwise false.
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
		} catch (final SQLException e) {
			tableExists = false;
		} finally {
			closeQuietly(c, s, null);
		}
		return tableExists;
	}

	/**
	 * Searches and returns the stored OCSP token for the supplied
	 * <code>key</code>.
	 *
	 * @param key
	 *            the OCSP token identifier
	 * @param certId
	 *            the OCSP token internal identifier
	 * @return the OCSP token or NULL if none was fund
	 */
	private OCSPToken findOCSPInDB(final String key, final CertificateID certId) {
		Connection c = null;
		PreparedStatement s = null;
		ResultSet rs = null;
		try {
			c = getDataSource().getConnection();
			s = c.prepareStatement(SQL_FIND_QUERY);
			s.setString(1, key);
			rs = s.executeQuery();
			if (rs.next()) {
				final byte[] data = rs.getBytes(SQL_FIND_QUERY_DATA);
				final String url = rs.getString(SQL_FIND_QUERY_LOC);
				final int status = rs.getInt(SQL_FIND_QUERY_STATUS);

				final OCSPResp ocspResp = new OCSPResp(data);
				final OCSPToken token = new OCSPToken();
				token.setResponseStatus(OCSPRespStatus.fromInt(status));
				token.setSourceURL(url);
				token.setCertId(certId);
				token.setAvailable(true);
				final BasicOCSPResp basicOCSPResp = (BasicOCSPResp) ocspResp.getResponseObject();
				token.setBasicOCSPResp(basicOCSPResp);
				LOG.debug("got OCSP token from db using key '{}'", key);
				return token;
			}
			c.commit();
		} catch (final Exception e) {
			LOG.error("Unable to select OCSP from the DB. Cause: " + e.getLocalizedMessage(), e);
			rollback(c);
		} finally {
			closeQuietly(c, s, rs);
		}

		return null;
	}

	/**
	 * Stores the supplied new OCSP <code>token</code> for the given
	 * <code>key</code>.
	 *
	 * @param key
	 *            identifier
	 * @param token
	 *            OCSP token
	 */
	private void insertOCSPInDb(final String key, final OCSPToken token) {
		Connection c = null;
		PreparedStatement s = null;
		final ResultSet rs = null;
		try {
			c = getDataSource().getConnection();
			s = c.prepareStatement(SQL_FIND_INSERT);

			s.setString(1, key);

			s.setBytes(2, token.getEncoded());

			if (token.getSourceURL() != null) {
				s.setString(3, token.getSourceURL());
			} else {
				s.setNull(3, Types.VARCHAR);
			}

			s.setInt(4, token.getResponseStatus().getStatusCode());

			if (token.getThisUpdate() != null) {
				s.setTimestamp(5, new Timestamp(token.getThisUpdate().getTime()));
			} else {
				s.setNull(5, Types.TIMESTAMP);
			}

			if (token.getNextUpdate() != null) {
				s.setTimestamp(6, new Timestamp(token.getNextUpdate().getTime()));
			} else if (cacheExpirationTime != null) {
				s.setTimestamp(6, new Timestamp(System.currentTimeMillis() + cacheExpirationTime));
			} else {
				s.setNull(6, Types.TIMESTAMP);
			}
			s.executeUpdate();
			c.commit();
			LOG.debug("OCSP token with key '{}' inserted", key);

		} catch (final Exception e) {
			LOG.error("Unable to insert OCSP in the DB. Cause: " + e.getLocalizedMessage(), e);
			rollback(c);
		} finally {
			closeQuietly(c, s, rs);
		}
	}

	/**
	 * Updates the currently stored OCSP token for the given <code>key</code>
	 * with supplied <code>token</code>.
	 *
	 * @param key
	 *            identifier
	 * @param token
	 *            new OCSP token
	 */
	private void updateOCSPInDb(final String key, final OCSPToken token) {
		Connection c = null;
		PreparedStatement s = null;
		final ResultSet rs = null;
		try {
			c = getDataSource().getConnection();
			s = c.prepareStatement(SQL_FIND_UPDATE);

			s.setBytes(1, token.getEncoded());

			if (token.getSourceURL() != null) {
				s.setString(2, token.getSourceURL());
			} else {
				s.setNull(2, Types.VARCHAR);
			}

			s.setInt(3, token.getResponseStatus().getStatusCode());

			if (token.getThisUpdate() != null) {
				s.setTimestamp(4, new Timestamp(token.getThisUpdate().getTime()));
			} else {
				s.setNull(4, Types.TIMESTAMP);
			}

			if (token.getNextUpdate() != null) {
				s.setTimestamp(5, new Timestamp(token.getNextUpdate().getTime()));
			} else if (cacheExpirationTime != null) {
				s.setTimestamp(5, new Timestamp(System.currentTimeMillis() + cacheExpirationTime));
			} else {
				s.setNull(5, Types.TIMESTAMP);
			}
			s.setString(6, key);
			s.executeUpdate();
			c.commit();
			LOG.debug("OCSP token with key '{}' updated", key);
		} catch (final Exception e) {
			LOG.error("Unable to update OCSP in the DB. Cause: " + e.getLocalizedMessage(), e);
			rollback(c);
		} finally {
			closeQuietly(c, s, rs);
		}
	}

	/**
	 * Creates the identifier for a certain entry within jdbc.
	 *
	 * @param certId
	 *            the identifier object
	 * @return the identifier for jdbc
	 */
	private String getJdbcKey(final CertificateID certId) {
		final StringBuilder buf = new StringBuilder();
		buf.append(Utils.toHex(certId.getSerialNumber().toByteArray())).append(":");
		buf.append(Utils.toHex(certId.getIssuerKeyHash())).append(":");
		buf.append(Utils.toHex(certId.getIssuerNameHash())).append(":");
		buf.append(certId.getHashAlgOID().getId());
		return buf.toString();
	}

	/**
	 * Returns the current used data source.
	 *
	 * @return the dataSource
	 */
	private DataSource getDataSource() {
		return dataSource;
	}

	/**
	 * Rollbacks the current open JDBC transaction.
	 *
	 * @param c
	 *            jdbc connection
	 */
	private void rollback(final Connection c) {
		if (c != null) {
			try {
				LOG.warn("Transaction is being rolled back");
				c.rollback();
			} catch (final SQLException e) {
				LOG.error("Unable to rollback", e);
			}
		}
	}

	/**
	 * Close the statement and connection and resultSet without throwing the
	 * exception
	 *
	 * @param c
	 *            the connection
	 * @param s
	 *            the statement
	 * @param rs
	 *            the ResultSet
	 */
	private void closeQuietly(final Connection c, final Statement s, final ResultSet rs) {
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
		} catch (final SQLException e) {
			// do nothing ...
		}
	}
}
