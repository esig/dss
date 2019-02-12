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

import java.io.IOException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.sql.Types;

import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSRevocationUtils;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.x509.CertificateToken;
import eu.europa.esig.dss.x509.revocation.JdbcRevocationSource;
import eu.europa.esig.dss.x509.revocation.exception.RevocationException;
import eu.europa.esig.dss.x509.revocation.ocsp.OCSPRespStatus;
import eu.europa.esig.dss.x509.revocation.ocsp.OCSPToken;

/**
 * OCSPSource that retrieve information from a JDBC data-source.
 *
 * @version 1.0
 * @author akoepe
 */
public class JdbcCacheOCSPSource extends JdbcRevocationSource<OCSPToken> {
	
	private static final long serialVersionUID = 10480458323923489L;

	private static final Logger LOG = LoggerFactory.getLogger(JdbcCacheOCSPSource.class);

	/**
	 * Used in the init method to check if the table exists
	 */
	private static final String SQL_INIT_CHECK_EXISTENCE = "SELECT COUNT(*) FROM CACHED_OCSP";

	/**
	 * Used in the init method to create the table, if not existing: ID (char40
	 * = SHA1 length) and DATA (blob)
	 */
	private static final String SQL_INIT_CREATE_TABLE = "CREATE TABLE CACHED_OCSP (ID VARCHAR(100), DATA BLOB, LOC VARCHAR(200), STATUS INT, THIS_UPDATE TIMESTAMP, NEXT_UPDATE TIMESTAMP)";

	/**
	 * Used in the find method to select the OCSP via the id
	 */
	private static final String SQL_FIND_QUERY = "SELECT * FROM CACHED_OCSP WHERE ID = ?";

	/**
	 * Used in the find method when selecting the OCSP via the id to get the
	 * DATA (blob) from the resultSet
	 */
	private static final String SQL_FIND_QUERY_DATA = "DATA";

	private static final String SQL_FIND_QUERY_LOC = "LOC";

	private static final String SQL_FIND_QUERY_STATUS = "STATUS";

	/**
	 * Used via the find method to insert a new record
	 */
	private static final String SQL_FIND_INSERT = "INSERT INTO CACHED_OCSP (ID, DATA, LOC, STATUS, THIS_UPDATE, NEXT_UPDATE) VALUES (?, ?, ?, ?, ?, ?)";

	/**
	 * Used via the find method to update an existing record via the id
	 */
	private static final String SQL_FIND_UPDATE = "UPDATE CACHED_OCSP SET DATA = ?, LOC = ?, STATUS = ?, THIS_UPDATE = ?, NEXT_UPDATE = ?  WHERE ID = ?";
	
	/**
	 * Used to drop the OCSP cache table
	 */
	private static final String SQL_DROP_TABLE = "DROP TABLE CACHED_OCSP";

	/**
	 * Constructor.
	 */
	public JdbcCacheOCSPSource() {
	}
	
	@Override
	protected String getCreateTableQuery() {
		return SQL_INIT_CREATE_TABLE;
	}
	
	@Override
	protected String getTableExistenceQuery() {
		return SQL_INIT_CHECK_EXISTENCE;
	}
	
	@Override
	protected String getFindRevocationQuery() {
		return SQL_FIND_QUERY;
	}

	@Override
	protected String getDeleteTableQuery() {
		return SQL_DROP_TABLE;
	}

	@Override
	public final String initRevocationTokenKey(CertificateToken certificateToken, final CertificateToken issuerCertificateToken) {
		return DSSUtils.getSHA1Digest(DSSRevocationUtils.getJdbcKey(certificateToken, issuerCertificateToken));
	}

	@Override
	protected OCSPToken buildRevocationTokenFromResult(ResultSet rs, CertificateToken certificateToken, CertificateToken issuerCert) throws RevocationException {
		try {
			final byte[] data = rs.getBytes(SQL_FIND_QUERY_DATA);
			final String url = rs.getString(SQL_FIND_QUERY_LOC);
			final int status = rs.getInt(SQL_FIND_QUERY_STATUS);
	
			final OCSPResp ocspResp = new OCSPResp(data);
			final OCSPToken token = new OCSPToken();
			token.setResponseStatus(OCSPRespStatus.fromInt(status));
			token.setSourceURL(url);
			token.setCertId(DSSRevocationUtils.getOCSPCertificateID(certificateToken, issuerCert));
			token.setAvailable(true);
			final BasicOCSPResp basicOCSPResp = (BasicOCSPResp) ocspResp.getResponseObject();
			token.setBasicOCSPResp(basicOCSPResp);
			return token;
		} catch (SQLException | IOException | OCSPException e) {
			throw new RevocationException("An error occurred during an attempt to obtain a revocation token");
		}
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
	@Override
	protected void insertRevocation(final String key, final OCSPToken token) {
		Connection c = null;
		PreparedStatement s = null;
		final ResultSet rs = null;
		try {
			c = dataSource.getConnection();
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
	@Override
	protected void updateRevocation(final String key, final OCSPToken token) {
		Connection c = null;
		PreparedStatement s = null;
		final ResultSet rs = null;
		try {
			c = dataSource.getConnection();
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
	
}
