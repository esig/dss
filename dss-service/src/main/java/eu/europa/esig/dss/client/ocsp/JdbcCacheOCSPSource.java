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
import java.util.Date;
import java.util.List;

import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSRevocationUtils;
import eu.europa.esig.dss.x509.CertificateToken;
import eu.europa.esig.dss.x509.RevocationOrigin;
import eu.europa.esig.dss.x509.revocation.JdbcRevocationSource;
import eu.europa.esig.dss.x509.revocation.exception.RevocationException;
import eu.europa.esig.dss.x509.revocation.ocsp.OCSPRespStatus;
import eu.europa.esig.dss.x509.revocation.ocsp.OCSPToken;
import eu.europa.esig.dss.x509.revocation.ocsp.OCSPTokenBuilder;
import eu.europa.esig.dss.x509.revocation.ocsp.OCSPTokenUtils;

/**
 * OCSPSource that retrieve information from a JDBC data-source.
 *
 * @version 1.0
 * @author akoepe
 * @author aleksandr.beliakov
 * @author pierrick.vanderbroucke
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
	private static final String SQL_INIT_CREATE_TABLE = "CREATE TABLE CACHED_OCSP (ID VARCHAR(100), DATA BLOB, LOC VARCHAR(200), STATUS INT, THIS_UPDATE TIMESTAMP, NEXT_UPDATE TIMESTAMP, USE_NONCE BOOLEAN, NONCE_MATCH BOOLEAN, ORIGIN VARCHAR(20))";

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

	private static final String SQL_FIND_QUERY_THIS_UPDATE = "THIS_UPDATE";

	private static final String SQL_FIND_QUERY_NEXT_UPDATE = "NEXT_UPDATE";

	private static final String SQL_FIND_QUERY_USE_NONCE = "USE_NONCE";

	private static final String SQL_FIND_QUERY_NONCE_MATCH = "NONCE_MATCH";

	private static final String SQL_FIND_QUERY_ORIGIN = "ORIGIN";

	/**
	 * Used via the find method to insert a new record
	 */
	private static final String SQL_FIND_INSERT = "INSERT INTO CACHED_OCSP (ID, DATA, LOC, STATUS, THIS_UPDATE, NEXT_UPDATE, USE_NONCE, NONCE_MATCH, ORIGIN) "
			+ "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)";

	/**
	 * Used via the find method to update an existing record via the id
	 */
	private static final String SQL_FIND_UPDATE = "UPDATE CACHED_OCSP SET DATA = ?, LOC = ?, STATUS = ?, THIS_UPDATE = ?, NEXT_UPDATE = ?, USE_NONCE = ?, NONCE_MATCH = ?, ORIGIN = ? "
			+ "WHERE ID = ?";
	
	/**
	 * Used via the find method to remove an existing record by the id
	 */
	private static final String SQL_FIND_REMOVE = "DELETE FROM CACHED_OCSP WHERE ID = ?";
	
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
	protected String getRemoveRevocationTokenEntryQuery() {
		return SQL_FIND_REMOVE;
	}

	@Override
	protected String getDeleteTableQuery() {
		return SQL_DROP_TABLE;
	}

	@Override
	public final List<String> initRevocationTokenKey(CertificateToken certificateToken) {
		return DSSRevocationUtils.getOcspRevocationTokenKeys(certificateToken);
	}

	@Override
	protected OCSPToken buildRevocationTokenFromResult(ResultSet rs, CertificateToken certificateToken, CertificateToken issuerCert) throws RevocationException {
		try {
			final byte[] data = rs.getBytes(SQL_FIND_QUERY_DATA);
			final String url = rs.getString(SQL_FIND_QUERY_LOC);
			final int status = rs.getInt(SQL_FIND_QUERY_STATUS);
			final boolean useNonce = rs.getBoolean(SQL_FIND_QUERY_USE_NONCE);
			final boolean nonceMatch = rs.getBoolean(SQL_FIND_QUERY_NONCE_MATCH);
			final Date thisUpdate = rs.getTimestamp(SQL_FIND_QUERY_THIS_UPDATE);
			final Date nextUpdate = rs.getTimestamp(SQL_FIND_QUERY_NEXT_UPDATE);
			final RevocationOrigin origin = RevocationOrigin.valueOf(rs.getString(SQL_FIND_QUERY_ORIGIN));
			
			final OCSPResp ocspResp = new OCSPResp(data);
			final BasicOCSPResp basicOCSPResp = (BasicOCSPResp) ocspResp.getResponseObject();
			OCSPTokenBuilder ocspTokenBuilder = new OCSPTokenBuilder(basicOCSPResp, certificateToken);
			OCSPRespStatus ocspRespStatus = OCSPRespStatus.fromInt(status);
			if (OCSPRespStatus.SUCCESSFUL.equals(ocspRespStatus)) {
				ocspTokenBuilder.setAvailable(true);
			}
			ocspTokenBuilder.setOcspRespStatus(ocspRespStatus);
			ocspTokenBuilder.setCertificateId(DSSRevocationUtils.getOCSPCertificateID(certificateToken, issuerCert));
			ocspTokenBuilder.setUseNonce(useNonce);
			ocspTokenBuilder.setNonceMatch(nonceMatch);
			ocspTokenBuilder.setSourceURL(url);
			ocspTokenBuilder.setThisUpdate(thisUpdate);
			ocspTokenBuilder.setNextUpdate(nextUpdate);
			ocspTokenBuilder.setOrigin(origin);
			OCSPToken ocspToken = ocspTokenBuilder.build();
			OCSPTokenUtils.checkTokenValidity(ocspToken, certificateToken, issuerCert);
			return ocspToken;
		} catch (SQLException | IOException | OCSPException e) {
			throw new RevocationException("An error occurred during an attempt to obtain a revocation token");
		}
	}

	/**
	 * Stores the supplied new OCSP <code>token</code> for the given
	 * <code>key</code>.
	 *
	 * @param token
	 *            OCSP token
	 */
	@Override
	protected void insertRevocation(final OCSPToken token) {
		Connection c = null;
		PreparedStatement s = null;
		try {
			c = dataSource.getConnection();
			s = c.prepareStatement(SQL_FIND_INSERT);

			s.setString(1, token.getRevocationTokenKey());

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
			} else if (cacheExpirationTime != null && token.getThisUpdate() != null) {
				s.setTimestamp(6, new Timestamp(token.getThisUpdate().getTime() + cacheExpirationTime));
			} else {
				s.setNull(6, Types.TIMESTAMP);
			}
			s.setBoolean(7, token.isUseNonce());
			s.setBoolean(8, token.isNonceMatch());
			s.setString(9, token.getOrigin().name());
			s.executeUpdate();
			c.commit();
			LOG.debug("OCSP token with key '{}' successfully inserted in DB", token.getRevocationTokenKey());
		} catch (final Exception e) {
			LOG.error("Unable to insert OCSP in the DB. Cause: " + e.getLocalizedMessage(), e);
			rollback(c);
		} finally {
			closeQuietly(c, s, null);
		}
	}

	/**
	 * Updates the currently stored OCSP token for the given <code>key</code>
	 * with supplied <code>token</code>.
	 *
	 * @param token
	 *            new OCSP token
	 */
	@Override
	protected void updateRevocation(final OCSPToken token) {
		Connection c = null;
		PreparedStatement s = null;
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
			} else if (cacheExpirationTime != null && token.getThisUpdate() != null) {
				s.setTimestamp(5, new Timestamp(token.getThisUpdate().getTime() + cacheExpirationTime));
			} else {
				s.setNull(5, Types.TIMESTAMP);
			}
			s.setString(6, token.getRevocationTokenKey());
			s.setBoolean(7, token.isUseNonce());
			s.setBoolean(8, token.isNonceMatch());
			s.setString(9, token.getOrigin().name());
			s.executeUpdate();
			c.commit();
			LOG.debug("OCSP token with key '{}' successfully updated in DB", token.getRevocationTokenKey());
		} catch (final Exception e) {
			LOG.error("Unable to update OCSP in the DB. Cause: " + e.getLocalizedMessage(), e);
			rollback(c);
		} finally {
			closeQuietly(c, s, null);
		}
	}
	
}
