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
package eu.europa.esig.dss.client.crl;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.sql.Types;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.DSSRevocationUtils;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.SignatureAlgorithm;
import eu.europa.esig.dss.crl.CRLValidity;
import eu.europa.esig.dss.x509.CertificateToken;
import eu.europa.esig.dss.x509.RevocationOrigin;
import eu.europa.esig.dss.x509.revocation.JdbcRevocationSource;
import eu.europa.esig.dss.x509.revocation.crl.CRLSource;
import eu.europa.esig.dss.x509.revocation.crl.CRLToken;
import eu.europa.esig.dss.x509.revocation.exception.RevocationException;

/**
 * CRLSource that retrieve information from a JDBC datasource
 */
public class JdbcCacheCRLSource extends JdbcRevocationSource<CRLToken> implements CRLSource {

	private static final long serialVersionUID = 3007740140330998336L;
	
	private static final Logger LOG = LoggerFactory.getLogger(JdbcCacheCRLSource.class);
	/**
	 * Used in the init method to check if the table exists
	 */
	private static final String SQL_INIT_CHECK_EXISTENCE = "SELECT COUNT(*) FROM CACHED_CRL";

	/**
	 * Used in the init method to create the table, if not existing: ID (char40
	 * = SHA1 length) and DATA (blob)
	 */
	private static final String SQL_INIT_CREATE_TABLE = "CREATE TABLE CACHED_CRL (ID CHAR(40), DATA BLOB, SIGNATURE_ALGORITHM VARCHAR(20), THIS_UPDATE TIMESTAMP, NEXT_UPDATE TIMESTAMP, EXPIRED_CERTS_ON_CRL TIMESTAMP, ISSUER LONGVARBINARY, ISSUER_PRINCIPAL_MATCH BOOLEAN, SIGNATURE_INTACT BOOLEAN, CRL_SIGN_KEY_USAGE BOOLEAN, UNKNOWN_CRITICAL_EXTENSION BOOLEAN, SIGNATURE_INVALID_REASON VARCHAR(256))";

	/**
	 * Used in the find method to select the crl via the id
	 */
	private static final String SQL_FIND_QUERY = "SELECT * FROM CACHED_CRL WHERE ID = ?";

	/**
	 * Used in the find method when selecting the crl via the id to get the ID
	 * (char20) from the resultset
	 */
	private static final String SQL_FIND_QUERY_ID = "ID";

	/**
	 * Used in the find method when selecting the crl via the id to get the DATA
	 * (blob) from the resultset
	 */
	private static final String SQL_FIND_QUERY_DATA = "DATA";

	/**
	 * Used in the find method when selecting the issuer certificate via the id
	 * to get the ISSUER (blob) from the resultset
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
	 * Used via the find method to insert a new record
	 */
	private static final String SQL_FIND_INSERT = "INSERT INTO CACHED_CRL (ID, DATA, SIGNATURE_ALGORITHM, THIS_UPDATE, NEXT_UPDATE, EXPIRED_CERTS_ON_CRL, ISSUER, ISSUER_PRINCIPAL_MATCH, SIGNATURE_INTACT, CRL_SIGN_KEY_USAGE, UNKNOWN_CRITICAL_EXTENSION, SIGNATURE_INVALID_REASON) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";

	/**
	 * Used via the find method to update an existing record via the id
	 */
	private static final String SQL_FIND_UPDATE = "UPDATE CACHED_CRL SET DATA = ?, SIGNATURE_ALGORITHM = ?, THIS_UPDATE = ?, NEXT_UPDATE = ?, EXPIRED_CERTS_ON_CRL = ?, ISSUER = ?, ISSUER_PRINCIPAL_MATCH = ?, SIGNATURE_INTACT = ?, CRL_SIGN_KEY_USAGE = ?, UNKNOWN_CRITICAL_EXTENSION = ?, SIGNATURE_INVALID_REASON = ?  WHERE ID = ?";

	/**
	 * Used via the find method to remove an existing record by the id
	 */
	private static final String SQL_FIND_REMOVE = "DELETE FROM CACHED_CRL WHERE ID = ?";
	
	/**
	 * Used to drop the OCSP cache table
	 */
	private static final String SQL_DROP_TABLE = "DROP TABLE CACHED_CRL";
	
	/**
	 * The default constructor for JdbcCRLSource.
	 */
	public JdbcCacheCRLSource() {
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
	
	/**
	 * Returns a revocation token key
	 * @param certificateToken {@link CertificateToken}
	 * @return revocation token key {@link String}
	 */
	@Override
	public List<String> initRevocationTokenKey(CertificateToken certificateToken) {
		return DSSRevocationUtils.getCRLRevocationTokenKeys(certificateToken);
	}

	@Override
	protected CRLToken buildRevocationTokenFromResult(ResultSet rs, CertificateToken certificateToken, CertificateToken issuerCert) {
		try {
			final CRLValidity cached = new CRLValidity();
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
			cached.setRevocationOrigin(RevocationOrigin.CACHED);
			return new CRLToken(certificateToken, cached);
		} catch (SQLException e) {
			throw new RevocationException("An error occurred during an attempt to get a revocation token");
		}
	}

	/**
	 * Insert a new CRL into the cache
	 *
	 * @param token
	 *            {@link CRLToken}
	 */
	@Override
	protected void insertRevocation(final CRLToken token) {
		Connection c = null;
		PreparedStatement s = null;
		CRLValidity crlValidity = token.getCrlValidity();
		try {
			c = dataSource.getConnection();
			s = c.prepareStatement(SQL_FIND_INSERT);

			s.setString(1, token.getRevocationTokenKey());

			s.setBytes(2, crlValidity.getCrlEncoded());

			s.setString(3, crlValidity.getSignatureAlgorithm().name());

			if (crlValidity.getThisUpdate() != null) {
				s.setTimestamp(4, new Timestamp(crlValidity.getThisUpdate().getTime()));
			} else {
				s.setNull(4, Types.TIMESTAMP);
			}

			if (crlValidity.getNextUpdate() != null) {
				s.setTimestamp(5, new Timestamp(crlValidity.getNextUpdate().getTime()));
			} else if (nextUpdateDelay != null && crlValidity.getThisUpdate() != null) {
				s.setTimestamp(5, new Timestamp(crlValidity.getThisUpdate().getTime() + nextUpdateDelay));
			} else {
				s.setNull(5, Types.TIMESTAMP);
			}

			if (crlValidity.getExpiredCertsOnCRL() != null) {
				s.setTimestamp(6, new Timestamp(crlValidity.getExpiredCertsOnCRL().getTime()));
			} else {
				s.setNull(6, Types.TIMESTAMP);
			}

			s.setBytes(7, crlValidity.getIssuerToken().getEncoded());
			s.setBoolean(8, crlValidity.isIssuerX509PrincipalMatches());
			s.setBoolean(9, crlValidity.isSignatureIntact());
			s.setBoolean(10, crlValidity.isCrlSignKeyUsage());
			s.setBoolean(11, crlValidity.isUnknownCriticalExtension());
			s.setString(12, crlValidity.getSignatureInvalidityReason());
			s.executeUpdate();
			c.commit();
			LOG.debug("CRL token with key '{}' successfully inserted in DB", token.getRevocationTokenKey());
		} catch (final SQLException e) {
			LOG.error("Unable to insert CRL in the DB", e);
			rollback(c);
		} finally {
			closeQuietly(c, s, null);
		}
	}

	/**
	 * Update the cache with the CRL
	 *
	 * @param token
	 *            {@link CRLToken}
	 */
	@Override
	protected void updateRevocation(CRLToken token) {
		Connection c = null;
		PreparedStatement s = null;
		CRLValidity crlValidity = token.getCrlValidity();
		try {
			c = dataSource.getConnection();
			s = c.prepareStatement(SQL_FIND_UPDATE);
			s.setBytes(1, crlValidity.getCrlEncoded());

			s.setString(2, crlValidity.getSignatureAlgorithm().name());

			if (crlValidity.getThisUpdate() != null) {
				s.setTimestamp(3, new Timestamp(crlValidity.getThisUpdate().getTime()));
			} else {
				s.setNull(3, Types.TIMESTAMP);
			}

			if (crlValidity.getNextUpdate() != null) {
				s.setTimestamp(4, new Timestamp(crlValidity.getNextUpdate().getTime()));
			} else if (nextUpdateDelay != null && crlValidity.getThisUpdate() != null) {
				s.setTimestamp(4, new Timestamp(crlValidity.getThisUpdate().getTime() + nextUpdateDelay));
			} else {
				s.setNull(4, Types.TIMESTAMP);
			}

			if (crlValidity.getExpiredCertsOnCRL() != null) {
				s.setTimestamp(5, new Timestamp(crlValidity.getExpiredCertsOnCRL().getTime()));
			} else {
				s.setNull(5, Types.TIMESTAMP);
			}

			s.setBytes(6, crlValidity.getIssuerToken().getEncoded());
			s.setBoolean(7, crlValidity.isIssuerX509PrincipalMatches());
			s.setBoolean(8, crlValidity.isSignatureIntact());
			s.setBoolean(9, crlValidity.isCrlSignKeyUsage());
			s.setBoolean(10, crlValidity.isUnknownCriticalExtension());
			s.setString(11, crlValidity.getSignatureInvalidityReason());

			s.setString(12, token.getRevocationTokenKey());
			s.executeUpdate();
			c.commit();
			LOG.debug("CRL token with key '{}' successfully updated in DB", token.getRevocationTokenKey());
		} catch (final SQLException e) {
			LOG.error("Unable to update CRL in the DB", e);
			rollback(c);
		} finally {
			closeQuietly(c, s, null);
		}
	}
	
}
