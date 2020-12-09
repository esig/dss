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
package eu.europa.esig.dss.service.ocsp;

import eu.europa.esig.dss.enumerations.RevocationOrigin;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.model.x509.revocation.ocsp.OCSP;
import eu.europa.esig.dss.spi.DSSRevocationUtils;
import eu.europa.esig.dss.spi.x509.revocation.JdbcRevocationSource;
import eu.europa.esig.dss.spi.x509.revocation.RevocationException;
import eu.europa.esig.dss.spi.x509.revocation.RevocationToken;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPSource;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPToken;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Types;
import java.util.List;

/**
 * OCSPSource that retrieve information from a JDBC data-source.
 *
 */
public class JdbcCacheOCSPSource extends JdbcRevocationSource<OCSP> implements OCSPSource {
	
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
	private static final String SQL_INIT_CREATE_TABLE = "CREATE TABLE CACHED_OCSP (ID VARCHAR(100), DATA BLOB, LOC VARCHAR(200))";

	/**
	 * Used in the find method to select the OCSP via the id
	 */
	private static final String SQL_FIND_QUERY = "SELECT * FROM CACHED_OCSP WHERE ID = ?";

	/**
	 * Used in the find method when selecting the OCSP via the id to get the
	 * DATA (blob) from the resultSet
	 */
	private static final String SQL_FIND_QUERY_DATA = "DATA";

	/**
	 * Used to store a URL
	 */
	private static final String SQL_FIND_QUERY_LOC = "LOC";

	/**
	 * Used via the find method to insert a new record
	 */
	private static final String SQL_FIND_INSERT = "INSERT INTO CACHED_OCSP (ID, DATA, LOC) "
			+ "VALUES (?, ?, ?)";

	/**
	 * Used via the find method to update an existing record via the id
	 */
	private static final String SQL_FIND_UPDATE = "UPDATE CACHED_OCSP SET DATA = ?, LOC = ? "
			+ "WHERE ID = ?";
	
	/**
	 * Used via the find method to remove an existing record by the id
	 */
	private static final String SQL_FIND_REMOVE = "DELETE FROM CACHED_OCSP WHERE ID = ?";
	
	/**
	 * Used to drop the OCSP cache table
	 */
	private static final String SQL_DROP_TABLE = "DROP TABLE CACHED_OCSP";

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
	protected OCSPToken buildRevocationTokenFromResult(ResultSet rs, CertificateToken certificateToken, CertificateToken issuerCert) {
		try {
			final byte[] data = rs.getBytes(SQL_FIND_QUERY_DATA);
			final String url = rs.getString(SQL_FIND_QUERY_LOC);
			
			final OCSPResp ocspResp = new OCSPResp(data);
			BasicOCSPResp basicResponse = (BasicOCSPResp) ocspResp.getResponseObject();
			SingleResp latestSingleResponse = DSSRevocationUtils.getLatestSingleResponse(basicResponse, certificateToken, issuerCert);
			OCSPToken ocspToken = new OCSPToken(basicResponse, latestSingleResponse, certificateToken, issuerCert);
			ocspToken.setSourceURL(url);
			ocspToken.setExternalOrigin(RevocationOrigin.CACHED);
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
	protected void insertRevocation(RevocationToken<OCSP> token) {
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
			
			s.executeUpdate();
			c.commit();
			LOG.debug("OCSP token with key '{}' successfully inserted in DB", token.getRevocationTokenKey());
		} catch (final Exception e) {
			LOG.error("Unable to insert OCSP {} into the DB. Cause: '{}'", token, e.getMessage(), e);
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
	protected void updateRevocation(final RevocationToken<OCSP> token) {
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
			
			s.executeUpdate();
			c.commit();
			LOG.debug("OCSP token with key '{}' successfully updated in DB", token.getRevocationTokenKey());
		} catch (final Exception e) {
			LOG.error("Unable to update OCSP {} into the DB. Cause: '{}'", token, e.getMessage(), e);
			rollback(c);
		} finally {
			closeQuietly(c, s, null);
		}
	}

	@Override
	public OCSPToken getRevocationToken(CertificateToken certificateToken, CertificateToken issuerCertificateToken) {
		return (OCSPToken) super.getRevocationToken(certificateToken, issuerCertificateToken);
	}

	@Override
	public OCSPToken getRevocationToken(CertificateToken certificateToken, CertificateToken issuerCertificateToken, boolean forceRefresh) {
		return (OCSPToken) super.getRevocationToken(certificateToken, issuerCertificateToken, forceRefresh);
	}
	
}
