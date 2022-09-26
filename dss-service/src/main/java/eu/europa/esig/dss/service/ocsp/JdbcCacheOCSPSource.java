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
import eu.europa.esig.dss.spi.client.jdbc.query.SqlQuery;
import eu.europa.esig.dss.spi.client.jdbc.query.SqlSelectQuery;
import eu.europa.esig.dss.spi.client.jdbc.record.SqlRecord;
import eu.europa.esig.dss.spi.exception.DSSExternalResourceException;
import eu.europa.esig.dss.spi.x509.revocation.JdbcRevocationSource;
import eu.europa.esig.dss.spi.x509.revocation.RevocationToken;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPSource;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPToken;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.SingleResp;

import java.io.IOException;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.List;

/**
 * OCSPSource that retrieve information from a JDBC data-source.
 *
 */
public class JdbcCacheOCSPSource extends JdbcRevocationSource<OCSP> implements OCSPSource {
	
	private static final long serialVersionUID = 10480458323923489L;

	/**
	 * Used in the init method to check if the table exists
	 */
	private static final SqlQuery SQL_INIT_CHECK_EXISTENCE = SqlQuery.createQuery("SELECT COUNT(*) FROM CACHED_OCSP");

	/**
	 * Used in the init method to create the table, if not existing:
	 * ID (char40 = SHA1 length), DATA (blob = OCSP binaries) and LOC (varchar(200) = location url)
 	 */
	private static final SqlQuery SQL_INIT_CREATE_TABLE = SqlQuery.createQuery("CREATE TABLE CACHED_OCSP (ID VARCHAR(100), DATA BLOB, LOC VARCHAR(200))");

	/**
	 * Used via the find method to insert a new record
	 */
	private static final SqlQuery SQL_FIND_INSERT = SqlQuery.createQuery("INSERT INTO CACHED_OCSP (ID, DATA, LOC) VALUES (?, ?, ?)");

	/**
	 * Used via the find method to update an existing record via the id
	 */
	private static final SqlQuery SQL_FIND_UPDATE = SqlQuery.createQuery("UPDATE CACHED_OCSP SET DATA = ?, LOC = ? WHERE ID = ?");
	
	/**
	 * Used via the find method to remove an existing record by the id
	 */
	private static final SqlQuery SQL_FIND_REMOVE = SqlQuery.createQuery("DELETE FROM CACHED_OCSP WHERE ID = ?");
	
	/**
	 * Used to drop the OCSP cache table
	 */
	private static final SqlQuery SQL_DROP_TABLE = SqlQuery.createQuery("DROP TABLE CACHED_OCSP");

	/**
	 * A list of requests to extract the certificates by
	 */
	private static final SqlSelectQuery SQL_FIND_QUERY = new SqlSelectQuery("SELECT * FROM CACHED_OCSP WHERE ID = ?") {
		@Override
		public SqlOCSPResponse getRecord(ResultSet rs) throws SQLException {
			SqlOCSPResponse response = new SqlOCSPResponse();
			response.id = rs.getString("ID");
			response.ocspBinary = rs.getBytes("DATA");
			response.ocspUrl = rs.getString("LOC");
			return response;
		}
	};

	/**
	 * Default constructor
	 */
	public JdbcCacheOCSPSource() {
		// empty
	}

	@Override
	protected SqlQuery getCreateTableQuery() {
		return SQL_INIT_CREATE_TABLE;
	}
	
	@Override
	protected SqlQuery getTableExistenceQuery() {
		return SQL_INIT_CHECK_EXISTENCE;
	}

	@Override
	protected SqlQuery getDeleteTableQuery() {
		return SQL_DROP_TABLE;
	}

	@Override
	protected SqlQuery getInsertRevocationTokenEntryQuery() {
		return SQL_FIND_INSERT;
	}

	@Override
	protected SqlQuery getUpdateRevocationTokenEntryQuery() {
		return SQL_FIND_UPDATE;
	}

	@Override
	protected SqlQuery getRemoveRevocationTokenEntryQuery() {
		return SQL_FIND_REMOVE;
	}

	@Override
	protected SqlSelectQuery getRevocationDataExtractQuery() {
		return SQL_FIND_QUERY;
	}

	@Override
	protected final List<String> initRevocationTokenKeys(CertificateToken certificateToken) {
		return DSSRevocationUtils.getOcspRevocationTokenKeys(certificateToken);
	}

	@Override
	protected RevocationToken<OCSP> buildRevocationTokenFromResult(SqlRecord response, CertificateToken certificateToken,
			CertificateToken issuerCert) throws DSSExternalResourceException {
		try {
			final SqlOCSPResponse ocspResponse = (SqlOCSPResponse) response;
			final OCSPResp ocspResp = new OCSPResp(ocspResponse.ocspBinary);
			BasicOCSPResp basicResponse = (BasicOCSPResp) ocspResp.getResponseObject();
			SingleResp latestSingleResponse = DSSRevocationUtils.getLatestSingleResponse(basicResponse, certificateToken, issuerCert);
			OCSPToken ocspToken = new OCSPToken(basicResponse, latestSingleResponse, certificateToken, issuerCert);
			ocspToken.setSourceURL(ocspResponse.ocspUrl);
			ocspToken.setExternalOrigin(RevocationOrigin.CACHED);
			return ocspToken;
		} catch (IOException | OCSPException e) {
			throw new DSSExternalResourceException(String.format(
					"An error occurred during an attempt to obtain a revocation token. Reason : %s", e.getMessage()), e);
		}
	}

	@Override
	protected void insertRevocation(final String revocationKey, final RevocationToken<OCSP> token) {
		getJdbcCacheConnector().execute(getInsertRevocationTokenEntryQuery(), revocationKey, token.getEncoded(), token.getSourceURL());
	}

	/**
	 * Updates the currently stored OCSP token for the given <code>key</code>
	 * with supplied <code>token</code>.
	 *
	 * @param revocationKey {@link String} the key of the revocation data to be updated
	 * @param token new OCSP token
	 */
	@Override
	protected void updateRevocation(final String revocationKey, final RevocationToken<OCSP> token) {
		getJdbcCacheConnector().execute(getUpdateRevocationTokenEntryQuery(), token.getEncoded(), token.getSourceURL(), revocationKey);
	}

	@Override
	public OCSPToken getRevocationToken(CertificateToken certificateToken, CertificateToken issuerCertificateToken) {
		return (OCSPToken) super.getRevocationToken(certificateToken, issuerCertificateToken);
	}

	@Override
	public OCSPToken getRevocationToken(CertificateToken certificateToken, CertificateToken issuerCertificateToken, boolean forceRefresh) {
		return (OCSPToken) super.getRevocationToken(certificateToken, issuerCertificateToken, forceRefresh);
	}
	
	@Override
	protected String getRevocationTokenKey(CertificateToken certificateToken, String urlString) {
		return DSSRevocationUtils.getOcspRevocationKey(certificateToken, urlString);
	}

	/**
	 * Represents an OCSP record extracted from the SQL database table
	 */
	protected static class SqlOCSPResponse implements SqlRecord {

		/** ID of the record */
		protected String id;

		/** OCSP binary */
		protected byte[] ocspBinary;

		/** OCSP URL */
		protected String ocspUrl;

		/**
		 * Default constructor
		 */
		protected SqlOCSPResponse() {
			// empty
		}

	}

}
