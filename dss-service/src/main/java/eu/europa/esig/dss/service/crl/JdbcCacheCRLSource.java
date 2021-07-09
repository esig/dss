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
package eu.europa.esig.dss.service.crl;

import eu.europa.esig.dss.crl.CRLBinary;
import eu.europa.esig.dss.crl.CRLUtils;
import eu.europa.esig.dss.crl.CRLValidity;
import eu.europa.esig.dss.enumerations.RevocationOrigin;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.model.x509.revocation.crl.CRL;
import eu.europa.esig.dss.spi.DSSRevocationUtils;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.client.jdbc.JdbcCacheConnector;
import eu.europa.esig.dss.spi.exception.DSSExternalResourceException;
import eu.europa.esig.dss.spi.x509.revocation.JdbcRevocationSource;
import eu.europa.esig.dss.spi.x509.revocation.RevocationToken;
import eu.europa.esig.dss.spi.x509.revocation.crl.CRLSource;
import eu.europa.esig.dss.spi.x509.revocation.crl.CRLToken;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/**
 * CRLSource that retrieve information from a JDBC datasource
 */
public class JdbcCacheCRLSource extends JdbcRevocationSource<CRL> implements CRLSource {

	private static final long serialVersionUID = 3007740140330998336L;

	/**
	 * Used in the init method to check if the table exists
	 */
	private static final String SQL_INIT_CHECK_EXISTENCE = "SELECT COUNT(*) FROM CACHED_CRL";

	/**
	 * Used in the init method to create the table, if not existing: ID (char40
	 * = SHA1 length) and DATA (blob)
	 */
	private static final String SQL_INIT_CREATE_TABLE = "CREATE TABLE CACHED_CRL (ID CHAR(40), DATA BLOB, ISSUER LONGVARBINARY)";

	/**
	 * Used in the find method to select the crl via the id
	 */
	private static final String SQL_FIND_QUERY = "SELECT * FROM CACHED_CRL WHERE ID = ?";

	/**
	 * Used in the find method when selecting the crl via the id to get the ID
	 * (char40) from the resultset
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

	/**
	 * Used via the find method to insert a new record
	 */
	private static final String SQL_FIND_INSERT = "INSERT INTO CACHED_CRL (ID, DATA, ISSUER) VALUES (?, ?, ?)";

	/**
	 * Used via the find method to update an existing record via the id
	 */
	private static final String SQL_FIND_UPDATE = "UPDATE CACHED_CRL SET DATA = ?, ISSUER = ?  WHERE ID = ?";

	/**
	 * Used via the find method to remove an existing record by the id
	 */
	private static final String SQL_FIND_REMOVE = "DELETE FROM CACHED_CRL WHERE ID = ?";
	
	/**
	 * Used to drop the cache table
	 */
	private static final String SQL_DROP_TABLE = "DROP TABLE CACHED_CRL";

	/**
	 * A list of requests to extract the certificates by
	 */
	private static List<JdbcCacheConnector.JdbcResultRequest> findCRLRequests;

	static {
		findCRLRequests = new ArrayList<>();
		findCRLRequests.add(new JdbcCacheConnector.JdbcResultRequest(SQL_FIND_QUERY_ID, String.class));
		findCRLRequests.add(new JdbcCacheConnector.JdbcResultRequest(SQL_FIND_QUERY_DATA, byte[].class));
		findCRLRequests.add(new JdbcCacheConnector.JdbcResultRequest(SQL_FIND_QUERY_ISSUER, byte[].class));
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
	protected Collection<JdbcCacheConnector.JdbcResultRequest> getRevocationDataExtractRequests() {
		return findCRLRequests;
	}
	
	/**
	 * Returns a revocation token key
	 *
	 * @param certificateToken {@link CertificateToken}
	 * @return revocation token key {@link String}
	 */
	@Override
	protected List<String> initRevocationTokenKeys(CertificateToken certificateToken) {
		return DSSRevocationUtils.getCRLRevocationTokenKeys(certificateToken);
	}

	@Override
	protected RevocationToken<CRL> buildRevocationTokenFromResult(JdbcCacheConnector.JdbcResultRecord resultRecord,
				CertificateToken certificateToken, CertificateToken issuerCertificateToken) throws DSSExternalResourceException {
		try {
			CRLBinary crlBinary = CRLUtils.buildCRLBinary((byte[]) resultRecord.get(SQL_FIND_QUERY_DATA));
			CertificateToken cachedIssuerCertificate = DSSUtils.loadCertificate((byte[]) resultRecord.get(SQL_FIND_QUERY_ISSUER));

			final CRLValidity cached = CRLUtils.buildCRLValidity(crlBinary, cachedIssuerCertificate);
			cached.setIssuerToken(cachedIssuerCertificate);
			
			CRLToken crlToken = new CRLToken(certificateToken, cached);
			crlToken.setExternalOrigin(RevocationOrigin.CACHED);
			return crlToken;
			
		} catch (Exception e) {
			throw new DSSExternalResourceException(String.format(
					"An error occurred during an attempt to get a revocation token. Reason : %s", e.getMessage()), e);
		}
	}

	@Override
	protected void insertRevocation(final String revocationKey, final RevocationToken<CRL> token) {
		CRLToken crlToken = (CRLToken) token;
		CRLValidity crlValidity = crlToken.getCrlValidity();

		jdbcCacheConnector.execute(SQL_FIND_INSERT, revocationKey, crlValidity.getDerEncoded(),
				crlValidity.getIssuerToken().getEncoded());
	}

	@Override
	protected void updateRevocation(final String revocationKey, final RevocationToken<CRL> token) {
		CRLToken crlToken = (CRLToken) token;
		CRLValidity crlValidity = crlToken.getCrlValidity();

		jdbcCacheConnector.execute(SQL_FIND_UPDATE, crlValidity.getDerEncoded(), crlValidity.getIssuerToken().getEncoded(),
				revocationKey);
	}

	@Override
	public CRLToken getRevocationToken(CertificateToken certificateToken, CertificateToken issuerCertificateToken) {
		return (CRLToken) super.getRevocationToken(certificateToken, issuerCertificateToken);
	}

	@Override
	public CRLToken getRevocationToken(CertificateToken certificateToken, CertificateToken issuerCertificateToken, boolean forceRefresh) {
		return (CRLToken) super.getRevocationToken(certificateToken, issuerCertificateToken, forceRefresh);
	}
	
	@Override
	protected String getRevocationTokenKey(CertificateToken certificateToken, String urlString) {
		return DSSRevocationUtils.getCRLRevocationTokenKey(urlString);
	}

}
