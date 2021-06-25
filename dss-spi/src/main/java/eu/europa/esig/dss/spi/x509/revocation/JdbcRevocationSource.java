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
package eu.europa.esig.dss.spi.x509.revocation;

import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.model.x509.revocation.Revocation;
import eu.europa.esig.dss.spi.client.jdbc.JdbcCacheConnector;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.sql.DataSource;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Collection;

/**
 * Abstract class to retrieve token from a JDBC datasource
 * 
 * @param <R> {@code CRL} or {@code OCSP}
 */
public abstract class JdbcRevocationSource<R extends Revocation> extends RepositoryRevocationSource<R> {

	private static final Logger LOG = LoggerFactory.getLogger(JdbcRevocationSource.class); 

	private static final long serialVersionUID = 8752226611048306095L;

	/**
	 * Connects to SQL database and performs queries
	 */
	protected transient JdbcCacheConnector jdbcCacheConnector;
	
	/**
	 * Returns CREATE_TABLE sql query
	 * @return {@link String} sql query
	 */
	protected abstract String getCreateTableQuery();
	
	/**
	 * Returns an sql query to check table existence
	 * @return {@link String} sql query
	 */
	protected abstract String getTableExistenceQuery();

	/**
	 * Returns an sql query to get revocation data from DB
	 * @return {@link String} sql query
	 */
	protected abstract String getFindRevocationQuery();

	/**
	 * Returns an sql query to remove a table from DB
	 * @return {@link String} sql query
	 */
	protected abstract String getDeleteTableQuery();
	
	/**
	 * Returns an sql query to remove a record from DB
	 * @return {@link String} sql query
	 */
	protected abstract String getRemoveRevocationTokenEntryQuery();
	
	/**
	 * Build {@link RevocationToken} from the obtained {@link ResultSet}
	 * @param resultRecord represent the extract record row
	 * @param certificateToken {@link CertificateToken} of certificate to get revocation data for
	 * @param issuerCertificateToken {@link CertificateToken} if issuer of the certificateToken
	 * @return {@link RevocationToken}
	 */
	protected abstract RevocationToken<R> buildRevocationTokenFromResult(JdbcCacheConnector.JdbcResultRecord resultRecord,
			CertificateToken certificateToken,CertificateToken issuerCertificateToken) throws RevocationException;

	/**
	 * Sets {@code DataSource}
	 *
	 * @param dataSource
	 *            the dataSource to set
	 *
	 * @deprecated since 5.9. Use {@code setJdbcCacheConnector(jdbcCacheConnector)}
	 */
	@Deprecated
	public void setDataSource(final DataSource dataSource) {
		this.jdbcCacheConnector = new JdbcCacheConnector(dataSource);
		LOG.info("Use of deprecated method setDataSource(dataSource). Use setJdbcCacheConnector(jdbcCacheConnector) instead.");
	}

	/**
	 * Sets the SQL connection DataSource
	 *
	 * @param jdbcCacheConnector {@link JdbcCacheConnector}
	 */
	public void setJdbcCacheConnector(JdbcCacheConnector jdbcCacheConnector) {
		this.jdbcCacheConnector = jdbcCacheConnector;
	}
	
	@Override
	protected RevocationToken<R> findRevocation(final String key, final CertificateToken certificateToken,
												final CertificateToken issuerCertificateToken) {
		Collection<JdbcCacheConnector.JdbcResultRecord> records = jdbcCacheConnector.select(
				getFindRevocationQuery(), getRevocationDataExtractRequests(), key);
		LOG.debug("Record obtained : {}", records.size());
		if (records.size() == 1) {
			return buildRevocationTokenFromResult(records.iterator().next(), certificateToken, issuerCertificateToken);
		}
		return null;
	}

	/**
	 * Returns a request to find a revocation data
	 *
	 * @return a collection of {@link JdbcCacheConnector.JdbcResultRequest}
	 */
	protected abstract Collection<JdbcCacheConnector.JdbcResultRequest> getRevocationDataExtractRequests();

	@Override
	protected void removeRevocation(final String revocationTokenKey) {
		jdbcCacheConnector.execute(getRemoveRevocationTokenEntryQuery(), revocationTokenKey);
	}

	/**
	 * Initialize the revocation token table by creating the table if it does not exist.
	 *
	 * @throws SQLException in case of SQL connection error
	 */
	public void initTable() throws SQLException {
		/* Create the table if it doesn't exist. */
		if (!isTableExists()) {
			LOG.debug("Table does not exist. Creating a new table...");
			createTable();
			LOG.info("Table was created.");
		} else {
			LOG.debug("Table already exists.");
		}
	}
	
	private void createTable() throws SQLException {
		jdbcCacheConnector.executeThrowable(getCreateTableQuery());
	}

	/**
	 * Verifies if the table exists
	 *
	 * @return TRUE if the table exists, FALSE otherwise
	 */
	public boolean isTableExists() {
		return jdbcCacheConnector.tableQuery(getTableExistenceQuery());
	}

	/**
	 * Removes table from DB
	 *
	 * @throws SQLException in case of error
	 */
	public void destroyTable() throws SQLException {
		/* Drop the table if it exists. */
		if (isTableExists()) {
			LOG.debug("Table exists. Removing the table...");
			dropTable();
			LOG.info("Table was destroyed.");
		} else {
			LOG.warn("Cannot drop the table. Table does not exist.");
		}
	}
	
	private void dropTable() throws SQLException {
		jdbcCacheConnector.executeThrowable(getDeleteTableQuery());
	}

}
