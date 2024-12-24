/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.spi.x509.revocation;

import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.model.x509.revocation.Revocation;
import eu.europa.esig.dss.spi.client.jdbc.JdbcCacheConnector;
import eu.europa.esig.dss.spi.client.jdbc.query.SqlQuery;
import eu.europa.esig.dss.spi.client.jdbc.query.SqlSelectQuery;
import eu.europa.esig.dss.spi.client.jdbc.record.SqlRecord;
import eu.europa.esig.dss.spi.exception.DSSExternalResourceException;
import eu.europa.esig.dss.utils.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

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
	private transient JdbcCacheConnector jdbcCacheConnector;

	/**
	 * Default constructor instantiating object with null values
	 */
	protected JdbcRevocationSource() {
	}
	
	/**
	 * Returns CREATE_TABLE sql query
	 *
	 * @return {@link SqlQuery}
	 */
	protected abstract SqlQuery getCreateTableQuery();
	
	/**
	 * Returns an sql query to check table existence
	 *
	 * @return {@link SqlQuery}
	 */
	protected abstract SqlQuery getTableExistenceQuery();

	/**
	 * Returns an sql query to remove a table from DB
	 *
	 * @return {@link SqlQuery}
	 */
	protected abstract SqlQuery getDeleteTableQuery();

	/**
	 * Returns an SQL query to insert a new revocation token to a table
	 *
	 * @return {@link SqlQuery}
	 */
	protected abstract SqlQuery getInsertRevocationTokenEntryQuery();

	/**
	 * Returns an SQL query to update a revocation token in a table
	 *
	 * @return {@link SqlQuery}
	 */
	protected abstract SqlQuery getUpdateRevocationTokenEntryQuery();
	
	/**
	 * Returns an sql query to remove a revocation token from DB
	 *
	 * @return {@link SqlQuery}
	 */
	protected abstract SqlQuery getRemoveRevocationTokenEntryQuery();
	
	/**
	 * Builds {@link RevocationToken} from the obtained {@link ResultSet}
	 *
	 * @param response {@link SqlRecord} represent the extracted record row
	 * @param certificateToken {@link CertificateToken} of certificate to get revocation data for
	 * @param issuerCertificateToken {@link CertificateToken} if issuer of the certificateToken
	 * @return {@link RevocationToken}
	 * @throws DSSExternalResourceException if an exception occurs during the attempt to extract token
	 */
	protected abstract RevocationToken<R> buildRevocationTokenFromResult(SqlRecord response,
			CertificateToken certificateToken, CertificateToken issuerCertificateToken) throws DSSExternalResourceException;

	/**
	 * Gets the SQL connection DataSource
	 *
	 * @return {@link JdbcCacheConnector}
	 */
	protected JdbcCacheConnector getJdbcCacheConnector() {
		Objects.requireNonNull(jdbcCacheConnector, "JdbcCacheConnector shall be provided! " +
				"Use setJdbcCacheConnector(jdbcCacheConnector) method.");
		return jdbcCacheConnector;
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
	protected List<RevocationToken<R>> findRevocations(final String key, final CertificateToken certificateToken,
													   final CertificateToken issuerCertificateToken) {
		Collection<SqlRecord> responses = getJdbcCacheConnector().select(getRevocationDataExtractQuery(), key);
		LOG.debug("Record obtained : {}", responses.size());
		if (Utils.isCollectionNotEmpty(responses)) {
			return getRevocationDataFromRecords(responses, certificateToken, issuerCertificateToken);
		}
		return Collections.emptyList();
	}

	private List<RevocationToken<R>> getRevocationDataFromRecords(
			Collection<SqlRecord> records, CertificateToken certificateToken, CertificateToken issuerCertificateToken) {
		List<RevocationToken<R>> revocationTokens = new ArrayList<>();
		for (SqlRecord sqlRecord : records) {
			RevocationToken<R> revocationToken = buildRevocationTokenFromResult(sqlRecord, certificateToken, issuerCertificateToken);
			if (revocationToken != null) {
				revocationTokens.add(revocationToken);
			}
		}
		return revocationTokens;
	}

	/**
	 * Returns a request to find a revocation data
	 *
	 * @return {@link SqlSelectQuery}
	 */
	protected abstract SqlSelectQuery getRevocationDataExtractQuery();

	@Override
	protected void removeRevocation(final String revocationTokenKey) {
		getJdbcCacheConnector().execute(getRemoveRevocationTokenEntryQuery(), revocationTokenKey);
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
		getJdbcCacheConnector().executeThrowable(getCreateTableQuery());
	}

	/**
	 * Verifies if the table exists
	 *
	 * @return TRUE if the table exists, FALSE otherwise
	 */
	public boolean isTableExists() {
		return getJdbcCacheConnector().tableQuery(getTableExistenceQuery());
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
		getJdbcCacheConnector().executeThrowable(getDeleteTableQuery());
	}

}
