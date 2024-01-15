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
package eu.europa.esig.dss.service.x509.aia;

import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.client.jdbc.JdbcCacheConnector;
import eu.europa.esig.dss.spi.client.jdbc.query.SqlQuery;
import eu.europa.esig.dss.spi.client.jdbc.query.SqlSelectQuery;
import eu.europa.esig.dss.spi.client.jdbc.record.SqlRecord;
import eu.europa.esig.dss.spi.exception.DSSExternalResourceException;
import eu.europa.esig.dss.spi.x509.aia.RepositoryAIASource;
import eu.europa.esig.dss.utils.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * The class represents a JDBC cached AIA Source
 */
public class JdbcCacheAIASource extends RepositoryAIASource {

    private static final long serialVersionUID = -4332455769204417938L;

    private static final Logger LOG = LoggerFactory.getLogger(JdbcCacheAIASource.class);

    /**
     * Used in the init method to check if the table exists
     */
    private static final SqlQuery SQL_INIT_CHECK_EXISTENCE = SqlQuery.createQuery("SELECT COUNT(*) FROM AIA_CERTIFICATES");

    /**
     * Used in the init method to create the table, if not existing:
     * ID (char40 = unique cert+aia Id), AIA url key (char40 = SHA1 length) and DATA (blob)
     */
    private static final SqlQuery SQL_INIT_CREATE_TABLE = SqlQuery.createQuery("CREATE TABLE AIA_CERTIFICATES (ID CHAR(40), AIA CHAR(40), DATA BLOB)");

    /**
     * Used to drop the cache table
     */
    private static final SqlQuery SQL_DROP_TABLE = SqlQuery.createQuery("DROP TABLE AIA_CERTIFICATES");

    /**
     * Used via the find method to insert a new record
     */
    private static final SqlQuery SQL_FIND_INSERT = SqlQuery.createQuery("INSERT INTO AIA_CERTIFICATES (ID, AIA, DATA) VALUES (?, ?, ?)");

    /**
     * Used via the find method to remove an existing record by the id
     */
    private static final SqlQuery SQL_FIND_REMOVE = SqlQuery.createQuery("DELETE FROM AIA_CERTIFICATES WHERE AIA = ?");

    /**
     * Requests to extract AIA certificates
     */
    private static final SqlSelectQuery SQL_FIND_QUERY = new SqlSelectQuery("SELECT * FROM AIA_CERTIFICATES WHERE AIA = ?") {
        @Override
        public SqlAIAResponse getRecord(ResultSet rs) throws SQLException {
            SqlAIAResponse response = new SqlAIAResponse();
            response.id = rs.getString("ID");
            response.aiaKey = rs.getString("AIA");
            response.certificateBinary = rs.getBytes("DATA");
            return response;
        }
    };

    /**
     * Requests to extract AIA keys
     */
    private static final SqlSelectQuery SQL_DISTINCT_AIA_KEYS_QUERY = new SqlSelectQuery("SELECT DISTINCT AIA FROM AIA_CERTIFICATES") {
        @Override
        public SqlAIAResponse getRecord(ResultSet rs) throws SQLException {
            SqlAIAResponse response = new SqlAIAResponse();
            response.aiaKey = rs.getString("AIA");
            return response;
        }
    };

    /**
     * Connection to database
     */
    protected transient JdbcCacheConnector jdbcCacheConnector;

    /**
     * Default constructor with null JdbcCacheConnector
     */
    public JdbcCacheAIASource() {
        // empty
    }

    /**
     * Sets the SQL connection DataSource
     *
     * @param jdbcCacheConnector {@link JdbcCacheConnector}
     */
    public void setJdbcCacheConnector(JdbcCacheConnector jdbcCacheConnector) {
        this.jdbcCacheConnector = jdbcCacheConnector;
    }

    /**
     * Returns CREATE_TABLE sql query
     *
     * @return {@link SqlQuery}
     */
    protected SqlQuery getCreateTableQuery() {
        return SQL_INIT_CREATE_TABLE;
    }

    /**
     * Returns an sql query to check table existence
     *
     * @return {@link SqlQuery}
     */
    protected SqlQuery getTableExistenceQuery() {
        return SQL_INIT_CHECK_EXISTENCE;
    }

    /**
     * Returns an sql query to remove a table from DB
     *
     * @return {@link SqlQuery}
     */
    protected SqlQuery getDeleteTableQuery() {
        return SQL_DROP_TABLE;
    }

    /**
     * Returns an SQL query to insert a new CRL to a table
     *
     * @return {@link SqlQuery}
     */
    protected SqlQuery getInsertCertificateTokenEntryQuery() {
        return SQL_FIND_INSERT;
    }

    /**
     * Returns an sql query to remove a record from DB
     *
     * @return {@link SqlQuery}
     */
    protected SqlQuery getRemoveCertificateTokenEntryQuery() {
        return SQL_FIND_REMOVE;
    }

    /**
     * Returns an SQL query to extract AIA certificates from a table
     *
     * @return {@link SqlSelectQuery}
     */
    protected SqlSelectQuery getAIACertificatesExtractQuery() {
        return SQL_FIND_QUERY;
    }

    /**
     * Returns an SQL query to extract stored AIA keys in a table
     *
     * @return {@link SqlSelectQuery}
     */
    protected SqlSelectQuery getAIAKeysExtractQuery() {
        return SQL_DISTINCT_AIA_KEYS_QUERY;
    }

    @Override
    protected Set<CertificateToken> findCertificates(final String key) {
        Collection<SqlRecord> records = jdbcCacheConnector.select(getAIACertificatesExtractQuery(), key);
        return buildCertificatesFromResult(records);
    }

    private Set<CertificateToken> buildCertificatesFromResult(Collection<SqlRecord> records) {
        try {
            Set<CertificateToken> certificateTokens = new LinkedHashSet<>();
            for (SqlRecord resultRecord : records) {
                final SqlAIAResponse aiaResponse = (SqlAIAResponse) resultRecord;
                byte[] binaries = aiaResponse.certificateBinary;
                if (Utils.isArrayNotEmpty(binaries)) {
                    CertificateToken certificateToken = DSSUtils.loadCertificate(binaries);
                    if (certificateToken != null) {
                        certificateTokens.add(certificateToken);
                    }
                }
            }
            return certificateTokens;

        } catch (Exception e) {
            throw new DSSExternalResourceException(String.format("An error occurred during an attempt to get " + "a certificate token from cache. Reason : %s", e.getMessage()), e);
        }
    }

    @Override
    protected void insertCertificate(final String aiaKey, final CertificateToken certificateTokens) {
        if (certificateTokens != null && aiaKey != null) {
            jdbcCacheConnector.execute(getInsertCertificateTokenEntryQuery(), getUniqueCertificateAiaId(certificateTokens, aiaKey), aiaKey, certificateTokens.getEncoded());
            LOG.debug("AIA Certificate with Id '{}' successfully inserted in DB", certificateTokens.getDSSIdAsString());
        }
    }

    @Override
    protected void removeCertificates(String aiaKey) {
        jdbcCacheConnector.execute(getRemoveCertificateTokenEntryQuery(), aiaKey);
        LOG.debug("Certificate tokens with AIA key '{}' successfully removed from DB", aiaKey);
    }

    @Override
    protected List<String> getExistingAIAKeys() {
        Collection<SqlRecord> result = jdbcCacheConnector.select(getAIAKeysExtractQuery());
        return result.stream().map(r -> ((SqlAIAResponse) r).aiaKey).collect(Collectors.toList());
    }

    /**
     * Initialize the table.
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

    /**
     * Checks of the table is created
     *
     * @return TRUE if the table is created, FALSE otherwise
     */
    public boolean isTableExists() {
        return jdbcCacheConnector.tableQuery(getTableExistenceQuery());
    }

    private void createTable() throws SQLException {
        jdbcCacheConnector.executeThrowable(getCreateTableQuery());
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

    /**
     * Represents an AIA record extracted from the SQL database table
     */
    protected static class SqlAIAResponse implements SqlRecord {

        /**
         * ID of the record
         */
        protected String id;

        /**
         * AIA internal key
         */
        protected String aiaKey;

        /**
         * Certificate binaries
         */
        protected byte[] certificateBinary;

        /**
         * Default constructor
         */
        protected SqlAIAResponse() {
            // empty
        }

    }

}
