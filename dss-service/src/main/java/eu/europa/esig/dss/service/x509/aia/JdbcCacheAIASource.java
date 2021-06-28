package eu.europa.esig.dss.service.x509.aia;

import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.client.jdbc.JdbcCacheConnector;
import eu.europa.esig.dss.spi.exception.DSSExternalResourceException;
import eu.europa.esig.dss.spi.x509.aia.RepositoryAIASource;
import eu.europa.esig.dss.utils.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * The class represents a JDBC cached AIA Source
 *
 */
public class JdbcCacheAIASource extends RepositoryAIASource {

    private static final Logger LOG = LoggerFactory.getLogger(JdbcCacheAIASource.class);

    /**
     * Used in the init method to check if the table exists
     */
    private static final String SQL_INIT_CHECK_EXISTENCE = "SELECT COUNT(*) FROM AIA_CERTIFICATES";

    /**
     * Used in the init method to create the table, if not existing:
     * ID (char40 = unique cert+aia Id), AIA url key (char40 = SHA1 length) and DATA (blob)
     */
    private static final String SQL_INIT_CREATE_TABLE = "CREATE TABLE AIA_CERTIFICATES (ID CHAR(40), AIA CHAR(40), DATA BLOB)";

    /**
     * Used in the find method to select a certificate via the ID
     */
    private static final String SQL_FIND_QUERY = "SELECT * FROM AIA_CERTIFICATES WHERE AIA = ?";

    /**
     * Used in the find method when selecting a certificate via the ID to get
     * the ID (char40) from the resultset
     */
    private static final String SQL_FIND_QUERY_ID = "ID";

    /**
     * Used in the find method when selecting a certificate via the AIA key to get
     * the ID (char40) from the resultset
     */
    private static final String SQL_FIND_QUERY_AIA = "AIA";

    /**
     * Used in the find method when selecting the certificate via the ID to get
     * the DATA (blob) from the resultset
     */
    private static final String SQL_FIND_QUERY_DATA = "DATA";

    /**
     * Used via the find method to insert a new record
     */
    private static final String SQL_FIND_INSERT = "INSERT INTO AIA_CERTIFICATES (ID, AIA, DATA) VALUES (?, ?, ?)";

    /**
     * Used via the find method to remove an existing record by the id
     */
    private static final String SQL_FIND_REMOVE = "DELETE FROM AIA_CERTIFICATES WHERE AIA = ?";

    /**
     * Used to drop the cache table
     */
    private static final String SQL_DROP_TABLE = "DROP TABLE AIA_CERTIFICATES";

    /**
     * Extracts all unique AIA keys from the table
     */
    private static final String SQL_DISTINCT_AIA_KEYS_QUERY = "SELECT DISTINCT AIA FROM AIA_CERTIFICATES";

    /**
     * A list of requests to extract the certificates by
     */
    private static List<JdbcCacheConnector.JdbcResultRequest> findCertificatesRequests;

    /**
     * A list of requests to extract AIA keys
     */
    private static List<JdbcCacheConnector.JdbcResultRequest> findAIAKeysRequests;

    static {
        findCertificatesRequests = new ArrayList<>();
        findCertificatesRequests.add(new JdbcCacheConnector.JdbcResultRequest(SQL_FIND_QUERY_AIA, String.class));
        findCertificatesRequests.add(new JdbcCacheConnector.JdbcResultRequest(SQL_FIND_QUERY_DATA, byte[].class));

        findAIAKeysRequests = new ArrayList<>();
        findAIAKeysRequests.add(new JdbcCacheConnector.JdbcResultRequest(SQL_FIND_QUERY_AIA, String.class));
    }

    /**
     * Connection to database
     */
    protected transient JdbcCacheConnector jdbcCacheConnector;

    /**
     * Sets the SQL connection DataSource
     *
     * @param jdbcCacheConnector {@link JdbcCacheConnector}
     */
    public void setJdbcCacheConnector(JdbcCacheConnector jdbcCacheConnector) {
        this.jdbcCacheConnector = jdbcCacheConnector;
    }

    @Override
    protected Set<CertificateToken> findCertificates(final String key) {
        Collection<JdbcCacheConnector.JdbcResultRecord> records = jdbcCacheConnector.select(
                SQL_FIND_QUERY, findCertificatesRequests, key);
        return buildCertificatesFromResult(records);
    }

    private Set<CertificateToken> buildCertificatesFromResult(Collection<JdbcCacheConnector.JdbcResultRecord> records) {
        try {
            Set<CertificateToken> certificateTokens = new LinkedHashSet<>();
            for (JdbcCacheConnector.JdbcResultRecord resultRecord : records) {
                byte[] binaries = (byte[]) resultRecord.get(SQL_FIND_QUERY_DATA);
                if (Utils.isArrayNotEmpty(binaries)) {
                    CertificateToken certificateToken = DSSUtils.loadCertificate(binaries);
                    if (certificateToken != null) {
                        certificateTokens.add(certificateToken);
                    }
                }
            }
            return certificateTokens;

        } catch (Exception e) {
            throw new DSSExternalResourceException(String.format("An error occurred during an attempt to get " +
                    "a certificate token from cache. Reason : %s", e.getMessage()), e);
        }
    }

    @Override
    protected void insertCertificates(final String aiaUrl, final Collection<CertificateToken> certificateTokens) {
        if (Utils.isCollectionNotEmpty(certificateTokens)) {
            for (CertificateToken certificate : certificateTokens) {
                jdbcCacheConnector.execute(SQL_FIND_INSERT, getUniqueCertificateAiaId(certificate, aiaUrl),
                        getAiaUrlIdentifier(aiaUrl), certificate.getEncoded());
                LOG.debug("AIA Certificate with Id '{}' successfully inserted in DB", certificate.getDSSIdAsString());
            }
        }
    }

    private String getUniqueCertificateAiaId(final CertificateToken certificateToken, String aiaUrl) {
        return DSSUtils.getSHA1Digest(certificateToken.getDSSIdAsString() + aiaUrl);
    }

    private String getAiaUrlIdentifier(final String aiaUrl) {
        return DSSUtils.getSHA1Digest(aiaUrl);
    }

    @Override
    protected void removeCertificates(String aiaKey) {
        jdbcCacheConnector.execute(SQL_FIND_REMOVE, aiaKey);
        LOG.debug("Certificate tokens with AIA key '{}' successfully removed from DB", aiaKey);
    }

    @Override
    protected List<String> getExistingAIAKeys() {
        Collection<JdbcCacheConnector.JdbcResultRecord> result = jdbcCacheConnector.select(SQL_DISTINCT_AIA_KEYS_QUERY, findAIAKeysRequests);
        return result.stream().map(r -> (String) r.get(SQL_FIND_QUERY_AIA)).collect(Collectors.toList());
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
        return jdbcCacheConnector.tableQuery(SQL_INIT_CHECK_EXISTENCE);
    }

    private void createTable() throws SQLException {
        jdbcCacheConnector.executeThrowable(SQL_INIT_CREATE_TABLE);
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
        jdbcCacheConnector.executeThrowable(SQL_DROP_TABLE);
    }

}
