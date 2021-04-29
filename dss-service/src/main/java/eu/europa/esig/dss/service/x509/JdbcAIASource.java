package eu.europa.esig.dss.service.x509;

import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.revocation.RepositoryAIASource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.sql.DataSource;
import java.util.ArrayList;
import java.util.List;

public class JdbcAIASource extends RepositoryAIASource {

    private static final Logger LOG = LoggerFactory.getLogger(JdbcAIASource.class);

    /**
     * Used in the init method to check if the table exists
     */
    private static final String SQL_INIT_CHECK_EXISTENCE = "SELECT COUNT(*) FROM AIA_CERTIFICATES";

    /**
     * Used in the init method to create the table, if not existing:
     * ID (char40 = SHA1 length) and DATA (blob)
     */
    private static final String SQL_INIT_CREATE_TABLE = "CREATE TABLE AIA_CERTIFICATES (ID CHAR(40), DATA BLOB)";

    /**
     * Used in the find method to select a certificate via the ID
     */
    private static final String SQL_FIND_QUERY = "SELECT * FROM AIA_CERTIFICATES WHERE ID = ?";

    /**
     * Used in the find method when selecting a certificate via the ID to get
     * the ID (char40) from the resultset
     */
    private static final String SQL_FIND_QUERY_ID = "ID";

    /**
     * Used in the find method when selecting the certificate via the ID to get
     * the DATA (blob) from the resultset
     */
    private static final String SQL_FIND_QUERY_DATA = "DATA";

    /**
     * Used via the find method to insert a new record
     */
    private static final String SQL_FIND_INSERT = "INSERT INTO AIA_CERTIFICATES (ID, DATA) VALUES (?, ?)";

    /**
     * Used via the find method to update an existing record via the id
     */
    private static final String SQL_FIND_UPDATE = "UPDATE AIA_CERTIFICATES SET DATA = ? WHERE ID = ?";

    /**
     * Used via the find method to remove an existing record by the id
     */
    private static final String SQL_FIND_REMOVE = "DELETE FROM AIA_CERTIFICATES WHERE ID = ?";

    /**
     * Used to drop the cache table
     */
    private static final String SQL_DROP_TABLE = "DROP TABLE AIA_CERTIFICATES";

    /**
     * SQL DataSource to create connection with
     */
    protected transient DataSource dataSource;

}
