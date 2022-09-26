package eu.europa.esig.dss.spi.client.jdbc.query;

import eu.europa.esig.dss.spi.client.jdbc.record.SqlRecord;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Collection;

/**
 * A select query containing logic to extract records from a {@code ResultSet}
 *
 */
public abstract class SqlSelectQuery extends SqlQuery {

    /**
     * Default constructor
     *
     * @param queryString {@link String}
     */
    protected SqlSelectQuery(String queryString) {
        super(queryString);
    }

    /**
     * Returns response from the given {@code ResultSet} row position
     *
     * @param rs {@link ResultSet} to get records from the provided position
     * @return {@link SqlRecord}
     * @throws SQLException if an error during the SQL request occurs
     */
    protected abstract SqlRecord getRecord(ResultSet rs) throws SQLException;

    /**
     * Extracts a collection of {@code SqlRecord}s from {@code ResultSet}
     *
     * @param rs {@link ResultSet} result of the select query
     * @return collection of {@link SqlRecord}s
     * @throws SQLException if an error during the SQL request occurs
     */
    public Collection<SqlRecord> getRecords(ResultSet rs) throws SQLException {
        final Collection<SqlRecord> records = new ArrayList<>();
        while (rs.next()) {
            records.add(getRecord(rs));
        }
        return records;
    }

}
