package eu.europa.esig.dss.spi.client.jdbc.query;

/**
 * Represents a stateless query to be made to an SQL database
 *
 */
public class SqlQuery {

    /** The executable SQL query string */
    private final String queryString;

    /**
     * Default constructor
     *
     * @param queryString {@link String}
     */
    protected SqlQuery(final String queryString) {
        this.queryString = queryString;
    }

    /**
     * This method creates a {@code SqlQuery} with the given query string
     *
     * @param queryString {@link String} of the SQL query
     * @return {@link SqlQuery}
     */
    public static SqlQuery createQuery(final String queryString) {
        return new SqlQuery(queryString);
    }

    /**
     * Returns the query String
     *
     * @return {@link String}
     */
    public String getQueryString() {
        return queryString;
    }

    @Override
    public String toString() {
        return "JdbcQuery[" + "queryString='" + queryString + '\'' + ']';
    }

}
