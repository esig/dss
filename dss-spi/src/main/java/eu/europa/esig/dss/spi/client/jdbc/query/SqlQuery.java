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
