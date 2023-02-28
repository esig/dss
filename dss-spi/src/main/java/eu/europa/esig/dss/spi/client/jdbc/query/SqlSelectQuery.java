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
