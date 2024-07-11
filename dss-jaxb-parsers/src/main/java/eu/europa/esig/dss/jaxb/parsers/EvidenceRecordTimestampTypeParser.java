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
package eu.europa.esig.dss.jaxb.parsers;

import eu.europa.esig.dss.enumerations.EvidenceRecordTimestampType;

/**
 * Parses the {@code eu.europa.esig.dss.jaxb.parsers.EvidenceRecordTimestampTypeParser}
 *
 */
public class EvidenceRecordTimestampTypeParser {

    /**
     * Default constructor
     */
    private EvidenceRecordTimestampTypeParser() {
        // empty
    }

    /**
     * Parses the value and returns {@code EvidenceRecordTimestampType}
     *
     * @param v {@link String} to parse
     * @return {@link EvidenceRecordTimestampType}
     */
    public static EvidenceRecordTimestampType parse(String v) {
        return EvidenceRecordTimestampType.valueOf(v);
    }

    /**
     * Gets a text name of the value
     *
     * @param v {@link EvidenceRecordTimestampType}
     * @return {@link String}
     */
    public static String print(EvidenceRecordTimestampType v) {
        return v.name();
    }

}
