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
package eu.europa.esig.dss.jaxb.parsers;

import eu.europa.esig.dss.enumerations.EvidenceRecordOrigin;

/**
 * Parses the {@code eu.europa.esig.dss.enumerations.EvidenceRecordOrigin}
 *
 */
public class EvidenceRecordOriginParser {

    /**
     * Empty constructor
     */
    private EvidenceRecordOriginParser() {
        // empty
    }

    /**
     * Parses the label value and returns {@code EvidenceRecordOrigin}
     *
     * @param v {@link String} to parse
     * @return {@link EvidenceRecordOrigin}
     */
    public static EvidenceRecordOrigin parse(String v) {
        if (v != null) {
            return EvidenceRecordOrigin.valueOf(v);
        }
        return null;
    }

    /**
     * Gets a user-friendly label value for the evidence record origin
     *
     * @param v {@link EvidenceRecordOrigin}
     * @return {@link String}
     */
    public static String print(EvidenceRecordOrigin v) {
        if (v != null) {
            return v.name();
        }
        return null;
    }

}
