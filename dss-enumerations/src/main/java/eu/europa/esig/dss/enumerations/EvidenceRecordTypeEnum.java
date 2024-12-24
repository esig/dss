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
package eu.europa.esig.dss.enumerations;

import java.util.Objects;

/**
 * Defines supported Evidence Record types
 *
 */
public enum EvidenceRecordTypeEnum {

    /** An XML Evidence Record according to RFC 6283 */
    XML_EVIDENCE_RECORD("XML Evidence Record"),

    /** An XML Evidence Record according to RFC 4998 */
    ASN1_EVIDENCE_RECORD("ASN.1 Evidence Record");

    /** User-friendly descriptor of the evidence record type */
    private final String label;

    /**
     * Default constructor
     *
     * @param label {@link String}
     */
    EvidenceRecordTypeEnum(String label) {
        this.label = label;
    }

    /**
     * Gets a user-friendly descriptor of an evidence record type
     *
     * @return {@link String}
     */
    public String getLabel() {
        return label;
    }

    /**
     * Gets an {@code EvidenceRecordEnum} for the given {@code label} string value
     *
     * @param label {@link String} representing a user-friendly identifier for an evidence record
     * @return {@link EvidenceRecordTypeEnum}
     */
    public static EvidenceRecordTypeEnum fromLabel(String label) {
        Objects.requireNonNull(label, "Label cannot be null!");
        for (EvidenceRecordTypeEnum evidenceRecordEnum : EvidenceRecordTypeEnum.values()) {
            if (label.equals(evidenceRecordEnum.label)) {
                return evidenceRecordEnum;
            }
        }
        throw new UnsupportedOperationException(String.format("Evidence record of type '%s' is not supported!", label));
    }

}
