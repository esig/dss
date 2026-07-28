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

import java.util.HashMap;
import java.util.Map;

/**
 * Defines possible supported qualification types for an Attestation (e.g. QEAA, PuBEAA, PID, etc.)
 *
 */
public enum AttestationQualification {

    /**
     * Qualified electronic attestation of attributes as defined in Regulation EU 2024/1183, Article 45d.
     */
    QEAA("QEAA", "Qualified Electronic Attestation of Attributes", "urn:cef:dss:attestation:qualification:QEAA"),

    /**
     * Electronic attestation of attributes as defined in Regulation EU 2024/1183, without a qualified revocation.
     */
    EAA("EAA", "Electronic Attestation of Attributes", "urn:cef:dss:attestation:qualification:EAA"),

    /**
     * Electronic attestation of attributes issued by or on behalf of a public sector body responsible
     * for an authentic source as defined in Regulation EU 2024/1183, Article 45f.
     */
    PUBEAA("PuB-EAA", "Electronic Attestation of Attributes issued by or on behalf of a public sector body", "urn:cef:dss:attestation:qualification:PUBEAA"),

    /**
     * Personal Identification Data (PID)
     */
    PID("PID", "Personal Identification Data", "urn:cef:dss:attestation:qualification:PID"),

    /**
     * Electronic attestation of attributes of unknown or conflicting revocation.
     */
    UNKNOWN("Unknown", "Electronic Attestation of Attributes of unknown type", "urn:cef:dss:attestation:qualification:Unknown"),

    /**
     * Indeterminate qualified electronic attestation of attributes as defined in Regulation EU 2024/1183, Article 45d.
     */
    INDETERMINATE_QEAA("Indeterminate QEAA", "Indeterminate Qualified Electronic Attestation of Attributes", "urn:cef:dss:attestation:qualification:indeterminateQEAA"),

    /**
     * Indeterminate electronic attestation of attributes as defined in Regulation EU 2024/1183, without a qualified revocation.
     */
    INDETERMINATE_EAA("Indeterminate EAA", "Indeterminate Electronic Attestation of Attributes", "urn:cef:dss:attestation:qualification:indeterminateEAA"),

    /**
     * Indeterminate electronic attestation of attributes issued by or on behalf of a public sector body responsible
     * for an authentic source as defined in Regulation EU 2024/1183, Article 45f.
     */
    INDETERMINATE_PUBEAA("Indeterminate Pub-EAA", "Indeterminate Electronic Attestation of Attributes issued by or on behalf of a public sector body", "urn:cef:dss:attestation:qualification:indeterminatePUBEAA"),

    /**
     * Indeterminate Personal Identification Data (PID)
     */
    INDETERMINATE_PID("Indeterminate PID", "Indeterminate Personal Identification Data", "urn:cef:dss:attestation:qualification:indeterminatePID"),

    /**
     * Indeterminate electronic attestation of attributes of unknown or conflicting revocation.
     */
    INDETERMINATE_UNKNOWN("Indeterminate Unknown", "Indeterminate Electronic Attestation of Attributes of unknown type", "urn:cef:dss:attestation:qualification:indeterminateUnknown"),

    /**
     * Not electronic attestation of attributes
     */
    NOT_EAA("Not EAA", "Not Electronic Attestation of Attributes", "urn:cef:dss:attestation:qualification:NOTEAA"),

    /**
     * Not Applicable
     */
    NA("N/A", "Not applicable", "urn:cef:dss:attestation:qualification:NA");

    /**
     * This class is used to provide a quick mapping of the user-friendly labels to enums
     */
    private static class Registry {

        private static final Map<String, AttestationQualification> QUALIFS_BY_READABLE = registerByReadable();

        private static Map<String, AttestationQualification> registerByReadable() {
            final Map<String, AttestationQualification> map = new HashMap<>();
            for (final AttestationQualification qualification : values()) {
                map.put(qualification.readable, qualification);
            }
            return map;
        }
    }

    /** User-friendly name (abbreviation) of the qualification */
    private final String readable;

    /** Description of the enumeration */
    private final String label;

    /** Unique URL */
    private final String uri;

    /**
     * Default constructor
     *
     * @param readable {@link String}
     * @param label {@link String}
     * @param uri {@link String}
     */
    AttestationQualification(String readable, String label, String uri) {
        this.readable = readable;
        this.label = label;
        this.uri = uri;
    }

    /**
     * Gets user-friendly name of the enumeration
     *
     * @return {@link String}
     */
    public String getReadable() {
        return readable;
    }

    /**
     * Gets description of the enumeration
     *
     * @return {@link String}
     */
    public String getLabel() {
        return label;
    }

    /**
     * Gets a unique URI
     *
     * @return {@link String}
     */
    public String getUri() {
        return uri;
    }

    /**
     * Gets AttestationQualification from an enumeration name
     * Note: AttestationQualification can be null
     *
     * @param value
     *            the qualification name to be converted to the enum
     * @return the linked AttestationQualification or null
     */
    public static AttestationQualification forName(String value) {
        if ((value != null) && !value.isEmpty()) {
            return AttestationQualification.valueOf(value);
        }
        return null;
    }

    /**
     * Gets AttestationQualification from a readable user-friendly label
     * Note: AttestationQualification can be null
     *
     * @param readable
     *            the readable description of the qualification to be converted to the enum
     * @return the linked AttestationQualification or null
     */
    public static AttestationQualification fromReadable(String readable) {
        if ((readable != null) && !readable.isEmpty()) {
            return AttestationQualification.Registry.QUALIFS_BY_READABLE.get(readable);
        }
        return null;
    }
    
}
