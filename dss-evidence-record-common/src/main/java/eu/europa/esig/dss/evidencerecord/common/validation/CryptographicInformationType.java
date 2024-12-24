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
package eu.europa.esig.dss.evidencerecord.common.validation;

import java.util.Objects;

/**
 * Defines type of the cryptographic information content
 */
public enum CryptographicInformationType {

    /**
     * For type CRL, a base64 encoding of a DER-encoded X.509 CRL[RFC5280]
     */
    CRL("CRL"),

    /**
     * For type OCSP, a base64 encoding of a DER-encoded OCSPResponse
     */
    OCSP("OCSP"),

    /**
     * For type SCVP, a base64 encoding of a DER-encoded CVResponse;
     */
    SCVP("SCVP"),

    /**
     * For type CERT, a base64 encoding of a DER-encoded X.509 certificate [RFC5280]
     */
    CERT("CERT");

    /** Identifies type definition string */
    private final String label;

    /**
     * Default constructor
     *
     * @param label {@link String}
     */
    CryptographicInformationType(final String label) {
        this.label = label;
    }

    /**
     * Gets the type definition label
     *
     * @return {@link String}
     */
    public String getLabel() {
        return label;
    }

    /**
     * Returns {@code CryptographicInformationType} for the given label String
     *
     * @param label {@link String}
     * @return {@link CryptographicInformationType}
     */
    public static CryptographicInformationType fromLabel(String label) {
        Objects.requireNonNull(label, "Label shall be provided!");
        for (CryptographicInformationType type : values()) {
            if (label.equals(type.label)) {
                return type;
            }
        }
        return null;
    }

}
