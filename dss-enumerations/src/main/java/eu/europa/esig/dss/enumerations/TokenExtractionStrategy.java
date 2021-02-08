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
package eu.europa.esig.dss.enumerations;

/**
 * Defines a representation of tokens in the DiagnosticData (as binaries or digests)
 */
public enum TokenExtractionStrategy {

    /**
     * Extract certificates, timestamps and revocation data
     */
    EXTRACT_ALL(true, true, true),

    /**
     * Extract certificates
     */
    EXTRACT_CERTIFICATES_ONLY(true, false, false),

    /**
     * Extract timestamps
     */
    EXTRACT_TIMESTAMPS_ONLY(false, true, false),

    /**
     * Extract revocation data
     */
    EXTRACT_REVOCATION_DATA_ONLY(false, false, true),

    /**
     * Extract certificates and timestamps
     */
    EXTRACT_CERTIFICATES_AND_TIMESTAMPS(true, true, false),

    /**
     * Extract certificates and revocation data
     */
    EXTRACT_CERTIFICATES_AND_REVOCATION_DATA(true, false, true),

    /**
     * Extract timestamps and revocation data
     */
    EXTRACT_TIMESTAMPS_AND_REVOCATION_DATA(false, true,
            true),

    /**
     * Extract nothing
     */
    NONE(false, false, false);

    private final boolean certificate;
    private final boolean timestamp;
    private final boolean revocationData;

    TokenExtractionStrategy(boolean certificate, boolean timestamp, boolean revocationData) {
        this.certificate = certificate;
        this.timestamp = timestamp;
        this.revocationData = revocationData;
    }

    /**
     * This method returns true if the certificate extraction is enabled
     *
     * @return true if certificates need to be extracted
     */
    public boolean isCertificate() {
        return certificate;
    }

    /**
     * This method returns true if the timestamp extraction is enabled
     *
     * @return true if timestamps need to be extracted
     */
    public boolean isTimestamp() {
        return timestamp;
    }

    /**
     * This method returns true if the revocation data extraction is enabled
     *
     * @return true if revocation data need to be extracted
     */
    public boolean isRevocationData() {
        return revocationData;
    }

    /**
     * Returns the enumeration value depending on parameters
     *
     * @param certificate    true if certificates need to be extracted
     * @param timestamp      true if timestamps need to be extracted
     * @param revocationData true if revocation data need to be extracted
     * @return {@link TokenExtractionStrategy}
     */
    public static TokenExtractionStrategy fromParameters(boolean certificate, boolean timestamp, boolean revocationData) {
        for (TokenExtractionStrategy value : TokenExtractionStrategy.values()) {
            if ((certificate == value.certificate) && (timestamp == value.timestamp) && (revocationData == value.revocationData)) {
                return value;
            }
        }
        return TokenExtractionStrategy.NONE;
    }

}
