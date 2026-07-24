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
package eu.europa.esig.dss.eaa.common.creation;

import eu.europa.esig.dss.model.x509.CertificateToken;

import java.io.Serializable;
import java.util.Objects;

/**
 * Represents a status_list structure as specified in clause 6 of IETF draft-ietf-oauth-status-list-13.
 *
 */
public class TokenStatusList implements Serializable {

    private static final long serialVersionUID = -8538801549100678146L;

    /** Non-negative integer representing the index check for status information in the Status List */
    private final int index;

    /** String value that identifies the Status List Token containing the status information */
    private final String uri;

    /** (Optional) Certificate containing the public key that signed or sealed the top-level certificate in the MSO revocation list structure */
    private final CertificateToken certificate;

    /**
     * Default constructor
     *
     * @param index integer
     * @param uri {@link String}
     */
    public TokenStatusList(final int index, final String uri) {
        this(index, uri, null);
    }

    /**
     * Constructor with a certificate
     *
     * @param index integer
     * @param uri {@link String}
     * @param certificate {@link CertificateToken}
     */
    public TokenStatusList(final int index, final String uri, final CertificateToken certificate) {
        Objects.requireNonNull(uri, "Uri cannot be null!");
        if (index < 0) {
            throw new IllegalArgumentException("Index shall be a non-negative integer!");
        }
        this.index = index;
        this.uri = uri;
        this.certificate = certificate;
    }

    /**
     * Gets index of the token within a status list
     *
     * @return non-negative integer
     */
    public int getIndex() {
        return index;
    }

    /**
     * Gets URI of the status list
     *
     * @return {@link String}
     */
    public String getUri() {
        return uri;
    }

    /**
     * Gets a certificate
     *
     * @return {@link CertificateToken}
     */
    public CertificateToken getCertificate() {
        return certificate;
    }

    @Override
    public boolean equals(Object object) {
        if (this == object) return true;
        if (object == null || getClass() != object.getClass()) return false;

        TokenStatusList that = (TokenStatusList) object;
        return index == that.index
                && Objects.equals(uri, that.uri)
                && Objects.equals(certificate, that.certificate);
    }

    @Override
    public int hashCode() {
        int result = index;
        result = 31 * result + Objects.hashCode(uri);
        result = 31 * result + Objects.hashCode(certificate);
        return result;
    }

    @Override
    public String toString() {
        return "EAAStatusList [" +
                "index=" + index +
                ", uri='" + uri + '\'' +
                ", certificate=" + certificate +
                ']';
    }

}