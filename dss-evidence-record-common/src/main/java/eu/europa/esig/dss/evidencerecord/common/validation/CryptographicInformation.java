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

/**
 * Defines CryptographicInformation element content
 */
public class CryptographicInformation implements EvidenceRecordObject {

    private static final long serialVersionUID = -3444524343827820741L;

    /** Defines content of the Cryptographic Information element */
    private final byte[] content;

    /** Defines type of the Cryptographic Information element */
    private final CryptographicInformationType type;

    /**
     * Default constructor
     *
     * @param content byte array containing Cryptographic Information element's content
     * @param type {@link CryptographicInformationType}
     */
    public CryptographicInformation(final byte[] content, final CryptographicInformationType type) {
        this.content = content;
        this.type = type;
    }

    /**
     * Gets content of the Cryptographic Information element
     *
     * @return byte array
     */
    public byte[] getContent() {
        return content;
    }

    /**
     * Gets type of the Cryptographic Information element
     *
     * @return {@link CryptographicInformationType}
     */
    public CryptographicInformationType getType() {
        return type;
    }

}
