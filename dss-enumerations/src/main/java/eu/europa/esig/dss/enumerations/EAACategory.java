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

/**
 * Provides a list of attestation category definitions
 *
 */
public enum EAACategory {

    /**
     * Indication, that the attestation has been issued as a qualified electronic attestation of attributes
     */
    EU_QEAA("urn:etsi:esi:eaa:eu:qualified"),

    /**
     * Indication, that the attestation has been issued as an electronic attestation of attributes issued by or on
     * behalf of a public body responsible for an authentic source
     */
    EU_PUBEAA("urn:etsi:esi:eaa:eu:pub");

    /** URN defined for the category */
    private final String urn;

    /**
     * Default constructor
     *
     * @param urn {@link String}
     */
    EAACategory(final String urn) {
        this.urn = urn;
    }

    /**
     * Gets URN defined for the attestation category
     *
     * @return {@link String}
     */
    public String getUrn() {
        return urn;
    }

}
