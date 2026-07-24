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
package eu.europa.esig.dss.model.attestation.claim;

/**
 * Represents an EAA Status claim
 *
 */
public interface ClaimStatus extends Claim {

    /* Token Status List (TSL) draft-ietf-oauth-revocation-list-20 */

    /**
     * Gets the embedded status_list claim value
     *
     * @return {@link ClaimStatusList}
     */
    ClaimStatusList getStatusList();

    /**
     * Gets the embedded identifier_list claim value
     *
     * @return {@link ClaimIdentifierList}
     */
    ClaimIdentifierList getIdentifierList();

    /* ETSI TS 119 472-1 revocation definition */

    /**
     * Gets the EAA's Status index value, when present
     *
     * @return {@link ClaimNumber}
     */
    ClaimNumber getIndex();

    /**
     * Gets the EAA's Status URI value, when present
     *
     * @return {@link ClaimString}
     */
    ClaimString getUri();

    /**
     * Gets the EAA's Status type value, when present
     *
     * @return {@link ClaimString}
     */
    ClaimString getType();

    /**
     * Gets the EAA's Status purpose value, when present
     *
     * @return {@link ClaimString}
     */
    ClaimString getPurpose();

}
