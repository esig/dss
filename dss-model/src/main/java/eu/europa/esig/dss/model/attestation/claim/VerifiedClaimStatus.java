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
 * Represents an attestation Status claim
 *
 */
public interface VerifiedClaimStatus extends VerifiedClaim {

    /* Token Status List (TSL) draft-ietf-oauth-revocation-list-20 */

    /**
     * Gets the embedded status_list claim value
     *
     * @return {@link VerifiedClaimStatusList}
     */
    VerifiedClaimStatusList getStatusList();

    /**
     * Gets the embedded identifier_list claim value
     *
     * @return {@link VerifiedClaimIdentifierList}
     */
    VerifiedClaimIdentifierList getIdentifierList();

    /* ETSI TS 119 472-1 revocation definition */

    /**
     * Gets the attestation's Status index value, when present
     *
     * @return {@link VerifiedClaimNumber}
     */
    VerifiedClaimNumber getIndex();

    /**
     * Gets the attestation's Status URI value, when present
     *
     * @return {@link VerifiedClaimString}
     */
    VerifiedClaimString getUri();

    /**
     * Gets the attestation's Status type value, when present
     *
     * @return {@link VerifiedClaimString}
     */
    VerifiedClaimString getType();

    /**
     * Gets the attestation's Status purpose value, when present
     *
     * @return {@link VerifiedClaimString}
     */
    VerifiedClaimString getPurpose();

}
