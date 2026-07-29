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
 * Represents an "address" claim.
 *
 */
public interface VerifiedClaimAddress extends VerifiedClaim {

    /**
     * Gets the user's full postal or mailing address, formatted, when present
     *
     * @return {@link VerifiedClaimString}
     */
    VerifiedClaimString getPostalAddress();

    /**
     * Gets the user's street address, when present.
     * The component may include a house number, street name, Post Office Box, and multi-line
     * extended street address information.
     *
     * @return {@link VerifiedClaimString}
     */
    VerifiedClaimString getStreetAddress();

    /**
     * Gets the user's city or locality address, when present.
     *
     * @return {@link VerifiedClaimString}
     */
    VerifiedClaimString getCity();

    /**
     * Gets the user's state or region address, when present.
     *
     * @return {@link VerifiedClaimString}
     */
    VerifiedClaimString getStateOrProvince();

    /**
     * Gets the user's zip code or postal code address, when present.
     *
     * @return {@link VerifiedClaimString}
     */
    VerifiedClaimString getPostalCode();

    /**
     * Gets the user's country address, when present.
     *
     * @return {@link VerifiedClaimString}
     */
    VerifiedClaimString getCountry();

    /* ARF PID Rulebook claims */

    /**
     * Gets The house number where the user to whom the person identification data relates currently resides,
     * including any affix or suffix, when present.
     *
     * @return {@link VerifiedClaimString}
     */
    VerifiedClaimString getHouseNumber();

}
