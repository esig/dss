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
 * Represents a structure containing information related to the validity of the MSO and its signature.
 * The structure corresponds to the definition of "ValidityInfo" per
 * "9.1.2.4 Signing method and structure for MSO" of ISO/IEC 18013-5.
 *
 */
public interface VerifiedClaimValidityInfo extends VerifiedClaim {

    /**
     * Gets the timestamp at which the MSO signature was created.
     *
     * @return {@link VerifiedClaimDate}
     */
    VerifiedClaimDate getSigned();

    /**
     * Gets the timestamp before which the MSO is not yet valid.
     *
     * @return {@link VerifiedClaimDate}
     */
    VerifiedClaimDate getValidFrom();

    /**
     * Gets the timestamp after which the MSO is no longer valid.
     *
     * @return {@link VerifiedClaimDate}
     */
    VerifiedClaimDate getValidUntil();

    /**
     * Gets the timestamp at which the issuing authority infrastructure expects to re-sign the MSO.
     *
     * @return {@link VerifiedClaimDate}
     */
    VerifiedClaimDate getExpectedUpdate();

}
