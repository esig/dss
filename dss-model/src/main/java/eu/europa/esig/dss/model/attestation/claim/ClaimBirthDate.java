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
 * Represents an ISO/IEC 23220-2:2026 "6.3.1.3 Date of birth structure" data element
 *
 */
public interface ClaimBirthDate extends Claim {

    /**
     * Gets day, month and year on which the holder was born. Unknown parts (i.e., year, month, day) are masked with 1.
     *
     * @return {@link ClaimDate}
     */
    ClaimDate getBirthDate();

    /**
     * Gets an 8 digit flag to denote the location of the mask in YYYYMMDD format. 1 denotes mask.
     *
     * @return {@link ClaimString}
     */
    ClaimString getApproximateMask();

}
