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
 * Represents a single item of the "driving_privileges" claim array, as defined in
 * "7.2.4 Categories of vehicles/restrictions/conditions" of ISO/IEC 18013-5.
 *
 */
public interface VerifiedClaimDrivingPrivilege extends VerifiedClaim {

    /**
     * Gets a vehicle category code as per ISO/IEC 18013-1 Annex B
     *
     * @return {@link VerifiedClaimString}
     */
    VerifiedClaimString getVehicleCategoryCode();

    /**
     * Gets a date of issue encoded as full-date
     *
     * @return {@link VerifiedClaimDate}
     */
    VerifiedClaimDate getIssueDate();

    /**
     * Gets a date of expiry encoded as full-date
     *
     * @return {@link VerifiedClaimDate}
     */
    VerifiedClaimDate getExpiryDate();

    /**
     * Gets an array of code info
     *
     * @return {@link VerifiedClaimArray}
     */
    VerifiedClaimDrivingPrivilegeCodes getCodes();

}
