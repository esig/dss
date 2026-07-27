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
package eu.europa.esig.dss.attestation.mdoc.claim;

import eu.europa.esig.dss.attestation.mdoc.ISO180135Headers;
import eu.europa.esig.dss.model.attestation.claim.VerifiedClaimArray;
import eu.europa.esig.dss.model.attestation.claim.VerifiedClaimDate;
import eu.europa.esig.dss.model.attestation.claim.VerifiedClaimDrivingPrivilegeCodes;
import eu.europa.esig.dss.model.attestation.claim.VerifiedClaimDrivingPrivilege;
import eu.europa.esig.dss.model.attestation.claim.VerifiedClaimMap;
import eu.europa.esig.dss.model.attestation.claim.VerifiedClaimString;

/**
 * Represents an mdoc implementation of a driving privilege, as defined in
 * "7.2.4 Categories of vehicles/restrictions/conditions" of ISO/IEC 18013-5.
 *
 */
public class MdocVerifiedClaimDrivingPrivilege extends MdocVerifiedClaimMap implements VerifiedClaimDrivingPrivilege {

    private static final long serialVersionUID = 4937039974596393841L;

    /**
     * Constructor to initialize MdocDrivingPrivilege from a ClaimMap
     *
     * @param value {@link VerifiedClaimMap}
     */
    public MdocVerifiedClaimDrivingPrivilege(VerifiedClaimMap value) {
        super(value.getName(), value.getNamespace(), value.getMapValue(), value.isSelectivelyDisclosable(), value.getParent());
    }

    @Override
    public VerifiedClaimString getVehicleCategoryCode() {
        return getAsString(ISO180135Headers.DRIVING_PRIVILEGES_VEHICLE_CATEGORY_CODE);
    }

    @Override
    public VerifiedClaimDate getIssueDate() {
        return getAsDate(ISO180135Headers.DRIVING_PRIVILEGES_ISSUE_DATE);
    }

    @Override
    public VerifiedClaimDate getExpiryDate() {
        return getAsDate(ISO180135Headers.DRIVING_PRIVILEGES_EXPIRY_DATE);
    }

    @Override
    public VerifiedClaimDrivingPrivilegeCodes getCodes() {
        VerifiedClaimArray codesArray = getAsArray(ISO180135Headers.DRIVING_PRIVILEGES_CODES);
        if (codesArray != null) {
            return new MdocVerifiedClaimDrivingPrivilegeCodes(codesArray);
        }
        return null;
    }

}
