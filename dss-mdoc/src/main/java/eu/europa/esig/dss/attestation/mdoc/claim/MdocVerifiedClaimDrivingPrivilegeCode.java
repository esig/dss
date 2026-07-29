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
import eu.europa.esig.dss.model.attestation.claim.VerifiedClaimDrivingPrivilegeCode;
import eu.europa.esig.dss.model.attestation.claim.VerifiedClaimMap;
import eu.europa.esig.dss.model.attestation.claim.VerifiedClaimString;

/**
 * Represents an mdoc implementation of a driving privilege code, as defined in
 * "7.2.4 Categories of vehicles/restrictions/conditions" of ISO/IEC 18013-5.
 *
 */
public class MdocVerifiedClaimDrivingPrivilegeCode extends MdocVerifiedClaimMap implements VerifiedClaimDrivingPrivilegeCode {

    private static final long serialVersionUID = -4531064601793382331L;

    /**
     * Constructor to initialize MdocClaimCode from a ClaimMap
     *
     * @param value {@link VerifiedClaimMap}
     */
    public MdocVerifiedClaimDrivingPrivilegeCode(VerifiedClaimMap value) {
        super(value.getName(), value.getNamespace(), value.getMapValue(), value.isSelectivelyDisclosable(), value.getParent());
    }

    @Override
    public VerifiedClaimString getCode() {
        return getAsString(ISO180135Headers.DRIVING_PRIVILEGES_CODE_CODE);
    }

    @Override
    public VerifiedClaimString getSign() {
        return getAsString(ISO180135Headers.DRIVING_PRIVILEGES_CODE_SIGN);
    }

    @Override
    public VerifiedClaimString getValue() {
        return getAsString(ISO180135Headers.DRIVING_PRIVILEGES_CODE_VALUE);
    }

}
