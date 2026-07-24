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

import eu.europa.esig.dss.model.attestation.claim.Claim;
import eu.europa.esig.dss.model.attestation.claim.ClaimArray;
import eu.europa.esig.dss.model.attestation.claim.ClaimDrivingPrivilegeCode;
import eu.europa.esig.dss.model.attestation.claim.ClaimDrivingPrivilegeCodes;
import eu.europa.esig.dss.model.attestation.claim.ClaimMap;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Represents an mdoc implementation of driving privilege codes, as defined in
 * "7.2.4 Categories of vehicles/restrictions/conditions" of ISO/IEC 18013-5.
 *
 */
public class MdocClaimDrivingPrivilegeCodes extends MdocClaimArray implements ClaimDrivingPrivilegeCodes {

    private static final long serialVersionUID = -6790765343355329691L;

    /**
     * Constructor to initialize MdocClaimCodes from a ClaimArray
     *
     * @param value {@link ClaimArray}
     */
    public MdocClaimDrivingPrivilegeCodes(ClaimArray value) {
        super(value.getName(), value.getNamespace(), value.getListValue(), value.isSelectivelyDisclosable(), value.getParent());
    }

    @Override
    public List<ClaimDrivingPrivilegeCode> getCodes() {
        return getListValue().stream().filter(c -> c instanceof ClaimDrivingPrivilegeCode)
                .map(c -> (ClaimDrivingPrivilegeCode) c).collect(Collectors.toList());
    }

    @Override
    public List<Claim> getListValue() {
        final List<Claim> result = new ArrayList<>();
        for (Claim claim : super.getListValue()) {
            if (claim.isMapValueType()) {
                result.add(new MdocClaimDrivingPrivilegeCode((ClaimMap) claim));
            } else {
                result.add(claim);
            }
        }
        return result;
    }

}
