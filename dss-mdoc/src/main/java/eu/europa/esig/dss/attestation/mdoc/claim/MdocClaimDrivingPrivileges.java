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
import eu.europa.esig.dss.model.attestation.claim.ClaimDrivingPrivilege;
import eu.europa.esig.dss.model.attestation.claim.ClaimDrivingPrivileges;
import eu.europa.esig.dss.model.attestation.claim.ClaimMap;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Represents an mdoc implementation of driving privileges, as defined in
 * "7.2.4 Categories of vehicles/restrictions/conditions" of ISO/IEC 18013-5.
 *
 */
public class MdocClaimDrivingPrivileges extends MdocClaimArray implements ClaimDrivingPrivileges {

    private static final long serialVersionUID = -8130304027679306126L;

    /**
     * Constructor to initialize MdocDrivingPrivileges from a ClaimArray
     *
     * @param value {@link ClaimArray}
     */
    public MdocClaimDrivingPrivileges(ClaimArray value) {
        super(value.getName(), value.getNamespace(), value.getListValue(), value.isSelectivelyDisclosable(), value.getParent());
    }

    @Override
    public List<ClaimDrivingPrivilege> getDrivingPrivileges() {
        return getListValue().stream().filter(c -> c instanceof MdocClaimDrivingPrivilege)
                .map(c -> (MdocClaimDrivingPrivilege) c).collect(Collectors.toList());
    }

    @Override
    public List<Claim> getListValue() {
        final List<Claim> result = new ArrayList<>();
        for (Claim claim : super.getListValue()) {
            if (claim.isMapValueType()) {
                result.add(new MdocClaimDrivingPrivilege((ClaimMap) claim));
            } else {
                result.add(claim);
            }
        }
        return result;
    }

}
