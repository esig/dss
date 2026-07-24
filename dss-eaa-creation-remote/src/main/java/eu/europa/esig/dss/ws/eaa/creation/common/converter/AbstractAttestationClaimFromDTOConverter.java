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
package eu.europa.esig.dss.ws.eaa.creation.common.converter;

import eu.europa.esig.dss.eaa.common.creation.claim.AttestationClaim;
import eu.europa.esig.dss.ws.eaa.creation.dto.parameters.ClaimDTO;
import eu.europa.esig.dss.ws.eaa.creation.dto.parameters.ClaimValueDTO;

import java.util.Objects;
import java.util.function.Function;

/**
 * Abstract implementation of a claim DTO into {@code EAAClaim} converter
 *
 * @param <C> {@link AttestationClaim}
 */
public abstract class AbstractAttestationClaimFromDTOConverter<C extends AttestationClaim> implements Function<ClaimDTO, C> {

    /**
     * Default constructor
     */
    protected AbstractAttestationClaimFromDTOConverter() {
        super();
    }

    /**
     * Checks whether the claim is made selectively disclosable
     *
     * @param claimDTO {@link ClaimDTO}
     * @return whether the claim is selectively disclosable
     */
    protected boolean isSelectivelyDisclosable(ClaimDTO claimDTO) {
        return Boolean.TRUE == claimDTO.getSelectivelyDisclosable();
    }

    /**
     * Verifies validity of the claim value
     *
     * @param claimValueDTO {@link ClaimValueDTO} to verify
     */
    protected void verifyClaimValueDTO(ClaimValueDTO claimValueDTO) {
        Objects.requireNonNull(claimValueDTO, "ClaimValueDTO cannot be null!");
        int definedValues = 0;
        if (claimValueDTO.getStringValue() != null) ++definedValues;
        if (claimValueDTO.getNumberValue() != null) ++definedValues;
        if (claimValueDTO.getBinaryValue() != null) ++definedValues;
        if (claimValueDTO.getBooleanValue() != null) ++definedValues;
        if (claimValueDTO.getDateValue() != null) ++definedValues;
        if (claimValueDTO.getArrayValue() != null) ++definedValues;
        if (claimValueDTO.getObjectValue() != null) ++definedValues;
        if (definedValues > 1) {
            throw new IllegalArgumentException("More than one data value is provided for a claim!");
        }
    }

}
