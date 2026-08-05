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
package eu.europa.esig.dss.ws.attestation.creation.common.converter;

import eu.europa.esig.dss.attestation.mdoc.creation.MdocClaim;
import eu.europa.esig.dss.ws.attestation.creation.dto.parameters.ClaimDTO;
import eu.europa.esig.dss.ws.attestation.creation.dto.parameters.ClaimValueDTO;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Converts a {@code ClaimDTO} into an {@code MdocClaim}
 *
 */
public class MdocClaimFromDTOConverter extends AbstractAttestationClaimFromDTOConverter<MdocClaim> {

    /**
     * Default constructor
     */
    public MdocClaimFromDTOConverter() {
        super();
    }

    @Override
    public MdocClaim apply(ClaimDTO claimDTO) {
        Objects.requireNonNull(claimDTO, "ClaimDTO cannot be null!");
        verifyClaimValueDTO(claimDTO.getValue());

        if (claimDTO.getDigestId() == null) {
            return MdocClaim.create(claimDTO.getNamespace(), claimDTO.getName(),
                    getValue(claimDTO.getValue()), claimDTO.getSalt());
        }
        return MdocClaim.create(claimDTO.getNamespace(), claimDTO.getDigestId(), claimDTO.getName(),
                getValue(claimDTO.getValue()), claimDTO.getSalt());
    }

    /**
     * Gets a plain value of the {@code claimValueDTO}
     *
     * @param claimValueDTO {@link ClaimValueDTO}
     * @return {@link Object}
     */
    protected Object getValue(ClaimValueDTO claimValueDTO) {
        if (claimValueDTO.getStringValue() != null) {
            return claimValueDTO.getStringValue();
        } else if (claimValueDTO.getNumberValue() != null) {
            return claimValueDTO.getNumberValue();
        } else if (claimValueDTO.getBooleanValue() != null) {
            return claimValueDTO.getBooleanValue();
        } else if (claimValueDTO.getBinaryValue() != null) {
            return claimValueDTO.getBinaryValue();
        } else if (claimValueDTO.getDateValue() != null) {
            return claimValueDTO.getDateValue();
        } else if (claimValueDTO.getArrayValue() != null) {
            List<Object> result = new ArrayList<>();
            claimValueDTO.getArrayValue().forEach(i -> result.add(apply(i).getValue()));
            return result;
        } else if (claimValueDTO.getObjectValue() != null) {
            Map<String, Object> result = new HashMap<>();
            claimValueDTO.getObjectValue().forEach(i -> result.put(i.getName(), apply(i).getValue()));
            return result;
        }
        return null;
    }

}
