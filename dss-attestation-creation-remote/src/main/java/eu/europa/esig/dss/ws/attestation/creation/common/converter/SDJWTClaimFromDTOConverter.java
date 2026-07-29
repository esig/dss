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

import eu.europa.esig.dss.attestation.sd.jwt.creation.SDJWTClaim;
import eu.europa.esig.dss.attestation.sd.jwt.creation.SDJWTClaimArray;
import eu.europa.esig.dss.attestation.sd.jwt.creation.SDJWTClaimObject;
import eu.europa.esig.dss.ws.attestation.creation.dto.parameters.ClaimDTO;
import eu.europa.esig.dss.ws.attestation.creation.dto.parameters.ClaimValueDTO;

import java.util.Base64;
import java.util.Objects;

/**
 * Converts a {@code ClaimDTO} into an {@code SDJWTClaim}
 *
 */
public class SDJWTClaimFromDTOConverter extends AbstractAttestationClaimFromDTOConverter<SDJWTClaim> {

    /**
     * Default constructor
     */
    public SDJWTClaimFromDTOConverter() {
        super();
    }

    @Override
    public SDJWTClaim apply(ClaimDTO claimDTO) {
        Objects.requireNonNull(claimDTO, "ClaimDTO cannot be null!");
        verifyClaimValueDTO(claimDTO.getValue());

        ClaimValueDTO claimValue = claimDTO.getValue();
        if (claimValue.getArrayValue() != null) {
            SDJWTClaimArray sdjwtClaimArray;
            if (isSelectivelyDisclosable(claimDTO)) {
                sdjwtClaimArray = SDJWTClaim.createArraySelectivelyDisclosableWithSalt(claimDTO.getName(), getSalt(claimDTO.getSalt()));
            } else {
                sdjwtClaimArray = SDJWTClaim.createArray(claimDTO.getName());
            }
            claimValue.getArrayValue().forEach(c -> sdjwtClaimArray.addElement(apply(c)));
            return sdjwtClaimArray;

        } else if (claimValue.getObjectValue() != null) {
            SDJWTClaimObject sdjwtClaimObject;
            if (isSelectivelyDisclosable(claimDTO)) {
                sdjwtClaimObject = SDJWTClaim.createObjectSelectivelyDisclosableWithSalt(claimDTO.getName(), getSalt(claimDTO.getSalt()));
            } else {
                sdjwtClaimObject = SDJWTClaim.createObject(claimDTO.getName());
            }
            claimValue.getObjectValue().forEach(c -> sdjwtClaimObject.addChild(apply(c)));
            return sdjwtClaimObject;

        } else {
            if (isSelectivelyDisclosable(claimDTO)) {
                return SDJWTClaim.createSelectivelyDisclosableWithSalt(claimDTO.getName(), getValue(claimValue), getSalt(claimDTO.getSalt()));
            } else {
                return SDJWTClaim.create(claimDTO.getName(), getValue(claimValue));
            }
        }
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
        }
        return null;
    }

    /**
     * Gets base64url-encoded salt
     *
     * @param salt byte array containing salt
     * @return {@link String}
     */
    protected String getSalt(byte[] salt) {
        if (salt == null) {
            return null;
        }
        return Base64.getUrlEncoder().withoutPadding().encodeToString(salt);
    }

}
