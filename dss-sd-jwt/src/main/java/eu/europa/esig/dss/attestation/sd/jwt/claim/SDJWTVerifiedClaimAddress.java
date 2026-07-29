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
package eu.europa.esig.dss.attestation.sd.jwt.claim;

import eu.europa.esig.dss.attestation.sd.jwt.SDJWTConstants;
import eu.europa.esig.dss.model.attestation.claim.VerifiedClaimAddress;
import eu.europa.esig.dss.model.attestation.claim.VerifiedClaimMap;
import eu.europa.esig.dss.model.attestation.claim.VerifiedClaimString;

/**
 * SD-JWT token representation of a user address claim, defined in OpenID Connect Core 1.0 "5.1.1. Address Claim".
 *
 */
public class SDJWTVerifiedClaimAddress extends SDJWTVerifiedClaimMap implements VerifiedClaimAddress {

    private static final long serialVersionUID = 4589801086719909382L;

    /**
     * Constructor to initialize SDJWTClaimAddress from a ClaimMap
     *
     * @param value {@link VerifiedClaimMap}
     */
    public SDJWTVerifiedClaimAddress(VerifiedClaimMap value) {
        super(value.getName(), value.getMapValue(), value.isSelectivelyDisclosable(), value.getParent());
    }

    @Override
    public VerifiedClaimString getPostalAddress() {
        return getAsString(SDJWTConstants.USER_ADDRESS_FORMATTED);
    }

    @Override
    public VerifiedClaimString getStreetAddress() {
        return getAsString(SDJWTConstants.USER_ADDRESS_STREET_ADDRESS);
    }

    @Override
    public VerifiedClaimString getCity() {
        return getAsString(SDJWTConstants.USER_ADDRESS_LOCALITY);
    }

    @Override
    public VerifiedClaimString getStateOrProvince() {
        return getAsString(SDJWTConstants.USER_ADDRESS_REGION);
    }

    @Override
    public VerifiedClaimString getPostalCode() {
        return getAsString(SDJWTConstants.USER_ADDRESS_POSTAL_CODE);
    }

    @Override
    public VerifiedClaimString getCountry() {
        return getAsString(SDJWTConstants.USER_ADDRESS_COUNTRY);
    }

    @Override
    public VerifiedClaimString getHouseNumber() {
        return getAsString(SDJWTConstants.USER_ADDRESS_HOUSE_NUMBER);
    }

}
