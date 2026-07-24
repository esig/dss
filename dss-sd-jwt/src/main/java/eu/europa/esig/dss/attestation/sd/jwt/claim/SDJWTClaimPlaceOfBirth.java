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
import eu.europa.esig.dss.model.attestation.claim.ClaimMap;
import eu.europa.esig.dss.model.attestation.claim.ClaimPlaceOfBirth;
import eu.europa.esig.dss.model.attestation.claim.ClaimString;

/**
 * Represents an SD JWT VC user's place of birth, as defined in
 * OpenID Connect for Identity Assurance Claims Registration 1.0 "4.1. Additional claims about end-users".
 *
 */
public class SDJWTClaimPlaceOfBirth extends SDJWTClaimMap implements ClaimPlaceOfBirth {

    private static final long serialVersionUID = 2338450733613706116L;

    /**
     * Default constructor
     *
     * @param value {@link ClaimMap}
     */
    public SDJWTClaimPlaceOfBirth(ClaimMap value) {
        super(value.getName(), value.getMapValue(), value.isSelectivelyDisclosable(), value.getParent());
    }

    @Override
    public ClaimString getCountry() {
        return getAsString(SDJWTConstants.USER_PLACE_OF_BIRTH_COUNTRY);
    }

    @Override
    public ClaimString getStateOrProvince() {
        return getAsString(SDJWTConstants.USER_PLACE_OF_BIRTH_REGION);
    }

    @Override
    public ClaimString getCity() {
        return getAsString(SDJWTConstants.USER_PLACE_OF_BIRTH_LOCALITY);
    }

}
