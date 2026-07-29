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

import eu.europa.esig.dss.attestation.mdoc.EUDIPIDHeaders;
import eu.europa.esig.dss.model.attestation.claim.VerifiedClaimMap;
import eu.europa.esig.dss.model.attestation.claim.VerifiedClaimPlaceOfBirth;
import eu.europa.esig.dss.model.attestation.claim.VerifiedClaimString;

/**
 * Represents an mdoc place of birth, as defined in PID Rulebook "3.1.6 Attribute place_of_birth".
 *
 */
public class MdocVerifiedClaimPlaceOfBirth extends MdocVerifiedClaimMap implements VerifiedClaimPlaceOfBirth {

    private static final long serialVersionUID = 8034900938724415602L;

    /**
     * Default constructor
     *
     * @param value {@link VerifiedClaimMap}
     */
    public MdocVerifiedClaimPlaceOfBirth(VerifiedClaimMap value) {
        super(value.getName(), value.getNamespace(), value.getMapValue(), value.isSelectivelyDisclosable(), value.getParent());
    }
    
    @Override
    public VerifiedClaimString getCountry() {
        return getAsString(EUDIPIDHeaders.PLACE_OF_BIRTH_COUNTRY);
    }

    @Override
    public VerifiedClaimString getStateOrProvince() {
        return getAsString(EUDIPIDHeaders.PLACE_OF_BIRTH_REGION);
    }

    @Override
    public VerifiedClaimString getCity() {
        return getAsString(EUDIPIDHeaders.PLACE_OF_BIRTH_LOCALITY);
    }
    
}
