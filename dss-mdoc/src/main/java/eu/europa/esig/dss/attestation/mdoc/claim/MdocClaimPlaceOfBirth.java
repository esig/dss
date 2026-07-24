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
import eu.europa.esig.dss.model.attestation.claim.ClaimMap;
import eu.europa.esig.dss.model.attestation.claim.ClaimPlaceOfBirth;
import eu.europa.esig.dss.model.attestation.claim.ClaimString;

/**
 * Represents an mdoc place of birth, as defined in PID Rulebook "3.1.6 Attribute place_of_birth".
 *
 */
public class MdocClaimPlaceOfBirth extends MdocClaimMap implements ClaimPlaceOfBirth {

    private static final long serialVersionUID = 8034900938724415602L;

    /**
     * Default constructor
     *
     * @param value {@link ClaimMap}
     */
    public MdocClaimPlaceOfBirth(ClaimMap value) {
        super(value.getName(), value.getNamespace(), value.getMapValue(), value.isSelectivelyDisclosable(), value.getParent());
    }
    
    @Override
    public ClaimString getCountry() {
        return getAsString(EUDIPIDHeaders.PLACE_OF_BIRTH_COUNTRY);
    }

    @Override
    public ClaimString getStateOrProvince() {
        return getAsString(EUDIPIDHeaders.PLACE_OF_BIRTH_REGION);
    }

    @Override
    public ClaimString getCity() {
        return getAsString(EUDIPIDHeaders.PLACE_OF_BIRTH_LOCALITY);
    }
    
}
