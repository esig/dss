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

import eu.europa.esig.dss.attestation.mdoc.ISO232202Headers;
import eu.europa.esig.dss.model.attestation.claim.VerifiedClaimBirthDate;
import eu.europa.esig.dss.model.attestation.claim.VerifiedClaimDate;
import eu.europa.esig.dss.model.attestation.claim.VerifiedClaimMap;
import eu.europa.esig.dss.model.attestation.claim.VerifiedClaimString;

/**
 * Mdoc implementation of the ISO/IEC 23220-2:2026 "6.3.1.3 Date of birth structure" data element
 *
 */
public class MdocVerifiedClaimBirthDate extends MdocVerifiedClaimMap implements VerifiedClaimBirthDate {

    private static final long serialVersionUID = -7090594892082602908L;

    /**
     * Constructor to initialize MdocClaimBirthDate from a ClaimMap
     *
     * @param value {@link VerifiedClaimMap}
     */
    public MdocVerifiedClaimBirthDate(VerifiedClaimMap value) {
        super(value.getName(), value.getNamespace(), value.getMapValue(), value.isSelectivelyDisclosable(), value.getParent());
    }

    @Override
    public VerifiedClaimDate getBirthDate() {
        return getAsDate(ISO232202Headers.BIRTH_DATE);
    }

    @Override
    public VerifiedClaimString getApproximateMask() {
        return getAsString(ISO232202Headers.APPROXIMATE_MASK);
    }

}
