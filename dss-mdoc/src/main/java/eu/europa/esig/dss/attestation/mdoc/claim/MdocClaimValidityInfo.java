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

import eu.europa.esig.dss.attestation.mdoc.MdocConstants;
import eu.europa.esig.dss.model.attestation.claim.ClaimDate;
import eu.europa.esig.dss.model.attestation.claim.ClaimMap;
import eu.europa.esig.dss.model.attestation.claim.ClaimValidityInfo;

/**
 * Mdoc implementation of a ValidityInfo element as defined in "9.1.2.4 Signing method and structure for MSO"
 * of ISO/IEC 18013-5.
 *
 */
public class MdocClaimValidityInfo extends MdocClaimMap implements ClaimValidityInfo {

    private static final long serialVersionUID = 2222443004678615851L;

    /**
     * Constructor to initialize MdocClaimValidityInfo from a ClaimMap
     *
     * @param value {@link ClaimMap}
     */
    public MdocClaimValidityInfo(ClaimMap value) {
        super(value.getName(), value.getNamespace(), value.getMapValue(), value.isSelectivelyDisclosable(), value.getParent());
    }

    @Override
    public ClaimDate getSigned() {
        return getAsDateTime(MdocConstants.SIGNED);
    }

    @Override
    public ClaimDate getValidFrom() {
        return getAsDateTime(MdocConstants.VALID_FROM);
    }

    @Override
    public ClaimDate getValidUntil() {
        return getAsDateTime(MdocConstants.VALID_UNTIL);
    }

    @Override
    public ClaimDate getExpectedUpdate() {
        return getAsDateTime(MdocConstants.EXPECTED_UPDATE);
    }

}
