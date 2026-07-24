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

import eu.europa.esig.dss.attestation.mdoc.ETSI194721Headers;
import eu.europa.esig.dss.model.attestation.claim.Claim;
import eu.europa.esig.dss.model.attestation.claim.ClaimArray;
import eu.europa.esig.dss.model.attestation.claim.ClaimAttestedAttributesSubject;
import eu.europa.esig.dss.model.attestation.claim.ClaimMap;
import eu.europa.esig.dss.model.attestation.claim.ClaimString;

/**
 * Associates one attribute to one entity different than the EAA subject.
 *
 */
public class MdocClaimAttestedAttributesSubject extends MdocClaimMap implements ClaimAttestedAttributesSubject {

    private static final long serialVersionUID = 6496844266166338418L;

    /**
     * Constructor to initialize MdocClaimAttestedAttributesSubject from a ClaimMap
     *
     * @param value {@link ClaimMap}
     */
    public MdocClaimAttestedAttributesSubject(ClaimMap value) {
        super(value.getName(), value.getNamespace(), value.getMapValue(), value.isSelectivelyDisclosable(), value.getParent());
    }

    @Override
    public Claim getSubjectId() {
        ClaimMap subId = getAsMap(ETSI194721Headers.SUB_ATTRS_ID);
        if (subId != null) {
            return new MdocClaimAttestedAttributesSubjectId(subId);
        }
        return null;
    }

    @Override
    public ClaimString getSubjectPseudonym() {
        return getAsString(ETSI194721Headers.SUB_ATTRS_AKA);
    }

    @Override
    public ClaimArray getAttributes() {
        // not supported in mdoc
        return null;
    }

}
