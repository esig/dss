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
import eu.europa.esig.dss.model.attestation.claim.VerifiedClaim;
import eu.europa.esig.dss.model.attestation.claim.VerifiedClaimArray;
import eu.europa.esig.dss.model.attestation.claim.VerifiedClaimAttestedAttributesSubject;
import eu.europa.esig.dss.model.attestation.claim.VerifiedClaimMap;
import eu.europa.esig.dss.model.attestation.claim.VerifiedClaimString;

/**
 * Associates one attribute to one entity different than the attestation subject.
 *
 */
public class MdocVerifiedClaimAttestedAttributesSubject extends MdocVerifiedClaimMap implements VerifiedClaimAttestedAttributesSubject {

    private static final long serialVersionUID = 6496844266166338418L;

    /**
     * Constructor to initialize MdocClaimAttestedAttributesSubject from a ClaimMap
     *
     * @param value {@link VerifiedClaimMap}
     */
    public MdocVerifiedClaimAttestedAttributesSubject(VerifiedClaimMap value) {
        super(value.getName(), value.getNamespace(), value.getMapValue(), value.isSelectivelyDisclosable(), value.getParent());
    }

    @Override
    public VerifiedClaim getSubjectId() {
        VerifiedClaimMap subId = getAsMap(ETSI194721Headers.SUB_ATTRS_ID);
        if (subId != null) {
            return new MdocVerifiedClaimAttestedAttributesSubjectId(subId);
        }
        return null;
    }

    @Override
    public VerifiedClaimString getPseudonym() {
        return getAsString(ETSI194721Headers.SUB_ATTRS_AKA);
    }

    @Override
    public VerifiedClaimArray getAttributes() {
        // not supported in mdoc
        return null;
    }

}
