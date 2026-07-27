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
import eu.europa.esig.dss.model.attestation.claim.VerifiedClaimAttestedAttributesSubjectId;
import eu.europa.esig.dss.model.attestation.claim.VerifiedClaimMap;
import eu.europa.esig.dss.model.attestation.claim.VerifiedClaimString;

/**
 * Univocally identify the attribute subject.
 *
 */
public class MdocVerifiedClaimAttestedAttributesSubjectId extends MdocVerifiedClaimMap implements VerifiedClaimAttestedAttributesSubjectId {

    private static final long serialVersionUID = 766280420105767688L;

    /**
     * Constructor to initialize MdocClaimAttestedAttributesSubjectId from a ClaimMap
     *
     * @param value {@link VerifiedClaimMap}
     */
    public MdocVerifiedClaimAttestedAttributesSubjectId(VerifiedClaimMap value) {
        super(value.getName(), value.getNamespace(), value.getMapValue(), value.isSelectivelyDisclosable(), value.getParent());
    }

    @Override
    public VerifiedClaimString getFamilyName() {
        return getAsString(ETSI194721Headers.SUB_ATTRS_ID_FAMILY_NAME);
    }

    @Override
    public VerifiedClaimString getGivenName() {
        return getAsString(ETSI194721Headers.SUB_ATTRS_ID_GIVEN_NAME);
    }

    @Override
    public VerifiedClaimString getDocumentNumber() {
        return getAsString(ETSI194721Headers.SUB_ATTRS_ID_DOCUMENT_NUMBER);
    }

}
