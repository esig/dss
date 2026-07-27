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
import eu.europa.esig.dss.model.attestation.claim.VerifiedClaimArray;
import eu.europa.esig.dss.model.attestation.claim.VerifiedClaimAttestedAttributesSubject;
import eu.europa.esig.dss.model.attestation.claim.VerifiedClaimMap;
import eu.europa.esig.dss.model.attestation.claim.VerifiedClaimString;

/**
 * SD-JWT implementation of the attested attributes claims
 *
 */
public class SDJWTVerifiedClaimAttestedAttributesSubject extends SDJWTVerifiedClaimMap implements VerifiedClaimAttestedAttributesSubject {

    private static final long serialVersionUID = 2378393232187408462L;

    /**
     * Default constructor
     *
     * @param value {@link VerifiedClaimMap}
     */
    public SDJWTVerifiedClaimAttestedAttributesSubject(VerifiedClaimMap value) {
        super(value.getName(), value.getMapValue(), value.isSelectivelyDisclosable(), value.getParent());
    }

    @Override
    public VerifiedClaimString getSubjectId() {
        /*
        * EAA-5.3-04: The sub_id member shall be a JSON String whose value shall be the identifier of the attribute
        * subject, which shall associate the attributes to this attribute subject.
        */
        return getAsString(SDJWTConstants.ATTESTED_ATTRIBUTES_SUBJECT_ID);
    }

    @Override
    public VerifiedClaimString getPseudonym() {
        /*
         * EAA-5.3-05: The sub_aka member shall be a JSON String whose value shall be the pseudonym of an attribute
         * subject which shall associate the attributes to this attribute subject.
         */
        return getAsString(SDJWTConstants.ATTESTED_ATTRIBUTES_SUBJECT_AKA);
    }

    @Override
    public VerifiedClaimArray getAttributes() {
        /*
         * EAA-5.3-07: The attrs member shall be a JSON Array whose elements shall be the attributes associated to the
         * attribute subject whose identifier appears in the sub_id member or whose pseudonym appears in the sub_aka
         * member.
         */
        return getAsArray(SDJWTConstants.ATTESTED_ATTRIBUTES_SUBJECT_ATTRIBUTES);
    }

}
