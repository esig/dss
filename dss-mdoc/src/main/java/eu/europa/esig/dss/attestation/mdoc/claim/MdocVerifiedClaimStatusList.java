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
import eu.europa.esig.dss.model.attestation.claim.VerifiedClaimByteString;
import eu.europa.esig.dss.model.attestation.claim.VerifiedClaimMap;
import eu.europa.esig.dss.model.attestation.claim.VerifiedClaimNumber;
import eu.europa.esig.dss.model.attestation.claim.VerifiedClaimStatusList;
import eu.europa.esig.dss.model.attestation.claim.VerifiedClaimString;

/**
 * Mdoc implementation of a status_list structure as defined in
 * https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-19.html
 * 
 */
public class MdocVerifiedClaimStatusList extends MdocVerifiedClaimMap implements VerifiedClaimStatusList {

    private static final long serialVersionUID = 8267815192474246983L;

    /**
     * Constructor to initialize MdocClaimStatus from a ClaimMap
     *
     * @param value {@link VerifiedClaimMap}
     */
    public MdocVerifiedClaimStatusList(VerifiedClaimMap value) {
        super(value.getName(), value.getNamespace(), value.getMapValue(), value.isSelectivelyDisclosable(), value.getParent());
    }

    @Override
    public VerifiedClaimNumber getIndex() {
        return getAsNumber(MdocConstants.STATUS_IDX);
    }

    @Override
    public VerifiedClaimString getUri() {
        return getAsString(MdocConstants.STATUS_URI);
    }

    @Override
    public VerifiedClaimByteString getCertificate() {
        return getAsByteString(MdocConstants.STATUS_CERTIFICATE);
    }

}
