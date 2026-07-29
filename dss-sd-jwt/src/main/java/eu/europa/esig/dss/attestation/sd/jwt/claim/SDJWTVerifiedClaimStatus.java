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
import eu.europa.esig.dss.model.attestation.claim.VerifiedClaimIdentifierList;
import eu.europa.esig.dss.model.attestation.claim.VerifiedClaimMap;
import eu.europa.esig.dss.model.attestation.claim.VerifiedClaimNumber;
import eu.europa.esig.dss.model.attestation.claim.VerifiedClaimStatus;
import eu.europa.esig.dss.model.attestation.claim.VerifiedClaimStatusList;
import eu.europa.esig.dss.model.attestation.claim.VerifiedClaimString;

/**
 * SD-JWT token representation of a "status" header. See draft-ietf-oauth-revocation-list-13.
 *
 */
public class SDJWTVerifiedClaimStatus extends SDJWTVerifiedClaimMap implements VerifiedClaimStatus {

    private static final long serialVersionUID = 8165315191811986745L;

    /**
     * Constructor to initialize SDJWTClaimStatus from a ClaimMap
     *
     * @param value {@link VerifiedClaimMap}
     */
    public SDJWTVerifiedClaimStatus(VerifiedClaimMap value) {
        super(value.getName(), value.getMapValue(), value.isSelectivelyDisclosable(), value.getParent());
    }

    @Override
    public VerifiedClaimStatusList getStatusList() {
        VerifiedClaimMap statusList = getAsMap(SDJWTConstants.STATUS_LIST);
        if (statusList != null) {
            return new SDJWTVerifiedClaimStatusList(statusList);
        }
        return null;
    }

    @Override
    public VerifiedClaimIdentifierList getIdentifierList() {
        // not defined
        return null;
    }

    @Override
    public VerifiedClaimNumber getIndex() {
        return getAsNumber(SDJWTConstants.STATUS_INDEX);
    }

    @Override
    public VerifiedClaimString getUri() {
        return getAsString(SDJWTConstants.STATUS_URI);
    }

    @Override
    public VerifiedClaimString getType() {
        return getAsString(SDJWTConstants.STATUS_TYPE);
    }

    @Override
    public VerifiedClaimString getPurpose() {
        return getAsString(SDJWTConstants.STATUS_PURPOSE);
    }

}
