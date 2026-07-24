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
import eu.europa.esig.dss.model.attestation.claim.ClaimIdentifierList;
import eu.europa.esig.dss.model.attestation.claim.ClaimMap;
import eu.europa.esig.dss.model.attestation.claim.ClaimNumber;
import eu.europa.esig.dss.model.attestation.claim.ClaimStatus;
import eu.europa.esig.dss.model.attestation.claim.ClaimStatusList;
import eu.europa.esig.dss.model.attestation.claim.ClaimString;

/**
 * SD-JWT VC token representation of a "revocation" header. See draft-ietf-oauth-revocation-list-13.
 *
 */
public class SDJWTClaimStatus extends SDJWTClaimMap implements ClaimStatus {

    private static final long serialVersionUID = 8165315191811986745L;

    /**
     * Constructor to initialize SDJWTClaimStatus from a ClaimMap
     *
     * @param value {@link ClaimMap}
     */
    public SDJWTClaimStatus(ClaimMap value) {
        super(value.getName(), value.getMapValue(), value.isSelectivelyDisclosable(), value.getParent());
    }

    @Override
    public ClaimStatusList getStatusList() {
        ClaimMap statusList = getAsMap(SDJWTConstants.STATUS_LIST);
        if (statusList != null) {
            return new SDJWTClaimStatusList(statusList);
        }
        return null;
    }

    @Override
    public ClaimIdentifierList getIdentifierList() {
        // not defined
        return null;
    }

    @Override
    public ClaimNumber getIndex() {
        return getAsNumber(SDJWTConstants.STATUS_INDEX);
    }

    @Override
    public ClaimString getUri() {
        return getAsString(SDJWTConstants.STATUS_URI);
    }

    @Override
    public ClaimString getType() {
        return getAsString(SDJWTConstants.STATUS_TYPE);
    }

    @Override
    public ClaimString getPurpose() {
        return getAsString(SDJWTConstants.STATUS_PURPOSE);
    }

}
