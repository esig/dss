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

import eu.europa.esig.dss.model.attestation.claim.VerifiedClaim;
import eu.europa.esig.dss.model.attestation.claim.VerifiedClaimAgeOverNN;
import eu.europa.esig.dss.model.attestation.claim.VerifiedClaimAgeEqualOrOver;
import eu.europa.esig.dss.model.attestation.claim.VerifiedClaimBoolean;
import eu.europa.esig.dss.model.attestation.claim.VerifiedClaimMap;
import eu.europa.esig.dss.utils.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * Represents the "age_equal_or_over" SD-JWT claim.
 * NOTE: Last occurrence in PID Rulebook 2.4.0.
 *
 */
public class SDJWTVerifiedClaimAgeOverNNList extends SDJWTVerifiedClaimMap implements VerifiedClaimAgeEqualOrOver {

    private static final long serialVersionUID = -1770354162483216734L;

    private static final Logger LOG = LoggerFactory.getLogger(SDJWTVerifiedClaimAgeOverNNList.class);

    /**
     * Constructor to initialize SDJWTClaimStatus from a ClaimMap
     *
     * @param value {@link VerifiedClaimMap}
     */
    public SDJWTVerifiedClaimAgeOverNNList(VerifiedClaimMap value) {
        super(value.getName(), value.getMapValue(), value.isSelectivelyDisclosable(), value.getParent());
    }

    @Override
    public List<VerifiedClaimAgeOverNN> getAgeOverNNClaims() {
        Map<String, VerifiedClaim> embeddedClaims = getMapValue();
        if (Utils.isMapEmpty(embeddedClaims)) {
            return Collections.emptyList();
        }

        final List<VerifiedClaimAgeOverNN> result = new ArrayList<>();
        for (VerifiedClaim claim : embeddedClaims.values()) {
            if (claim.isBooleanValueType()) {
                result.add(new SDJWTVerifiedClaimAgeOverNN((VerifiedClaimBoolean) claim));
            } else {
                LOG.warn("An item of 'age_equal_or_over' shall be of boolean type!");
            }
        }
        return result;
    }

}
