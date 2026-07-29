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

import eu.europa.esig.dss.model.attestation.claim.VerifiedClaimAgeOverNN;
import eu.europa.esig.dss.model.attestation.claim.VerifiedClaimBoolean;
import eu.europa.esig.dss.utils.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * SD-JWT claim representing an age_over_NN for a given value
 *
 */
public class SDJWTVerifiedClaimAgeOverNN extends VerifiedClaimBoolean implements VerifiedClaimAgeOverNN {

    private static final long serialVersionUID = -1770354162483216734L;

    private static final Logger LOG = LoggerFactory.getLogger(SDJWTVerifiedClaimAgeOverNN.class);

    /**
     * Constructor to initialize SDJWTClaimAgeOverNN from a ClaimBoolean
     *
     * @param value {@link VerifiedClaimBoolean}
     */
    public SDJWTVerifiedClaimAgeOverNN(VerifiedClaimBoolean value) {
        super(value.getName(), value.getBooleanValue(), value.isSelectivelyDisclosable(), value.getParent());
    }

    @Override
    public Integer getAge() {
        String name = getName();
        if (Utils.isStringDigits(name)) {
            return Integer.parseInt(name);
        }
        LOG.warn("Unable to determine age from the header with name '{}'!", name);
        return null;
    }

}
