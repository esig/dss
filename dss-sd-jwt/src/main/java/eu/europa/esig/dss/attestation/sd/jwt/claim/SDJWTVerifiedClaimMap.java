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

import eu.europa.esig.dss.attestation.sd.jwt.SDJWTUtils;
import eu.europa.esig.dss.model.attestation.claim.VerifiedClaim;
import eu.europa.esig.dss.model.attestation.claim.VerifiedClaimDate;
import eu.europa.esig.dss.model.attestation.claim.VerifiedClaimMap;
import eu.europa.esig.dss.model.attestation.claim.VerifiedClaimNumber;
import eu.europa.esig.dss.model.attestation.claim.VerifiedClaimString;
import eu.europa.esig.dss.spi.DSSUtils;

import java.util.Date;
import java.util.Map;

/**
 * SD-JWT implementation of a ClaimMap
 *
 */
public class SDJWTVerifiedClaimMap extends VerifiedClaimMap {

    private static final long serialVersionUID = -8277442405573676334L;

    /**
     * Simplified constructor with a map value
     *
     * @param value {@link Map}
     */
    protected SDJWTVerifiedClaimMap(Map<?, ?> value) {
        super(value);
    }

    /**
     * Default constructor
     *
     * @param name {@link String} claim header name
     * @param value value of the claim
     * @param selectivelyDisclosable whether the claim is selectively disclosable
     *                               (can be TRUE only when the value of claim is provided in a form of disclosure)
     * @param parent {@link VerifiedClaim} representing the parent claim, when applicable
     */
    public SDJWTVerifiedClaimMap(String name, Map<?, ?> value, boolean selectivelyDisclosable, VerifiedClaim parent) {
        super(name, value, selectivelyDisclosable, parent);
    }

    /**
     * Gets the claim value if a Date from the current map using the {@code headerName} as a key
     *
     * @param headerName {@link String}
     * @return {@link VerifiedClaimDate}
     */
    public VerifiedClaimDate getAsDate(String headerName) {
        VerifiedClaimString claimString = getAsString(headerName);
        if (claimString != null) {
            Date date = DSSUtils.parseISO8601Date(claimString.getStringValue());
            if (date != null) {
                return new VerifiedClaimDate(headerName, date, claimString.isSelectivelyDisclosable());
            }
        }
        return null;
    }

    /**
     * Gets value of a header with name {@code headerName} as ClaimDate.
     * Returns NULL if no value is provided or the Claim is of a different type.
     *
     * @param headerName {@link String} to get header value from the payload
     * @return {@link VerifiedClaimDate}
     */
    public VerifiedClaimDate getAsDateTime(String headerName) {
        VerifiedClaimString claimString = getAsString(headerName);
        if (claimString != null) {
            Date date = DSSUtils.parseRFCDate(claimString.getStringValue());
            if (date != null) {
                return new VerifiedClaimDate(headerName, date, claimString.isSelectivelyDisclosable());
            }
        }
        VerifiedClaimNumber claimNumber = getAsNumber(headerName);
        if (claimNumber != null) {
            long timeValueInMilliseconds = DSSUtils.getTimeValueInMilliseconds(claimNumber.getNumberValue().longValue());
            Date date = DSSUtils.getDateFromMilliseconds(timeValueInMilliseconds);
            return new VerifiedClaimDate(headerName, date, claimNumber.isSelectivelyDisclosable());
        }
        return null;
    }

    @Override
    protected String getKeyAsString(Object key) {
        return (String) key; // only String keys are supported in JSON
    }

    @Override
    protected VerifiedClaim createClaim(String name, Object value) {
        return SDJWTUtils.createClaim(name, this, value);
    }

}
