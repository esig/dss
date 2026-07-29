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

import eu.europa.esig.dss.attestation.mdoc.MdocUtils;
import eu.europa.esig.dss.model.attestation.claim.VerifiedClaim;
import eu.europa.esig.dss.model.attestation.claim.VerifiedClaimArray;
import eu.europa.esig.dss.model.attestation.claim.VerifiedClaimByteString;
import eu.europa.esig.dss.model.attestation.claim.VerifiedClaimDate;
import eu.europa.esig.dss.model.attestation.claim.VerifiedClaimMap;
import eu.europa.esig.dss.model.attestation.claim.VerifiedClaimNumber;
import eu.europa.esig.dss.model.attestation.claim.VerifiedClaimString;
import eu.europa.esig.dss.spi.DSSUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Date;
import java.util.Map;

/**
 * Mdoc implementation of a ClaimMap
 *
 */
public class MdocVerifiedClaimMap extends VerifiedClaimMap {

    private static final Logger LOG = LoggerFactory.getLogger(MdocVerifiedClaimMap.class);

    private static final long serialVersionUID = 5139850883142004890L;

    /**
     * Simplified constructor with a map value
     *
     * @param value {@link Map}
     */
    protected MdocVerifiedClaimMap(Map<?, ?> value) {
        super(value);
    }

    /**
     * Default constructor
     *
     * @param name {@link String} claim header name
     * @param namespace {@link String} representing the original namespace (NOTE: used in mdoc)
     * @param value value of the claim
     * @param selectivelyDisclosable whether the claim is selectively disclosable
     *                               (can be TRUE only when the value of claim is provided in a form of disclosure)
     * @param parent {@link VerifiedClaim} representing the parent claim, when applicable
     */
    public MdocVerifiedClaimMap(final String name, final String namespace, final Map<?, ?> value,
                                final boolean selectivelyDisclosable, final VerifiedClaim parent) {
        super(name, namespace, value, selectivelyDisclosable, parent);
    }

    /**
     * Gets the claims for the corresponding header name key
     *
     * @param headerLabel {@link Number} header name or a map key to get a corresponding value for
     * @return {@link VerifiedClaim}
     */
    public VerifiedClaim get(Number headerLabel) {
        return getMapValue().get(getKeyAsString(headerLabel));
    }

    /**
     * Gets the claim value if a string from the current map using the {@code headerLabel} as a key
     *
     * @param headerLabel {@link Number}
     * @return {@link VerifiedClaimString}
     */
    public VerifiedClaimString getAsString(Number headerLabel) {
        return getAsString(getKeyAsString(headerLabel));
    }

    /**
     * Gets the claim value if a number from the current map using the {@code headerLabel} as a key
     *
     * @param headerLabel {@link Number}
     * @return {@link VerifiedClaimNumber}
     */
    public VerifiedClaimNumber getAsNumber(Number headerLabel) {
        return getAsNumber(getKeyAsString(headerLabel));
    }

    /**
     * Checks if the claim for the {@code headerName} is of a CBOR array type and returns its value as {@code ClaimByteString}
     *
     * @param headerLabel {@link Number} to get header value from the map
     * @return {@link VerifiedClaimArray}
     */
    protected VerifiedClaimArray getAsArray(Number headerLabel) {
        return getAsArray(getKeyAsString(headerLabel));
    }

    /**
     * Checks if the {@code claim} is of date type and returns its value as {@code ClaimDate}
     *
     * @param headerName {@link String} to get header value from the payload
     * @return {@link VerifiedClaimDate}
     */
    protected VerifiedClaimDate getAsDate(String headerName) {
        VerifiedClaim claim = get(headerName);
        return getAsDate(claim);
    }

    /**
     * Checks if the {@code claim} is of date type and returns its value as {@code ClaimDate}
     *
     * @param claim {@link VerifiedClaim}
     * @return {@link VerifiedClaimDate}
     */
    protected VerifiedClaimDate getAsDate(VerifiedClaim claim) {
        if (claim != null && claim.isStringValueType()) {
            Date date = DSSUtils.parseISO8601Date(claim.getStringValue());
            if (date != null) {
                return new VerifiedClaimDate(claim.getName(), claim.getNamespace(), date, claim.isSelectivelyDisclosable(), claim.getParent());
            }
        }
        return null;
    }

    /**
     * Checks if the {@code claim} is of date-time type and returns its value as {@code ClaimDate}
     *
     * @param headerName {@link String} to get header value from the payload
     * @return {@link VerifiedClaimDate}
     */
    protected VerifiedClaimDate getAsDateTime(String headerName) {
        VerifiedClaim claim = get(headerName);
        return getAsDateTime(claim);
    }

    /**
     * Checks if the {@code claim} is of date type and returns its value as {@code ClaimDate}
     *
     * @param claim {@link VerifiedClaim}
     * @return {@link VerifiedClaimDate}
     */
    protected VerifiedClaimDate getAsDateTime(VerifiedClaim claim) {
        if (claim == null) {
            return null;
        }
        if (claim.isStringValueType()) {
            Date date = DSSUtils.parseRFCDate(claim.getStringValue());
            if (date != null) {
                return new VerifiedClaimDate(claim.getName(), date, claim.isSelectivelyDisclosable());
            }
        } else if (claim.isNumberValueType()) {
            long timeValueInMilliseconds = DSSUtils.getTimeValueInMilliseconds(claim.getNumberValue().longValue());
            Date date = DSSUtils.getDateFromMilliseconds(timeValueInMilliseconds);
            return new VerifiedClaimDate(claim.getName(), claim.getNamespace(), date, claim.isSelectivelyDisclosable(), claim.getParent());
        }
        return null;
    }
    /**
     * Checks if the {@code claim} is of date or date-time type and returns its value as {@code ClaimDate}
     *
     * @param headerName {@link String} to get header value from the payload
     * @return {@link VerifiedClaimDate}
     */
    protected VerifiedClaimDate getAsDateOrDateTime(String headerName) {
        VerifiedClaim claim = get(headerName);
        return getAsDateOrDateTime(claim);
    }

    /**
     * Checks if the {@code claim} is of date or date-time type and returns its value as {@code ClaimDate}
     *
     * @param claim {@link VerifiedClaim}
     * @return {@link VerifiedClaimDate}
     */
    protected VerifiedClaimDate getAsDateOrDateTime(VerifiedClaim claim) {
        if (claim == null) {
            return null;
        }
        if (claim.isStringValueType()) {
            String dateTimeString = claim.getStringValue();
            Date date;
            if (DSSUtils.isRFCDate(dateTimeString)) {
                date = DSSUtils.parseRFCDate(dateTimeString);
            } else if (DSSUtils.isISO8601Date(dateTimeString)) {
                date = DSSUtils.parseISO8601Date(dateTimeString);
            } else {
                LOG.warn("Date or full datetime is expected for the claim with name '{}'!", claim.getName());
                return null;
            }
            if (date != null) {
                return new VerifiedClaimDate(claim.getName(), claim.getNamespace(), date, claim.isSelectivelyDisclosable(), claim.getParent());
            }

        } else if (claim.isNumberValueType()) {
            long timeValueInMilliseconds = DSSUtils.getTimeValueInMilliseconds(claim.getNumberValue().longValue());
            Date date = DSSUtils.getDateFromMilliseconds(timeValueInMilliseconds);
            return new VerifiedClaimDate(claim.getName(), claim.getNamespace(), date, claim.isSelectivelyDisclosable(), claim.getParent());
        }
        return null;
    }

    /**
     * Checks if the claim for the {@code headerName} is of byte string type and returns its value as {@code ClaimByteString}
     *
     * @param headerName {@link String} to get header value from the map
     * @return {@link VerifiedClaimDate}
     */
    public VerifiedClaimByteString getAsByteString(String headerName) {
        VerifiedClaim claim = get(headerName);
        return getAsByteString(claim);
    }

    /**
     * Checks if the claim for the {@code headerName} is of byte string type and returns its value as {@code ClaimByteString}
     *
     * @param headerLabel {@link Number} to get header value from the map
     * @return {@link VerifiedClaimDate}
     */
    public VerifiedClaimByteString getAsByteString(Number headerLabel) {
        return getAsByteString(getKeyAsString(headerLabel));
    }

    /**
     * Checks if the {@code claim} is of byte string type and returns its value as {@code ClaimByteString}
     *
     * @param claim {@link VerifiedClaim}
     * @return {@link VerifiedClaimByteString}
     */
    public VerifiedClaimByteString getAsByteString(VerifiedClaim claim) {
        if (claim != null && claim.isBinaryValueType()) {
            return (VerifiedClaimByteString) claim;
        }
        return null;
    }

    @Override
    protected String getKeyAsString(Object key) {
        if (key instanceof String) {
            return (String) key;
        }
        // CBOR allows any type of map keys
        return MdocUtils.createClaim(key).getValueAsString();
    }

    @Override
    protected VerifiedClaim createClaim(String name, Object value) {
        return MdocUtils.createClaim(name, this, value);
    }

}
