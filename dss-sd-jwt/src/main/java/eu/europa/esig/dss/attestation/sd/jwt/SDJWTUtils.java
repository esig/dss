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
package eu.europa.esig.dss.attestation.sd.jwt;

import eu.europa.esig.dss.attestation.sd.jwt.claim.SDJWTClaimArray;
import eu.europa.esig.dss.attestation.sd.jwt.claim.SDJWTClaimMap;
import eu.europa.esig.dss.model.attestation.claim.Claim;
import eu.europa.esig.dss.model.attestation.claim.ClaimArray;
import eu.europa.esig.dss.model.attestation.claim.ClaimBoolean;
import eu.europa.esig.dss.model.attestation.claim.ClaimDate;
import eu.europa.esig.dss.model.attestation.claim.ClaimMap;
import eu.europa.esig.dss.model.attestation.claim.ClaimNull;
import eu.europa.esig.dss.model.attestation.claim.ClaimNumber;
import eu.europa.esig.dss.model.attestation.claim.ClaimString;

import java.util.Date;
import java.util.List;
import java.util.Map;

/**
 * This class contains utility methods for processing SD-JWT tokens
 *
 */
public final class SDJWTUtils {

    /**
     * Singleton
     */
    private SDJWTUtils() {
        // empty
    }

    /**
     * This method parses the {@code value} and wraps it into a {@code ClaimValue} according to its format.
     * This method can be used for non selectively disclosable claims, provided directly within EAA Payload.
     *
     * @param value {@link Object} containing the value of the object
     * @return {@link Claim}
     */
    public static Claim createClaim(Object value) {
        return createClaim(null, null, value);
    }

    /**
     * This method parses the {@code value} and wraps it into a {@code ClaimValue} according to its format.
     * This method allows providing of the claim parent, to be used within the claim's metadata.
     * When a value is of Claim type, the existing selectively discussable tag value is used,
     * otherwise it is set to false.
     *
     * @param claimName {@link String} representing the header name of the claim
     * @param parent {@link Claim} parent of the claim
     * @param value {@link Object} containing the value of the object
     * @return {@link Claim}
     */
    public static Claim createClaim(String claimName, Claim parent, Object value) {
        boolean selectivelyDisclosable = false;
        if (value instanceof Claim) {
            selectivelyDisclosable = ((Claim) value).isSelectivelyDisclosable();
        }
        return createClaim(claimName, parent, value, selectivelyDisclosable);
    }

    /**
     * This method parses the {@code value} and wraps it into a {@code ClaimValue} according to its format.
     * This method can be used for definition of claims used within provided disclosures.
     * This method allows providing of the claim parent, to be used within the claim's metadata.
     *
     * @param claimName {@link String} representing the header name of the claim
     * @param parent {@link Claim} parent of the claim
     * @param value {@link Object} containing the value of the object
     * @param selectivelyDisclosable whether the claim is selectively disclosable
     *                               (can be TRUE only when the value of claim is provided in a form of disclosure)
     * @return {@link Claim}
     */
    public static Claim createClaim(String claimName, Claim parent, Object value, boolean selectivelyDisclosable) {
        if (value instanceof ClaimString) {
            return new ClaimString(claimName, ((ClaimString) value).getStringValue(), selectivelyDisclosable, parent);
        } else if (value instanceof ClaimNumber) {
            return new ClaimNumber(claimName, ((ClaimNumber) value).getNumberValue(), selectivelyDisclosable, parent);
        } else if (value instanceof ClaimBoolean) {
            return new ClaimBoolean(claimName, ((ClaimBoolean) value).getBooleanValue(), selectivelyDisclosable, parent);
        } else if (value instanceof ClaimDate) {
            return new ClaimDate(claimName, ((ClaimDate) value).getDateValue(), selectivelyDisclosable, parent);
        } else if (value instanceof ClaimNull) {
            return new ClaimNull(claimName, selectivelyDisclosable, parent);
        } else if (value instanceof ClaimMap) {
            return new SDJWTClaimMap(claimName, ((ClaimMap) value).getMapValue(), selectivelyDisclosable, parent);
        } else if (value instanceof ClaimArray) {
            return new SDJWTClaimArray(claimName, ((ClaimArray) value).getListValue(), selectivelyDisclosable, parent);
        } else if (value instanceof String) {
            return new ClaimString(claimName, (String) value, selectivelyDisclosable, parent);
        } else if (value instanceof Number) {
            return new ClaimNumber(claimName, (Number) value, selectivelyDisclosable, parent);
        } else if (value instanceof Boolean) {
            return new ClaimBoolean(claimName, (Boolean) value, selectivelyDisclosable, parent);
        } else if (value instanceof Date) {
            return new ClaimDate(claimName, (Date) value, selectivelyDisclosable, parent);
        } else if (value instanceof Map) {
            return new SDJWTClaimMap(claimName, (Map<?,?>) value, selectivelyDisclosable, parent);
        } else if (value instanceof List) {
            return new SDJWTClaimArray(claimName, (List<?>) value, selectivelyDisclosable, parent);
        } else if (value == null) {
            return new ClaimNull(claimName, selectivelyDisclosable, parent);
        } else {
            throw new IllegalArgumentException(String.format("The claim value of type '%s' is not supported!", value.getClass().getSimpleName()));
        }
    }

}
