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
package eu.europa.esig.dss.attestation.mdoc;

import eu.europa.esig.dss.attestation.mdoc.claim.MdocVerifiedClaimArray;
import eu.europa.esig.dss.attestation.mdoc.claim.MdocVerifiedClaimMap;
import eu.europa.esig.dss.cbades.cbor.CBORObject;
import eu.europa.esig.dss.model.attestation.claim.VerifiedClaim;
import eu.europa.esig.dss.model.attestation.claim.VerifiedClaimArray;
import eu.europa.esig.dss.model.attestation.claim.VerifiedClaimBoolean;
import eu.europa.esig.dss.model.attestation.claim.VerifiedClaimByteString;
import eu.europa.esig.dss.model.attestation.claim.VerifiedClaimDate;
import eu.europa.esig.dss.model.attestation.claim.VerifiedClaimMap;
import eu.europa.esig.dss.model.attestation.claim.VerifiedClaimNull;
import eu.europa.esig.dss.model.attestation.claim.VerifiedClaimNumber;
import eu.europa.esig.dss.model.attestation.claim.VerifiedClaimString;

import java.util.Date;
import java.util.List;
import java.util.Map;

/**
 * Contains common utility methods for processing mdoc documents
 *
 */
public final class MdocUtils {

    /**
     * Default constructor
     */
    private MdocUtils() {
        // singleton
    }

    /**
     * This method parses the {@code value} and wraps it into a {@code ClaimValue} according to its format.
     * This method can be used for non selectively disclosable claims, provided directly within attestation Payload.
     *
     * @param value {@link Object} containing the value of the object
     * @return {@link VerifiedClaim}
     */
    public static VerifiedClaim createClaim(Object value) {
        return createClaim(null, null, value);
    }

    /**
     * This method parses the {@code value} and wraps it into a {@code ClaimValue} according to its format.
     * This method allows providing of the claim parent, to be used within the claim's metadata.
     * When a value is of Claim type, the existing selectively discussable tag value is used,
     * otherwise it is set to false.
     *
     * @param claimName {@link String} representing the header name of the claim
     * @param parent {@link VerifiedClaim} parent of the claim
     * @param value {@link Object} containing the value of the object
     * @return {@link VerifiedClaim}
     */
    public static VerifiedClaim createClaim(String claimName, VerifiedClaim parent, Object value) {
        boolean selectivelyDisclosable = false;
        if (value instanceof VerifiedClaim) {
            selectivelyDisclosable = ((VerifiedClaim) value).isSelectivelyDisclosable();
        }
        return createClaim(claimName, parent, value, selectivelyDisclosable);
    }

    /**
     * This method parses the {@code value} and wraps it into a {@code ClaimValue} according to its format.
     * This method can be used for definition of claims used within provided disclosures.
     * This method allows providing of the claim parent, to be used within the claim's metadata.
     *
     * @param claimName {@link String} representing the header name of the claim
     * @param parent {@link VerifiedClaim} parent of the claim
     * @param value {@link Object} containing the value of the object
     * @param selectivelyDisclosable whether the claim is selectively disclosable
     *                               (can be TRUE only when the value of claim is provided in a form of disclosure)
     * @return {@link VerifiedClaim}
     */
    public static VerifiedClaim createClaim(String claimName, VerifiedClaim parent, Object value, boolean selectivelyDisclosable) {
        String namespace = null;
        if (value instanceof VerifiedClaim) {
            namespace = ((VerifiedClaim) value).getNamespace();
        }
        return createClaim(claimName, parent, value, selectivelyDisclosable, namespace);
    }

    /**
     * This method parses the {@code value} and wraps it into a {@code ClaimValue} according to its format.
     * This method can be used for definition of claims used within provided disclosures.
     * This method allows providing of the claim parent, to be used within the claim's metadata.
     * This method allows providing of the claim's namespace.
     *
     * @param claimName {@link String} representing the header name of the claim
     * @param parent {@link VerifiedClaim} parent of the claim
     * @param value {@link Object} containing the value of the object
     * @param selectivelyDisclosable whether the claim is selectively disclosable
     *                               (can be TRUE only when the value of claim is provided in a form of disclosure)
     * @param namespace {@link String} representing the original namespace
     * @return {@link VerifiedClaim}
     */
    public static VerifiedClaim createClaim(String claimName, VerifiedClaim parent, Object value, boolean selectivelyDisclosable, String namespace) {
        if (value instanceof VerifiedClaimString) {
            return new VerifiedClaimString(claimName, namespace, ((VerifiedClaimString) value).getStringValue(), selectivelyDisclosable, parent);

        } else if (value instanceof VerifiedClaimNumber) {
            return new VerifiedClaimNumber(claimName, namespace, ((VerifiedClaimNumber) value).getNumberValue(), selectivelyDisclosable, parent);

        } else if (value instanceof VerifiedClaimBoolean) {
            return new VerifiedClaimBoolean(claimName, namespace, ((VerifiedClaimBoolean) value).getBooleanValue(), selectivelyDisclosable, parent);

        } else if (value instanceof VerifiedClaimByteString) {
            return new VerifiedClaimByteString(claimName, namespace, ((VerifiedClaimByteString) value).getBinaryValue(), selectivelyDisclosable, parent);

        } else if (value instanceof VerifiedClaimDate) {
            return new VerifiedClaimDate(claimName, namespace, ((VerifiedClaimDate) value).getDateValue(), selectivelyDisclosable, parent);

        } else if (value instanceof VerifiedClaimMap) {
            return new MdocVerifiedClaimMap(claimName, namespace, ((VerifiedClaimMap) value).getMapValue(), selectivelyDisclosable, parent);

        } else if (value instanceof VerifiedClaimArray) {
            return new MdocVerifiedClaimArray(claimName, namespace, ((VerifiedClaimArray) value).getListValue(), selectivelyDisclosable, parent);

        } else if (value instanceof VerifiedClaimNull) {
            return new VerifiedClaimNull(claimName, namespace, selectivelyDisclosable, parent);

        } else if (value instanceof CBORObject) {
            CBORObject cborObject = (CBORObject) value;
            if (cborObject.isArray()) {
                return new MdocVerifiedClaimArray(claimName, namespace, cborObject.getValueAsList(), selectivelyDisclosable, parent);
            } else if (cborObject.isBoolean()) {
                return new VerifiedClaimBoolean(claimName, namespace, cborObject.getValueAsBoolean(), selectivelyDisclosable, parent);
            } else if (cborObject.isByteString()) {
                return new VerifiedClaimByteString(claimName, namespace, cborObject.getValueAsBytes(), selectivelyDisclosable, parent);
            } else if (cborObject.isFloatingPointNumber()) {
                return new VerifiedClaimNumber(claimName, namespace, cborObject.getValueAsDouble(), selectivelyDisclosable, parent);
            } else if (cborObject.isNegativeInteger() || cborObject.isUnsignedInteger()) {
                return new VerifiedClaimNumber(claimName, namespace, cborObject.getValueAsLong(), selectivelyDisclosable, parent);
            } else if (cborObject.isMap()) {
                return new MdocVerifiedClaimMap(claimName, namespace, cborObject.getValueAsMap(), selectivelyDisclosable, parent);
            } else if (cborObject.isNull()) {
                return new VerifiedClaimNull(claimName, namespace, selectivelyDisclosable, parent);
            } else if (cborObject.isUnicodeString()) {
                return new VerifiedClaimString(claimName, namespace, cborObject.getValueAsString(), selectivelyDisclosable, parent);
            }
            throw new IllegalArgumentException(String.format("The claim value of type '%s' is not supported!", value.getClass().getSimpleName()));

        } else if (value instanceof String) {
            return new VerifiedClaimString(claimName, namespace, (String) value, selectivelyDisclosable, parent);

        } else if (value instanceof Number) {
            return new VerifiedClaimNumber(claimName, namespace, (Number) value, selectivelyDisclosable, parent);

        } else if (value instanceof Boolean) {
            return new VerifiedClaimBoolean(claimName, namespace, (Boolean) value, selectivelyDisclosable, parent);

        } else if (value instanceof Date) {
            return new VerifiedClaimDate(claimName, namespace, (Date) value, selectivelyDisclosable, parent);

        } else if (value instanceof Map) {
            return new MdocVerifiedClaimMap(claimName, namespace, (Map<?,?>) value, selectivelyDisclosable, parent);

        } else if (value instanceof List) {
            return new MdocVerifiedClaimArray(claimName, namespace, (List<?>) value, selectivelyDisclosable, parent);

        } else if (value == null) {
            return new VerifiedClaimNull(claimName, namespace, selectivelyDisclosable, parent);

        } else {
            throw new IllegalArgumentException(String.format("The claim value of type '%s' is not supported!", value.getClass().getSimpleName()));
        }
    }

}
