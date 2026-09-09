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

import eu.europa.ec.digit.cddl4j.cbor.CBORValue;
import eu.europa.esig.dss.attestation.mdoc.claim.MdocVerifiedClaimArray;
import eu.europa.esig.dss.attestation.mdoc.claim.MdocVerifiedClaimMap;
import eu.europa.esig.dss.attestation.mdoc.creation.MdocIssuerSignedItem;
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
import eu.europa.esig.dss.utils.Utils;

import java.util.ArrayList;
import java.util.Collections;
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
            // TODO : remove after DSS 6.6
            return createClaim(claimName, parent, ((CBORObject) value).toCBORValue(), selectivelyDisclosable, namespace);

        } else if (value instanceof CBORValue) {
            CBORValue cborValue = (CBORValue) value;
            if (cborValue.isArray()) {
                return new MdocVerifiedClaimArray(claimName, namespace, cborValue.getElements(), selectivelyDisclosable, parent);
            } else if (cborValue.isBoolean()) {
                return new VerifiedClaimBoolean(claimName, namespace, cborValue.asBoolean(), selectivelyDisclosable, parent);
            } else if (cborValue.isByteString()) {
                return new VerifiedClaimByteString(claimName, namespace, cborValue.asBytes(), selectivelyDisclosable, parent);
            } else if (cborValue.isFloatingPoint()) {
                return new VerifiedClaimNumber(claimName, namespace, cborValue.asDouble(), selectivelyDisclosable, parent);
            } else if (cborValue.isNegativeInteger() || cborValue.isUnsignedInteger()) {
                return new VerifiedClaimNumber(claimName, namespace, cborValue.asInteger(), selectivelyDisclosable, parent);
            } else if (cborValue.isMap()) {
                return new MdocVerifiedClaimMap(claimName, namespace, cborValue.getEntries(), selectivelyDisclosable, parent);
            } else if (cborValue.isNull()) {
                return new VerifiedClaimNull(claimName, namespace, selectivelyDisclosable, parent);
            } else if (cborValue.isTextString()) {
                return new VerifiedClaimString(claimName, namespace, cborValue.asString(), selectivelyDisclosable, parent);
            } else if (cborValue.isTag()) {
                return createClaim(claimName, parent, cborValue.getTaggedValue(), selectivelyDisclosable, namespace);
            }
            throw new IllegalArgumentException(String.format("The CBORValue of type '%s' is not supported!", cborValue.getType()));

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

    /**
     * Returns a list of disclosures extracted for every namespace from a Document structure
     *
     * @param namespaces a map of {@link String} namespaces and {@link MdocIssuerSignedItem}s
     * @return a list of {@link MdocIssuerSignedItem}s
     */
    public static List<MdocIssuerSignedItem> getSelectiveDisclosures(Map<String, List<MdocIssuerSignedItem>> namespaces) {
        if (Utils.isMapEmpty(namespaces)) {
            return Collections.emptyList();
        }
        final List<MdocIssuerSignedItem> result = new ArrayList<>();
        for (List<MdocIssuerSignedItem> signedItems : namespaces.values()) {
            result.addAll(signedItems);
        }
        return result;
    }

}
