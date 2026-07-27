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
package eu.europa.esig.dss.attestation.mdoc.model;

import eu.europa.esig.dss.cbades.cbor.CBORByteString;
import eu.europa.esig.dss.cbades.cbor.CBORMap;
import eu.europa.esig.dss.cbades.cbor.CBORObject;
import eu.europa.esig.dss.cbades.cbor.CBORUtils;
import eu.europa.esig.dss.attestation.mdoc.MdocHeaderParameter;
import eu.europa.esig.dss.attestation.mdoc.MdocUtils;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.attestation.SelectivelyDisclosableClaim;
import eu.europa.esig.dss.model.attestation.claim.VerifiedClaim;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.exception.IllegalInputException;

/**
 * Represents an mDoc signed item, as specified in ISO 18013-5 "8.3.2.1.2.2 Device retrieval mdoc response".
 * {@code
 *      IssuerSignedItem = {
 *          "digestID" : uint, ; Digest ID for issuer data authentication
 *          "random" : bstr, ; Random value for issuer data authentication
 *          "elementIdentifier" : DataElementIdentifier, ; Data element identifier
 *          "elementValue" : DataElementValue ; Data element value
 *      }
 * }
 */
public class MdocIssuerSignedItem extends SelectivelyDisclosableClaim {

    private static final long serialVersionUID = -1844558182130817388L;

    /** Namespace */
    private final String namespace;

    /** The original signed item bytes */
    private final CBORByteString issuerSignedItemBytes;

    /** Digest ID for issuer data authentication */
    private Long digestId;

    /**
     * Default constructor
     *
     * @param namespace {@link String}
     * @param issuerSignedItemBytes {@link CBORMap}
     */
    public MdocIssuerSignedItem(final String namespace, final CBORByteString issuerSignedItemBytes) {
        this.namespace = namespace;
        this.issuerSignedItemBytes = issuerSignedItemBytes;
        parseSignedItem(issuerSignedItemBytes);
    }

    private void parseSignedItem(CBORByteString issuerSignedItemBytes) {
        CBORMap issuerSignedItemMap = new CBORMap(issuerSignedItemBytes);
        this.digestId = getDigestId(issuerSignedItemMap);
        this.salt = getRandom(issuerSignedItemMap);
        this.claim = getClaim(issuerSignedItemMap);
    }

    private Long getDigestId(CBORMap issuerSignedItemMap) {
        CBORObject digestIDHeader = issuerSignedItemMap.getHeader(MdocHeaderParameter.DIGEST_ID.cbor());
        if (digestIDHeader == null) {
            throw new IllegalInputException(String.format(
                    "'%s' header parameter shall be present within IssuerSignedItem!", MdocHeaderParameter.DIGEST_ID));
        }
        if (!digestIDHeader.isUnsignedInteger()) {
            throw new IllegalInputException(String.format(
                    "'%s' header parameter shall be of unsigned integer type!", MdocHeaderParameter.DIGEST_ID));
        }
        return digestIDHeader.getValueAsLong();
    }

    private byte[] getRandom(CBORMap issuerSignedItemMap) {
        CBORObject randomHeader = issuerSignedItemMap.getHeader(MdocHeaderParameter.RANDOM.cbor());
        if (randomHeader == null) {
            throw new IllegalInputException(String.format(
                    "'%s' header parameter shall be present within IssuerSignedItem!", MdocHeaderParameter.RANDOM));
        }
        if (!randomHeader.isByteString()) {
            throw new IllegalInputException(String.format(
                    "'%s' header parameter shall be of byte string type!", MdocHeaderParameter.RANDOM));
        }
        return randomHeader.getValueAsBytes();
    }

    private VerifiedClaim getClaim(CBORMap issuerSignedItemMap) {
        String elementIdentifier = getElementIdentifier(issuerSignedItemMap);
        CBORObject elementValue = getElementValue(issuerSignedItemMap);
        return MdocUtils.createClaim(elementIdentifier, null, elementValue, true, namespace);
    }

    private String getElementIdentifier(CBORMap issuerSignedItemMap) {
        CBORObject elementIdentifierHeader = issuerSignedItemMap.getHeader(MdocHeaderParameter.ELEMENT_IDENTIFIER.cbor());
        if (elementIdentifierHeader == null) {
            throw new IllegalInputException(String.format(
                    "'%s' header parameter shall be present within IssuerSignedItem!", MdocHeaderParameter.ELEMENT_IDENTIFIER));
        }
        if (!elementIdentifierHeader.isUnicodeString()) {
            throw new IllegalInputException(String.format(
                    "'%s' header parameter shall be of unicode string type!", MdocHeaderParameter.ELEMENT_IDENTIFIER));
        }
        return elementIdentifierHeader.getValueAsString();
    }

    private CBORObject getElementValue(CBORMap issuerSignedItemMap) {
        CBORObject elementValue = issuerSignedItemMap.getHeader(MdocHeaderParameter.ELEMENT_VALUE.cbor());
        if (elementValue == null) {
            throw new IllegalInputException(String.format(
                    "'%s' header parameter shall be present within IssuerSignedItem!", MdocHeaderParameter.ELEMENT_VALUE));
        }
        return elementValue;
    }

    @Override
    public String getNamespace() {
        return namespace;
    }

    @Override
    public Long getDigestId() {
        return digestId;
    }

    @Override
    protected Digest computeDigest(DigestAlgorithm digestAlgorithm) {
        byte[] signedItemBytes = CBORUtils.serializeCborObject(issuerSignedItemBytes);
        byte[] digestValue = DSSUtils.digest(digestAlgorithm, signedItemBytes);
        return new Digest(digestAlgorithm, digestValue);
    }

}
