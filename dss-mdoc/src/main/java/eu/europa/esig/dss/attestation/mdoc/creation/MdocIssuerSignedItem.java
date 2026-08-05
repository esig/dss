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
package eu.europa.esig.dss.attestation.mdoc.creation;

import eu.europa.esig.dss.attestation.common.creation.AbstractSelectiveDisclosure;
import eu.europa.esig.dss.attestation.mdoc.MdocHeaderParameter;
import eu.europa.esig.dss.cbades.cbor.CBORByteString;
import eu.europa.esig.dss.cbades.cbor.CBORMap;
import eu.europa.esig.dss.cbades.cbor.CBORObject;
import eu.europa.esig.dss.cbades.cbor.CBORUtils;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.exception.IllegalInputException;

import java.util.Objects;

/**
 * Implementation of a disclosure for an ISO/IEC 18013-5 token
 *
 */
public class MdocIssuerSignedItem extends AbstractSelectiveDisclosure {

    private static final long serialVersionUID = 4647204332079766021L;

    /** Namespace of the disclosure */
    private final String namespace;

    /** Represents serialized  */
    private final CBORByteString issuerSignedItemBytes;

    /** DigestId of the disclosure */
    private Long digestId;

    /**
     * Constructor to instantiate the mdoc disclosure from an IssuerSignedItemBytes object with defined namespace
     *
     * @param namespace {@link String} namespace of the element claim
     * @param issuerSignedItemBytes {@link CBORByteString} IssuerSignedItemBytes object
     */
    public MdocIssuerSignedItem(final String namespace, final CBORByteString issuerSignedItemBytes) {
        Objects.requireNonNull(namespace, "Namespace cannot be null!");
        Objects.requireNonNull(issuerSignedItemBytes, "IssuerSignedItemBytes cannot be null!");
        this.namespace = namespace;
        this.issuerSignedItemBytes = issuerSignedItemBytes;
    }

    /**
     * Constructor to instantiate the mdoc disclosure from a serialized IssuerSignedItemBytes object with defined namespace
     *
     * @param namespace {@link String} namespace of the element claim
     * @param issuerSignedItemBytes serialized IssuerSignedItemBytes bytes
     */
    public MdocIssuerSignedItem(final String namespace, final byte[] issuerSignedItemBytes) {
        Objects.requireNonNull(namespace, "Namespace cannot be null!");
        Objects.requireNonNull(issuerSignedItemBytes, "IssuerSignedItemBytes cannot be null!");
        this.namespace = namespace;
        this.issuerSignedItemBytes = parse(issuerSignedItemBytes);
    }

    /**
     * Constructor to instantiate a void
     *
     * @param digestId unique integer identifying the element within the attestation namespace
     * @param issuerSignedItemBytes {@link CBORByteString} IssuerSignedItemBytes object
     */
    protected MdocIssuerSignedItem(final int digestId, final CBORByteString issuerSignedItemBytes) {
        Objects.requireNonNull(issuerSignedItemBytes, "IssuerSignedItemBytes cannot be null!");
        this.namespace = null;
        this.digestId = (long) digestId;
        this.issuerSignedItemBytes = issuerSignedItemBytes;
    }

    /**
     * Constructor to instantiate the mdoc disclosure from a serialized IssuerSignedItemBytes object
     *
     * @param namespace {@link String} namespace of the element claim
     * @param digestId unique integer identifying the element within the attestation namespace
     * @param issuerSignedItemBytes serialized IssuerSignedItemBytes bytes
     */
    public MdocIssuerSignedItem(final String namespace, final int digestId, final byte[] issuerSignedItemBytes) {
        Objects.requireNonNull(namespace, "Namespace cannot be null!");
        Objects.requireNonNull(issuerSignedItemBytes, "IssuerSignedItemBytes cannot be null!");
        this.namespace = namespace;
        this.digestId = (long) digestId;
        this.issuerSignedItemBytes = parse(issuerSignedItemBytes);
    }

    private static CBORByteString parse(byte[] issuerSignedItemBytes) {
        CBORObject cborObject;
        try {
            cborObject = CBORUtils.parseCbor(issuerSignedItemBytes);
        } catch (Exception e) {
            throw new IllegalInputException(String.format("The issuerSignedItemBytes shall be CBOR encoded : %s", e.getMessage()), e);
        }
        if (!cborObject.isByteString()) {
            throw new IllegalInputException("The issuerSignedItemBytes shall be CBOR Byte String encoded!");
        }
        return (CBORByteString) cborObject;
    }

    /**
     * Constructor to instantiate the mdoc disclosure from a IssuerSignedItemBytes object
     *
     * @param namespace {@link String} namespace of the element claim
     * @param digestId unique integer identifying the element within the attestation namespace
     * @param issuerSignedItemBytes {@link CBORByteString} IssuerSignedItemBytes object
     */
    public MdocIssuerSignedItem(final String namespace, final int digestId, final CBORByteString issuerSignedItemBytes) {
        Objects.requireNonNull(namespace, "Namespace cannot be null!");
        Objects.requireNonNull(issuerSignedItemBytes, "IssuerSignedItemBytes cannot be null!");
        this.namespace = namespace;
        this.digestId = (long) digestId;
        this.issuerSignedItemBytes = issuerSignedItemBytes;
    }

    /**
     * Gets the element namespace
     *
     * @return {@link String}
     */
    public String getNamespace() {
        return namespace;
    }

    /**
     * Gets the disclosure digestId
     *
     * @return {@link Long}
     */
    public Long getDigestId() {
        if (digestId == null) {
            parse();
        }
        return digestId;
    }

    /**
     * Gets the IssuerSignedItemBytes
     *
     * @return {@link CBORByteString} IssuerSignedItemBytes
     */
    public CBORByteString getIssuerSignedItemBytes() {
        return issuerSignedItemBytes;
    }

    @Override
    protected Digest computeDigest(DigestAlgorithm digestAlgorithm) {
        byte[] serialized = CBORUtils.serializeCborObject(issuerSignedItemBytes);
        byte[] digestValue = DSSUtils.digest(digestAlgorithm, serialized);
        return new Digest(digestAlgorithm, digestValue);
    }

    @Override
    protected void parse() {
        parseSignedItem(issuerSignedItemBytes);
    }

    private void parseSignedItem(CBORByteString issuerSignedItemBytes) {
        CBORMap issuerSignedItemMap = new CBORMap(issuerSignedItemBytes);
        this.digestId = getDigestId(issuerSignedItemMap);
        this.salt = getRandom(issuerSignedItemMap);
        this.name = getElementIdentifier(issuerSignedItemMap);
        this.value = getElementValue(issuerSignedItemMap);
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
    public boolean equals(Object object) {
        if (this == object) return true;
        if (object == null || getClass() != object.getClass()) return false;

        MdocIssuerSignedItem that = (MdocIssuerSignedItem) object;
        return namespace.equals(that.namespace)
                && Objects.equals(issuerSignedItemBytes, that.issuerSignedItemBytes);
    }

    @Override
    public int hashCode() {
        int result = namespace.hashCode();
        result = 31 * result + Objects.hashCode(issuerSignedItemBytes);
        return result;
    }

}
