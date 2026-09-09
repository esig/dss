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

import eu.europa.ec.digit.cddl4j.cbor.CBORTags;
import eu.europa.ec.digit.cddl4j.cbor.CBORValue;
import eu.europa.esig.dss.attestation.common.creation.AbstractSelectiveDisclosure;
import eu.europa.esig.dss.attestation.mdoc.MdocHeaderParameter;
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
    private final CBORValue issuerSignedItemBytes;

    /** DigestId of the disclosure */
    private Long digestId;

    /**
     * Constructor to instantiate the mdoc disclosure from an IssuerSignedItemBytes object with defined namespace
     *
     * @param namespace {@link String} namespace of the element claim
     * @param issuerSignedItemBytes {@link CBORValue} IssuerSignedItemBytes object
     */
    public MdocIssuerSignedItem(final String namespace, final CBORValue issuerSignedItemBytes) {
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
     * @param issuerSignedItemBytes {@link CBORValue} IssuerSignedItemBytes object
     */
    protected MdocIssuerSignedItem(final int digestId, final CBORValue issuerSignedItemBytes) {
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

    private static CBORValue parse(byte[] issuerSignedItemBytes) {
        CBORValue cborValue;
        try {
            cborValue = CBORUtils.parseCbor(issuerSignedItemBytes);
        } catch (Exception e) {
            throw new IllegalInputException(String.format("The issuerSignedItemBytes shall be CBOR encoded : %s", e.getMessage()), e);
        }
        if (!cborValue.isTag() || CBORTags.ENCODED_CBOR != cborValue.getTag().longValue() || !cborValue.getTaggedValue().isByteString()) {
            throw new IllegalInputException(String.format(
                    "IssuerSignedItemBytes shall be of a tagged CBOR Byte String type with tag value #6.24! Found type : %s", cborValue.getType()));
        }
        return cborValue;
    }

    /**
     * Constructor to instantiate the mdoc disclosure from a IssuerSignedItemBytes object
     *
     * @param namespace {@link String} namespace of the element claim
     * @param digestId unique integer identifying the element within the attestation namespace
     * @param issuerSignedItemBytes {@link CBORValue} IssuerSignedItemBytes object
     */
    public MdocIssuerSignedItem(final String namespace, final int digestId, final CBORValue issuerSignedItemBytes) {
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
     * @return {@link CBORValue} IssuerSignedItemBytes
     */
    public CBORValue getIssuerSignedItemBytes() {
        return issuerSignedItemBytes;
    }

    @Override
    protected Digest computeDigest(DigestAlgorithm digestAlgorithm) {
        byte[] serialized = CBORUtils.serializeCbor(issuerSignedItemBytes);
        byte[] digestValue = DSSUtils.digest(digestAlgorithm, serialized);
        return new Digest(digestAlgorithm, digestValue);
    }

    @Override
    protected void parse() {
        parseSignedItem(issuerSignedItemBytes);
    }

    private void parseSignedItem(CBORValue issuerSignedItemBytes) {
        if (!issuerSignedItemBytes.isTag() || CBORTags.ENCODED_CBOR != issuerSignedItemBytes.getTag().longValue()) {
            throw new IllegalInputException(String.format(
                    "IssuerSignedItemBytes shall be of a tagged CBOR Byte String type with tag value #6.24! Found type : %s", issuerSignedItemBytes.getType()));
        }
        issuerSignedItemBytes = issuerSignedItemBytes.getTaggedValue();
        if (!issuerSignedItemBytes.isByteString()) {
            throw new IllegalInputException(String.format(
                    "IssuerSignedItemBytes shall wrap a CBOR Byte String type! Found type : %s", issuerSignedItemBytes.getType()));
        }
        CBORValue issuerSignedItem = CBORUtils.parseCbor(issuerSignedItemBytes.asBytes());
        if (!issuerSignedItem.isMap()) {
            throw new IllegalInputException(String.format(
                    "IssuerSignedItem shall by of a CBOR Map type! Found type : %s", issuerSignedItem.getType()));
        }
        this.digestId = getDigestId(issuerSignedItem);
        this.salt = getRandom(issuerSignedItem);
        this.name = getElementIdentifier(issuerSignedItem);
        this.value = getElementValue(issuerSignedItem);
    }

    private Long getDigestId(CBORValue issuerSignedItemMap) {
        CBORValue digestIDHeader = issuerSignedItemMap.get(MdocHeaderParameter.DIGEST_ID.cbor());
        if (digestIDHeader == null) {
            throw new IllegalInputException(String.format(
                    "'%s' header parameter shall be present within IssuerSignedItem!", MdocHeaderParameter.DIGEST_ID));
        }
        if (!digestIDHeader.isUnsignedInteger()) {
            throw new IllegalInputException(String.format(
                    "'%s' header parameter shall be of unsigned integer type!", MdocHeaderParameter.DIGEST_ID));
        }
        return digestIDHeader.asInteger().longValue();
    }

    private byte[] getRandom(CBORValue issuerSignedItemMap) {
        CBORValue randomHeader = issuerSignedItemMap.get(MdocHeaderParameter.RANDOM.cbor());
        if (randomHeader == null) {
            throw new IllegalInputException(String.format(
                    "'%s' header parameter shall be present within IssuerSignedItem!", MdocHeaderParameter.RANDOM));
        }
        if (!randomHeader.isByteString()) {
            throw new IllegalInputException(String.format(
                    "'%s' header parameter shall be of byte string type!", MdocHeaderParameter.RANDOM));
        }
        return randomHeader.asBytes();
    }

    private String getElementIdentifier(CBORValue issuerSignedItemMap) {
        CBORValue elementIdentifierHeader = issuerSignedItemMap.get(MdocHeaderParameter.ELEMENT_IDENTIFIER.cbor());
        if (elementIdentifierHeader == null) {
            throw new IllegalInputException(String.format(
                    "'%s' header parameter shall be present within IssuerSignedItem!", MdocHeaderParameter.ELEMENT_IDENTIFIER));
        }
        if (!elementIdentifierHeader.isTextString()) {
            throw new IllegalInputException(String.format(
                    "'%s' header parameter shall be of unicode string type!", MdocHeaderParameter.ELEMENT_IDENTIFIER));
        }
        return elementIdentifierHeader.asString();
    }

    private CBORValue getElementValue(CBORValue issuerSignedItemMap) {
        CBORValue elementValue = issuerSignedItemMap.get(MdocHeaderParameter.ELEMENT_VALUE.cbor());
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
