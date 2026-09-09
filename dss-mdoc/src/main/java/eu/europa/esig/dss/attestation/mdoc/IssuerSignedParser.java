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

import eu.europa.ec.digit.cddl4j.cbor.CBORDecodeException;
import eu.europa.ec.digit.cddl4j.cbor.CBORInspector;
import eu.europa.ec.digit.cddl4j.cbor.CBORMajorType;
import eu.europa.ec.digit.cddl4j.cbor.CBORTags;
import eu.europa.ec.digit.cddl4j.cbor.CBORValue;
import eu.europa.esig.dss.attestation.mdoc.creation.MdocIssuerSignedItem;
import eu.europa.esig.dss.attestation.mdoc.model.MdocIssuerSigned;
import eu.europa.esig.dss.cbades.COSEParser;
import eu.europa.esig.dss.cbades.COSESignStructure;
import eu.europa.esig.dss.cbades.cbor.CBORMap;
import eu.europa.esig.dss.cbades.cbor.CBORUtils;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.spi.exception.IllegalInputException;
import eu.europa.esig.dss.utils.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Parses the mdoc IssuerSigned as per ISO 18013-5 "8.3.2.1.2.2 Device retrieval mdoc response"
 *
 */
public class IssuerSignedParser {

    private static final Logger LOG = LoggerFactory.getLogger(IssuerSignedParser.class);

    /** The document to be parsed */
    private DSSDocument document;

    /** CBORMap to be parsed */
    private CBORValue cborIssuerSerial;

    /**
     * Creates a parser from a {@code DSSDocument} containing an mdoc IssuerSigned object structure
     *
     * @param document {@link DSSDocument} to parse
     */
    public IssuerSignedParser(DSSDocument document) {
        Objects.requireNonNull(document, "Document cannot be null!");
        this.document = document;
    }

    /**
     * Creates a parser from a {@code CBORMap} representing an mdoc IssuerSigned object structure
     *
     * @param cborIssuerSerial {@link CBORMap} to read
     * @deprecated since DSS 6.6. Use {@link IssuerSignedParser(CBORValue)} instead.
     */
    @Deprecated
    public IssuerSignedParser(CBORMap cborIssuerSerial) {
        Objects.requireNonNull(cborIssuerSerial, "CBOR IssuerSerial object cannot be null!");
        this.cborIssuerSerial = cborIssuerSerial.toCBORValue();
    }

    /**
     * Creates a parser from a {@code CBORMap} representing an mdoc IssuerSigned object structure
     *
     * @param cborIssuerSerial {@link CBORValue} to read
     */
    public IssuerSignedParser(CBORValue cborIssuerSerial) {
        Objects.requireNonNull(cborIssuerSerial, "CBOR IssuerSerial object cannot be null!");
        this.cborIssuerSerial = cborIssuerSerial;
    }

    /**
     * Verifies if the provided file is an mdoc
     *
     * @return TRUE if the document is an mdoc and supported by the parser, FALSE otherwise
     */
    public boolean isSupported() {
        try (InputStream is = document.openStream()) {
            return isIssuerSigned(is);
        } catch (IOException | CBORDecodeException e) {
            if (LOG.isTraceEnabled()) {
                LOG.trace("Error on mdoc decoding : {}. Not a valid mdoc file.", e.getMessage());
            }
        }
        return false;
    }

    private boolean isIssuerSigned(InputStream is) throws IOException, CBORDecodeException {
        CBORInspector inspector = new CBORInspector(is);
        int initialByte = inspector.read();
        if (CBORMajorType.fromInitialByte(initialByte) != CBORMajorType.MAP) {
            return false;
        }

        long mapLength = inspector.readLength(initialByte);
        // -1 for not defined length, from 1 to 2 for allowed structures
        if (mapLength != -1 && (mapLength < 1 || mapLength > 2)) {
            return false;
        }

        int mapFirstByte = inspector.read();
        if (CBORMajorType.fromInitialByte(mapFirstByte) != CBORMajorType.TEXT_STRING) {
            return false;
        }

        String headerName = inspector.readTextString(mapFirstByte);
        return MdocHeaderParameter.NAMESPACES.toString().equals(headerName)
                || MdocHeaderParameter.ISSUER_AUTH.toString().equals(headerName);
    }


    /**
     * Parses the provided document and returns an mdoc IssuerSigned object, if supported
     *
     * @return {@link MdocIssuerSigned}
     */
    public MdocIssuerSigned parse() {
        if (cborIssuerSerial == null) {
            CBORValue cborValue = parseCbor(document);
            if (cborValue == null || !cborValue.isMap()) {
                throw new IllegalInputException("An mdoc shall be represented by a CBOR Map type!");
            }
            cborIssuerSerial = cborValue;
        }
        return getIssuerSigned(cborIssuerSerial);
    }

    private MdocIssuerSigned getIssuerSigned(CBORValue issuerSignedMap) {
        if (issuerSignedMap.size() == 0) {
            throw new IllegalInputException(
                    String.format("'%s' header is represented by an empty map!", MdocHeaderParameter.ISSUER_SIGNED));
        }

        final MdocIssuerSigned issuerSigned = new MdocIssuerSigned();
        issuerSigned.setNamespaces(getIssuerNamespaces(issuerSignedMap));
        issuerSigned.setIssuerAuth(getIssuerAuth(issuerSignedMap));
        return issuerSigned;
    }

    private Map<String, List<MdocIssuerSignedItem>> getIssuerNamespaces(CBORValue issuerSigned) {
        CBORValue namespacesHeader = issuerSigned.get(MdocHeaderParameter.NAMESPACES.cbor());
        if (namespacesHeader == null) {
            // optional
            return Collections.emptyMap();
        }
        if (!namespacesHeader.isMap()) {
            LOG.warn("'{}' header within IssuerSigned object shall be of Map type!", MdocHeaderParameter.NAMESPACES);
            return Collections.emptyMap();
        }
        if (namespacesHeader.size() == 0) {
            LOG.warn("'{}' map is empty!", MdocHeaderParameter.NAMESPACES);
            return Collections.emptyMap();
        }

        final Map<String, List<MdocIssuerSignedItem>> nameSpaces = new HashMap<>();
        List<CBORValue> namespaces = namespacesHeader.getKeys();
        for (CBORValue namespace : namespaces) {
            if (!namespace.isTextString()) {
                LOG.warn("NameSpace object shall be of an unsigned string type! Found  : '{}'", namespace.getType());
                continue;
            }
            String namespaceString = namespace.asString();
            final List<MdocIssuerSignedItem> signedItems = new ArrayList<>();
            CBORValue issuerSignedItemBytesArray = namespacesHeader.get(namespace);
            if (issuerSignedItemBytesArray != null && issuerSignedItemBytesArray.isArray()) {
                List<CBORValue> issuerSignedItemBytesList = issuerSignedItemBytesArray.getElements();
                if (Utils.isCollectionEmpty(issuerSignedItemBytesList)) {
                    LOG.warn("Array of IssuerSignedItemBytes items cannot be empty!");
                    continue;
                }
                for (CBORValue issuerSignedItemBytes : issuerSignedItemBytesList) {
                    if (issuerSignedItemBytes == null || !issuerSignedItemBytes.isTag() || CBORTags.ENCODED_CBOR != issuerSignedItemBytes.getTag().longValue()) {
                        LOG.warn("IssuerSignedItemBytes shall be of a tagged CBOR byte string type with a tag #6.24! Found : '{}'",
                                issuerSignedItemBytes != null ? issuerSignedItemBytes.getType() : null);
                        continue;
                    }
                    CBORValue issuerSignedItemBytesValue = issuerSignedItemBytes.getTaggedValue();
                    if (issuerSignedItemBytesValue == null || !issuerSignedItemBytesValue.isByteString()) {
                        LOG.warn("IssuerSignedItemBytes shall be of CBOR byte string type! Found : '{}'",
                                issuerSignedItemBytesValue != null ? issuerSignedItemBytesValue.getType() : null);
                        continue;
                    }
                    MdocIssuerSignedItem signedItem = new MdocIssuerSignedItem(namespaceString, issuerSignedItemBytes);
                    signedItems.add(signedItem);
                }

            } else {
                LOG.warn("Value of the IssuerNameSpaces map shall be of CBOR Array type! Found : '{}'",
                        issuerSignedItemBytesArray != null ? issuerSignedItemBytesArray.getType() : null);
            }

            nameSpaces.put(namespaceString, signedItems);
        }
        return nameSpaces;
    }

    private COSESignStructure getIssuerAuth(CBORValue issuerSigned) {
        CBORValue issuerAuthHeader = issuerSigned.get(MdocHeaderParameter.ISSUER_AUTH.cbor());
        if (issuerAuthHeader == null) {
            throw new IllegalInputException(
                    String.format("No mandatory '%s' header found within the mdoc!", MdocHeaderParameter.ISSUER_AUTH));
        }
        try {
            COSEParser coseParser = COSEParser.fromCBORValue(issuerAuthHeader);
            return coseParser.parse();
        } catch (Exception e) {
            throw new IllegalInputException(String.format(
                    "Unable to parse '%s' signature. Reason : %s", MdocHeaderParameter.ISSUER_AUTH, e.getMessage()), e);
        }
    }

    /**
     * Parses CBOR {@code DSSDocument}
     *
     * @param document {@link DSSDocument}
     * @return {@link CBORValue}
     */
    private CBORValue parseCbor(DSSDocument document) {
        try {
            return CBORUtils.parseCbor(document);
        } catch (CBORDecodeException e) {
            throw new IllegalInputException(String.format("A parsing error of CBOR content occurred : %s", e.getMessage()), e);
        }
    }

}
