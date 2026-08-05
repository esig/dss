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

import co.nstant.in.cbor.CborException;
import co.nstant.in.cbor.decoder.UnicodeStringDecoder;
import co.nstant.in.cbor.model.MajorType;
import co.nstant.in.cbor.model.UnicodeString;
import eu.europa.esig.dss.attestation.mdoc.creation.MdocIssuerSignedItem;
import eu.europa.esig.dss.attestation.mdoc.model.MdocIssuerSigned;
import eu.europa.esig.dss.cbades.COSEParser;
import eu.europa.esig.dss.cbades.COSESignStructure;
import eu.europa.esig.dss.cbades.cbor.CBORByteString;
import eu.europa.esig.dss.cbades.cbor.CBORMap;
import eu.europa.esig.dss.cbades.cbor.CBORObject;
import eu.europa.esig.dss.cbades.cbor.CBORUtils;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
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
import java.util.Set;

/**
 * Parses the mdoc IssuerSigned as per ISO 18013-5 "8.3.2.1.2.2 Device retrieval mdoc response"
 *
 */
public class IssuerSignedParser {

    private static final Logger LOG = LoggerFactory.getLogger(MdocDeviceResponseParser.class);

    /** The document to be parsed */
    private DSSDocument document;

    /** CBORMap to be parsed */
    private CBORMap cborIssuerSerial;

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
     */
    public IssuerSignedParser(CBORMap cborIssuerSerial) {
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
            int symbol = is.read();
            return isIssuerSigned(symbol, is);
        } catch (IOException | CborException e) {
            if (LOG.isTraceEnabled()) {
                LOG.trace("Error on mdoc decoding : {}. Not a valid mdoc file.", e.getMessage());
            }
        }
        return false;
    }

    private boolean isIssuerSigned(int symbol, InputStream is) throws IOException, CborException {
        if (MajorType.MAP == MajorType.ofByte(symbol)) {
            MdocDeviceResponseParser.DSSMapDecoder mapDecoder = new MdocDeviceResponseParser.DSSMapDecoder(is);
            long mapLength = mapDecoder.getLength(symbol);
            if (mapLength == -1 || (mapLength >= 1 && mapLength <= 2)) { // -1 for not defined length, from 1 to 2 for allowed structures
                int mapFirstSymbol = is.read();
                if (MajorType.UNICODE_STRING == MajorType.ofByte(mapFirstSymbol)) {
                    UnicodeStringDecoder stringDecoder = new UnicodeStringDecoder(null, is);
                    UnicodeString unicodeString = stringDecoder.decode(mapFirstSymbol);
                    String headerName = unicodeString.toString();
                    return MdocHeaderParameter.NAMESPACES.toString().equals(headerName) ||
                            MdocHeaderParameter.ISSUER_AUTH.toString().equals(headerName);
                }
            }
        }
        return false;
    }

    /**
     * Parses the provided document and returns an mdoc IssuerSigned object, if supported
     *
     * @return {@link MdocIssuerSigned}
     */
    public MdocIssuerSigned parse() {
        if (cborIssuerSerial == null) {
            CBORObject cborObject = parseCbor(document);
            if (!cborObject.isMap()) {
                throw new IllegalInputException("An mdoc shall be represented by a CBOR Map type!");
            }
            cborIssuerSerial = (CBORMap) cborObject;
        }
        return getIssuerSigned(cborIssuerSerial);
    }

    private MdocIssuerSigned getIssuerSigned(CBORMap issuerSignedMap) {
        if (issuerSignedMap.isEmpty()) {
            throw new IllegalInputException(
                    String.format("'%s' header is represented by an empty map!", MdocHeaderParameter.ISSUER_SIGNED));
        }

        final MdocIssuerSigned issuerSigned = new MdocIssuerSigned();
        issuerSigned.setNamespaces(getIssuerNamespaces(issuerSignedMap));
        issuerSigned.setIssuerAuth(getIssuerAuth(issuerSignedMap));
        return issuerSigned;
    }

    private Map<String, List<MdocIssuerSignedItem>> getIssuerNamespaces(CBORMap issuerSigned) {
        CBORObject namespacesHeader = issuerSigned.getHeader(MdocHeaderParameter.NAMESPACES.cbor());
        if (namespacesHeader == null) {
            // optional
            return Collections.emptyMap();
        }
        if (!namespacesHeader.isMap()) {
            LOG.warn("'{}' header within IssuerSigned object shall be of Map type!", MdocHeaderParameter.NAMESPACES);
            return Collections.emptyMap();
        }
        CBORMap namespacesMap = (CBORMap) namespacesHeader;
        if (namespacesMap.isEmpty()) {
            LOG.warn("'{}' map is empty!", MdocHeaderParameter.NAMESPACES);
            return Collections.emptyMap();
        }

        final Map<String, List<MdocIssuerSignedItem>> nameSpaces = new HashMap<>();
        Set<CBORObject> namespaces = namespacesMap.getKeys();
        for (CBORObject namespace : namespaces) {
            if (!namespace.isUnicodeString()) {
                LOG.warn("NameSpace object shall be of an unsigned string type! Found  : '{}'", namespace.getClass().getSimpleName());
                continue;
            }
            String namespaceString = namespace.getValueAsString();
            final List<MdocIssuerSignedItem> signedItems = new ArrayList<>();
            CBORObject issuerSignedItemBytesArray = namespacesMap.getHeader(namespace);
            if (issuerSignedItemBytesArray != null && issuerSignedItemBytesArray.isArray()) {
                List<CBORObject> issuerSignedItemBytesList = issuerSignedItemBytesArray.getValueAsList();
                if (Utils.isCollectionEmpty(issuerSignedItemBytesList)) {
                    LOG.warn("Array of IssuerSignedItemBytes items cannot be empty!");
                    continue;
                }
                for (CBORObject issuerSignedItemBytes : issuerSignedItemBytesList) {
                    if (issuerSignedItemBytes != null && issuerSignedItemBytes.isByteString()) {
                        MdocIssuerSignedItem signedItem = new MdocIssuerSignedItem(namespaceString, (CBORByteString) issuerSignedItemBytes);
                        signedItems.add(signedItem);
                    } else {
                        LOG.warn("IssuerSignedItemBytes shall be of CBOR byte string type! Found : '{}'",
                                issuerSignedItemBytes != null ? issuerSignedItemBytes.getClass().getSimpleName() : null);
                    }
                }

            } else {
                LOG.warn("Value of the IssuerNameSpaces map shall be of CBOR Array type! Found : '{}'",
                        issuerSignedItemBytesArray != null ? issuerSignedItemBytesArray.getClass().getSimpleName() : null);
            }

            nameSpaces.put(namespaceString, signedItems);
        }
        return nameSpaces;
    }

    private COSESignStructure getIssuerAuth(CBORMap issuerSigned) {
        CBORObject issuerAuthHeader = issuerSigned.getHeader(MdocHeaderParameter.ISSUER_AUTH.cbor());
        if (issuerAuthHeader == null) {
            throw new IllegalInputException(
                    String.format("No mandatory '%s' header found within the mdoc!", MdocHeaderParameter.ISSUER_AUTH));
        }
        try {
            COSEParser coseParser = COSEParser.fromCBORObject(issuerAuthHeader);
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
     * @return {@link CBORObject}
     */
    private CBORObject parseCbor(DSSDocument document) {
        try {
            return CBORUtils.parseCbor(document);
        } catch (CborException e) {
            throw new DSSException(String.format("A parsing error of CBOR content occurred : %s", e.getMessage()), e);
        }
    }

}
