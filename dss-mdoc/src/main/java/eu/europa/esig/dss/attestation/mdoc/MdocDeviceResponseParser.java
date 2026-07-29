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
import co.nstant.in.cbor.decoder.MapDecoder;
import co.nstant.in.cbor.decoder.UnicodeStringDecoder;
import co.nstant.in.cbor.model.MajorType;
import co.nstant.in.cbor.model.UnicodeString;
import eu.europa.esig.dss.cbades.COSEParser;
import eu.europa.esig.dss.cbades.cbor.CBORArray;
import eu.europa.esig.dss.cbades.cbor.CBORByteString;
import eu.europa.esig.dss.cbades.cbor.CBORMap;
import eu.europa.esig.dss.cbades.cbor.CBORObject;
import eu.europa.esig.dss.cbades.cbor.CBORSimpleObject;
import eu.europa.esig.dss.cbades.cbor.CBORUtils;
import eu.europa.esig.dss.attestation.mdoc.model.MdocDeviceAuth;
import eu.europa.esig.dss.attestation.mdoc.model.MdocDeviceNameSpaces;
import eu.europa.esig.dss.attestation.mdoc.model.MdocDeviceResponse;
import eu.europa.esig.dss.attestation.mdoc.model.MdocDeviceSigned;
import eu.europa.esig.dss.attestation.mdoc.model.MdocDocument;
import eu.europa.esig.dss.attestation.mdoc.model.MdocDocumentError;
import eu.europa.esig.dss.attestation.mdoc.model.MdocErrorItems;
import eu.europa.esig.dss.attestation.mdoc.model.MdocIssuerSigned;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.spi.exception.IllegalInputException;
import eu.europa.esig.dss.utils.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Parses the mdoc message as per ISO 18013-5
 *
 */
public class MdocDeviceResponseParser {

    private static final Logger LOG = LoggerFactory.getLogger(MdocDeviceResponseParser.class);

    /** The document to be parsed */
    private final DSSDocument document;

    /**
     * The default constructor
     *
     * @param document {@link DSSDocument} to parse
     */
    public MdocDeviceResponseParser(DSSDocument document) {
        Objects.requireNonNull(document, "Document cannot be null!");
        this.document = document;
    }

    /**
     * Verifies if the provided file is an mdoc
     *
     * @return TRUE if the document is an mdoc and supported by the parser, FALSE otherwise
     */
    public boolean isSupported() {
        try (InputStream is = document.openStream()) {
            int symbol = is.read();
            return isMdoc(symbol, is);
        } catch (IOException | CborException e) {
            if (LOG.isTraceEnabled()) {
                LOG.trace("Error on mdoc decoding : {}. Not a valid mdoc file.", e.getMessage());
            }
        }
        return false;
    }

    private boolean isMdoc(int symbol, InputStream is) throws IOException, CborException {
        if (MajorType.MAP == MajorType.ofByte(symbol)) {
            DSSMapDecoder mapDecoder = new DSSMapDecoder(is);
            long mapLength = mapDecoder.getLength(symbol);
            if (mapLength == -1 || (mapLength >= 2 && mapLength <= 4)) { // -1 for not defined length, from 2 to 4 for allowed structures
                int mapFirstSymbol = is.read();
                if (MajorType.UNICODE_STRING == MajorType.ofByte(mapFirstSymbol)) {
                    UnicodeStringDecoder stringDecoder = new UnicodeStringDecoder(null, is);
                    UnicodeString unicodeString = stringDecoder.decode(mapFirstSymbol);
                    String headerName = unicodeString.toString();
                    return MdocHeaderParameter.VERSION.toString().equals(headerName) ||
                            MdocHeaderParameter.DOCUMENTS.toString().equals(headerName) ||
                            MdocHeaderParameter.DOCUMENT_ERRORS.toString().equals(headerName) ||
                            MdocHeaderParameter.STATUS.toString().equals(headerName);
                }
            }
        }
        return false;
    }

    /**
     * Parses the provided document and returns an mdoc object, if supported
     *
     * @return {@link MdocDeviceResponse}
     */
    public MdocDeviceResponse parse() {
        CBORObject cborObject = parseCbor(document);
        if (!cborObject.isMap()) {
            throw new IllegalInputException("An mdoc shall be represented by a CBOR Map type!");
        }
        CBORMap cborMdoc = (CBORMap) cborObject;

        final MdocDeviceResponse mdocDeviceResponse = new MdocDeviceResponse();
        mdocDeviceResponse.setVersion(getVersion(cborMdoc));
        mdocDeviceResponse.setDocuments(getDocuments(cborMdoc));
        mdocDeviceResponse.setDocumentErrors(getDocumentErrors(cborMdoc));
        mdocDeviceResponse.setStatus(getStatus(cborMdoc));
        return mdocDeviceResponse;
    }

    private String getVersion(CBORMap cborMdoc) {
        CBORObject versionHeader = cborMdoc.getHeader(MdocHeaderParameter.VERSION.cbor());
        if (versionHeader == null) {
            throw new IllegalInputException(
                    String.format("No mandatory '%s' header found within the mdoc!", MdocHeaderParameter.VERSION));
        }
        if (!versionHeader.isUnicodeString()) {
            throw new IllegalInputException(
                    String.format("'%s' header shall be of Unicode String type!", MdocHeaderParameter.VERSION));
        }
        CBORSimpleObject versionString = (CBORSimpleObject) versionHeader;
        return versionString.getValueAsString();
    }

    private List<MdocDocument> getDocuments(CBORMap cborMdoc) {
        CBORObject documentsHeader = cborMdoc.getHeader(MdocHeaderParameter.DOCUMENTS.cbor());
        if (documentsHeader == null) {
            // optional
            return Collections.emptyList();
        }
        if (!documentsHeader.isArray()) {
            LOG.warn("'{}' header within mdoc structure shall be represented by an Array type!", MdocHeaderParameter.DOCUMENTS);
            return Collections.emptyList();
        }
        CBORArray documentsArray = (CBORArray) documentsHeader;
        if (documentsArray.isEmpty()) {
            LOG.warn("'{}' array is empty!", MdocHeaderParameter.DOCUMENTS);
            return Collections.emptyList();
        }
        return documentsArray.getValueAsList().stream()
                .map(this::parseDocument).filter(Objects::nonNull).collect(Collectors.toList());
    }

    private MdocDocument parseDocument(CBORObject documentObject) {
        if (documentObject == null) {
            LOG.warn("Document cannot be null!");
            return null;
        }
        if (!documentObject.isMap()) {
            LOG.warn("Document object shall be represented by a Map type!");
            return null;
        }

        try {
            CBORMap documentMap = (CBORMap) documentObject;

            final MdocDocument mdocDocument = new MdocDocument();
            mdocDocument.setDocType(getDocType(documentMap));
            mdocDocument.setIssuerSigned(getIssuerSigned(documentMap));
            mdocDocument.setDeviceSigned(getDeviceSigned(documentMap));
            mdocDocument.setErrors(getErrors(documentMap));
            return mdocDocument;

        } catch (Exception e) {
            String errorMessage = "An error occurred on processing of a Document instance : {}";
            if (LOG.isDebugEnabled()) {
                LOG.warn(errorMessage, e.getMessage(), e);
            } else {
                LOG.warn(errorMessage, e.getMessage());
            }
            return null;
        }
    }

    private String getDocType(CBORMap documentMap) {
        CBORObject docTypeHeader = documentMap.getHeader(MdocHeaderParameter.DOC_TYPE.cbor());
        if (docTypeHeader == null) {
            throw new IllegalInputException(
                    String.format("No mandatory '%s' header found within the mdoc!", MdocHeaderParameter.DOC_TYPE));
        }
        if (!docTypeHeader.isUnicodeString()) {
            throw new IllegalInputException(
                    String.format("'%s' header shall be of Unicode String type!", MdocHeaderParameter.DOC_TYPE));
        }
        CBORSimpleObject docTypeString = (CBORSimpleObject) docTypeHeader;
        return docTypeString.getValueAsString();
    }

    private MdocIssuerSigned getIssuerSigned(CBORMap documentMap) {
        CBORObject issuerSignedHeader = documentMap.getHeader(MdocHeaderParameter.ISSUER_SIGNED.cbor());
        if (issuerSignedHeader == null) {
            throw new IllegalInputException(
                    String.format("No mandatory '%s' header found within the mdoc!", MdocHeaderParameter.ISSUER_SIGNED));
        }
        if (!issuerSignedHeader.isMap()) {
            throw new IllegalInputException(
                    String.format("'%s' header shall be of Map type!", MdocHeaderParameter.ISSUER_SIGNED));
        }
        CBORMap issuerSignedMap = (CBORMap) issuerSignedHeader;
        return new IssuerSignedParser(issuerSignedMap).parse();
    }

    private MdocDeviceSigned getDeviceSigned(CBORMap documentMap) {
        CBORObject deviceSignedHeader = documentMap.getHeader(MdocHeaderParameter.DEVICE_SIGNED.cbor());
        if (deviceSignedHeader == null) {
            throw new IllegalInputException(
                    String.format("No mandatory '%s' header found within the mdoc!", MdocHeaderParameter.DEVICE_SIGNED));
        }
        if (!deviceSignedHeader.isMap()) {
            throw new IllegalInputException(
                    String.format("'%s' header shall be of Map type!", MdocHeaderParameter.DEVICE_SIGNED));
        }
        CBORMap deviceSignedMap = (CBORMap) deviceSignedHeader;
        if (deviceSignedMap.isEmpty()) {
            throw new IllegalInputException(
                    String.format("'%s' header is represented by an empty map!", MdocHeaderParameter.DEVICE_SIGNED));
        }

        final MdocDeviceSigned deviceSigned = new MdocDeviceSigned();
        deviceSigned.setDeviceNameSpaces(getDeviceNameSpaces(deviceSignedMap));
        deviceSigned.setDeviceAuth(getDeviceAuth(deviceSignedMap));
        return deviceSigned;
    }

    private MdocDeviceNameSpaces getDeviceNameSpaces(CBORMap deviceSignedMap) {
        CBORObject namespacesHeader = deviceSignedMap.getHeader(MdocHeaderParameter.NAMESPACES.cbor());
        if (namespacesHeader == null) {
            throw new IllegalInputException(String.format(
                    "No mandatory '%s' header found within the mdoc DeviceSigned object!", MdocHeaderParameter.NAMESPACES));
        }
        if (!namespacesHeader.isByteString()) {
            throw new IllegalInputException(String.format(
                    "'%s' header within DeviceSigned object shall be of CBOR byte string type!", MdocHeaderParameter.NAMESPACES));
        }
        CBORByteString namespacesByteString = (CBORByteString) namespacesHeader;
        return new MdocDeviceNameSpaces(namespacesByteString);
    }

    private MdocDeviceAuth getDeviceAuth(CBORMap deviceSignedMap) {
        CBORObject deviceAuthHeader = deviceSignedMap.getHeader(MdocHeaderParameter.DEVICE_AUTH.cbor());
        if (deviceAuthHeader == null) {
            throw new IllegalInputException(
                    String.format("No mandatory '%s' header found within the mdoc!", MdocHeaderParameter.DEVICE_AUTH));
        }
        if (!deviceAuthHeader.isMap()) {
            throw new IllegalInputException(
                    String.format("'%s' header shall be of Map type!", MdocHeaderParameter.DEVICE_AUTH));
        }
        CBORMap deviceAuthMap = (CBORMap) deviceAuthHeader;
        if (deviceAuthMap.isEmpty()) {
            throw new IllegalInputException(
                    String.format("'%s' header is represented by an empty map!", MdocHeaderParameter.DEVICE_AUTH));
        }

        final MdocDeviceAuth mdocDeviceAuth = new MdocDeviceAuth();
        CBORObject deviceSignature = deviceAuthMap.getHeader(MdocHeaderParameter.DEVICE_SIGNATURE.cbor());
        if (deviceSignature != null) {
            mdocDeviceAuth.setDeviceSignature(COSEParser.fromCBORObject(deviceSignature).parse());
        } else {
            CBORObject deviceMac = deviceAuthMap.getHeader(MdocHeaderParameter.DEVICE_MAC.cbor());
            if (deviceMac == null) {
                throw new IllegalInputException(
                        String.format("Either '%s' or '%s' header shall be present within mdoc DeviceAuth object!",
                                MdocHeaderParameter.DEVICE_SIGNATURE, MdocHeaderParameter.DEVICE_MAC));
            }
            if (!deviceMac.isArray()) {
                throw new IllegalInputException(
                        String.format("'%s' header shall be of Array type!", MdocHeaderParameter.DEVICE_MAC));
            }
            mdocDeviceAuth.setDeviceMac((CBORArray) deviceMac);
        }
        return mdocDeviceAuth;
    }

    private Map<String, MdocErrorItems> getErrors(CBORMap documentMap) {
        CBORObject errorsHeader = documentMap.getHeader(MdocHeaderParameter.ERRORS.cbor());
        if (errorsHeader == null) {
            // optional
            return Collections.emptyMap();
        }
        if (!errorsHeader.isMap()) {
            LOG.warn("'{}' header shall be of Map type!", MdocHeaderParameter.ERRORS);
            return Collections.emptyMap();
        }
        CBORMap errorsMap = (CBORMap) errorsHeader;
        if (errorsMap.isEmpty()) {
            LOG.warn("'{}' map is empty!", MdocHeaderParameter.ERRORS);
            return Collections.emptyMap();
        }

        final Map<String, MdocErrorItems> errors = new HashMap<>();
        Set<CBORObject> errorNamespaces = errorsMap.getKeys();
        for (CBORObject namespace : errorNamespaces) {
            if (!namespace.isUnicodeString()) {
                LOG.warn("NameSpace object shall be of an unsigned string type! Found  : '{}'", namespace.getClass().getSimpleName());
                continue;
            }
            try {
                String namespaceString = namespace.getValueAsString();
                errors.put(namespaceString, getErrorItems(errorsMap, namespace));
            } catch (Exception e) {
                LOG.warn("An error occurred on Errors processing : {}", e.getMessage(), e);
            }
        }
        return errors;
    }

    private MdocErrorItems getErrorItems(CBORMap errorsMap, CBORObject namespace) {
        CBORObject errorItemsObject = errorsMap.getHeader(namespace);
        if (errorItemsObject == null) {
            throw new IllegalStateException(
                    String.format("No ErrorItems found for the namespace '%s'!", namespace.getValueAsString()));
        }
        if (!errorItemsObject.isMap()) {
            throw new IllegalInputException("ErrorItems shall be of Map type!");
        }
        CBORMap errorItemsMap = (CBORMap) errorItemsObject;
        if (errorItemsMap.isEmpty()) {
            throw new IllegalInputException("ErrorItems object is represented by an empty map!");
        }

        final MdocErrorItems errorItems = new MdocErrorItems();
        Map<String, Long> result = new HashMap<>();
        for (CBORObject dataElementIdentifier : errorItemsMap.getKeys()) {
            if (!dataElementIdentifier.isUnicodeString()) {
                LOG.warn("DataElementIdentifier object shall be of an unsigned string type! Found  : '{}'",
                        dataElementIdentifier.getClass().getSimpleName());
                continue;
            }
            String dataElementIdentifierString = dataElementIdentifier.getValueAsString();
            CBORObject errorCodeObject = errorItemsMap.getHeader(dataElementIdentifier);
            if (errorCodeObject == null) {
                throw new IllegalStateException(
                        String.format("No ErrorCode found for the DataElementIdentifier '%s'!", dataElementIdentifierString));
            }
            if (!errorCodeObject.isNegativeInteger() || !errorCodeObject.isUnsignedInteger()) {
                throw new IllegalInputException("ErrorCode shall be of an Integer type!");
            }
            Long errorCodeLong = errorCodeObject.getValueAsLong();
            result.put(dataElementIdentifierString, errorCodeLong);
        }
        errorItems.setErrorsMap(result);
        return errorItems;
    }

    private List<MdocDocumentError> getDocumentErrors(CBORMap cborMdoc) {
        CBORObject documentErrorsHeader = cborMdoc.getHeader(MdocHeaderParameter.DOCUMENT_ERRORS.cbor());
        if (documentErrorsHeader == null) {
            // optional
            return Collections.emptyList();
        }
        if (!documentErrorsHeader.isArray()) {
            LOG.warn("'{}' header within mdoc structure shall be represented by an Array type!", MdocHeaderParameter.DOCUMENT_ERRORS);
            return Collections.emptyList();
        }
        CBORArray documentErrorsArray = (CBORArray) documentErrorsHeader;
        if (documentErrorsArray.isEmpty()) {
            LOG.warn("'{}' array is empty!", MdocHeaderParameter.DOCUMENT_ERRORS);
            return Collections.emptyList();
        }

        return documentErrorsArray.getValueAsList().stream()
                .map(this::getDocumentError).filter(Objects::nonNull).collect(Collectors.toList());
    }

    private MdocDocumentError getDocumentError(CBORObject documentErrorObject) {
        if (documentErrorObject == null) {
            LOG.warn("DocumentError cannot be null!");
            return null;
        }
        if (!documentErrorObject.isMap()) {
            LOG.warn("DocumentError object shall be represented by a Map type!");
            return null;
        }
        Map<CBORObject, CBORObject> documentErrorMap = documentErrorObject.getValueAsMap();
        if (Utils.mapSize(documentErrorMap) != 1) {
            LOG.warn("DocumentError object shall be a Map of a single entry!");
            return null;
        }

        Map.Entry<CBORObject, CBORObject> mapEntry = documentErrorMap.entrySet().iterator().next();
        CBORObject docTypeObject = mapEntry.getKey();
        if (!docTypeObject.isUnicodeString()) {
            LOG.warn("DocType within a DocumentError shall be represented by a unicode string type!");
            return null;
        }
        CBORObject errorCodeObject = mapEntry.getValue();
        if (!errorCodeObject.isUnsignedInteger() && !errorCodeObject.isNegativeInteger()) {
            LOG.warn("ErrorCode within a DocumentError shall be represented by an integer type!");
            return null;
        }

        final MdocDocumentError documentError = new MdocDocumentError();
        documentError.setDocType(docTypeObject.getValueAsString());
        documentError.setErrorCode(errorCodeObject.getValueAsLong());
        return documentError;
    }

    private Long getStatus(CBORMap cborMdoc) {
        CBORObject statusHeader = cborMdoc.getHeader(MdocHeaderParameter.STATUS.cbor());
        if (statusHeader == null) {
            throw new IllegalInputException(
                    String.format("No mandatory '%s' header found within the mdoc!", MdocHeaderParameter.STATUS));
        }
        if (!statusHeader.isUnsignedInteger()) {
            throw new IllegalInputException(
                    String.format("'%s' header shall be of an unsigned integer type!", MdocHeaderParameter.STATUS));
        }
        return statusHeader.getValueAsLong();
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

    /**
     * Extended implementation of {@code MapDecoder}
     */
    protected static class DSSMapDecoder extends MapDecoder {

        /**
         * Default constructor
         *
         * @param inputStream {@link InputStream}
         */
        public DSSMapDecoder(InputStream inputStream) {
            super(null, inputStream);
        }

        @Override
        protected long getLength(int initialByte) throws CborException {
            return super.getLength(initialByte);
        }

    }

}
