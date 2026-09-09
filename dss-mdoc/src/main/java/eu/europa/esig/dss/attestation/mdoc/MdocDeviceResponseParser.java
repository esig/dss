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
import eu.europa.ec.digit.cddl4j.cbor.CBORMapEntry;
import eu.europa.ec.digit.cddl4j.cbor.CBORValue;
import eu.europa.esig.dss.attestation.mdoc.model.MdocDeviceAuth;
import eu.europa.esig.dss.attestation.mdoc.model.MdocDeviceNameSpaces;
import eu.europa.esig.dss.attestation.mdoc.model.MdocDeviceResponse;
import eu.europa.esig.dss.attestation.mdoc.model.MdocDeviceSigned;
import eu.europa.esig.dss.attestation.mdoc.model.MdocDocument;
import eu.europa.esig.dss.attestation.mdoc.model.MdocDocumentError;
import eu.europa.esig.dss.attestation.mdoc.model.MdocErrorItems;
import eu.europa.esig.dss.attestation.mdoc.model.MdocIssuerSigned;
import eu.europa.esig.dss.cbades.COSEParser;
import eu.europa.esig.dss.cbades.cbor.CBORUtils;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.spi.exception.IllegalInputException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
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
            return isMdoc(is);
        } catch (IOException | CBORDecodeException e) {
            if (LOG.isTraceEnabled()) {
                LOG.trace("Error on mdoc decoding : {}. Not a valid mdoc file.", e.getMessage());
            }
        }
        return false;
    }

    private boolean isMdoc(InputStream is) throws IOException, CBORDecodeException {
        CBORInspector inspector = new CBORInspector(is);
        int initialByte = inspector.read();
        if (CBORMajorType.fromInitialByte(initialByte) != CBORMajorType.MAP) {
            return false;
        }

        long mapLength = inspector.readLength(initialByte);
        // -1 for not defined length, from 2 to 4 for allowed structures
        if (mapLength != -1 && (mapLength < 2 || mapLength > 4)) {
            return false;
        }

        int mapFirstByte = inspector.read();
        if (CBORMajorType.fromInitialByte(mapFirstByte) != CBORMajorType.TEXT_STRING) {
            return false;
        }

        String headerName = inspector.readTextString(mapFirstByte);
        return MdocHeaderParameter.VERSION.toString().equals(headerName)
                || MdocHeaderParameter.DOCUMENTS.toString().equals(headerName)
                || MdocHeaderParameter.DOCUMENT_ERRORS.toString().equals(headerName)
                || MdocHeaderParameter.STATUS.toString().equals(headerName);
    }


    /**
     * Parses the provided document and returns an mdoc object, if supported
     *
     * @return {@link MdocDeviceResponse}
     */
    public MdocDeviceResponse parse() {
        CBORValue cborValue = parseCbor(document);
        if (cborValue == null || !cborValue.isMap()) {
            throw new IllegalInputException("An mdoc shall be represented by a CBOR Map type!");
        }

        final MdocDeviceResponse mdocDeviceResponse = new MdocDeviceResponse();
        mdocDeviceResponse.setVersion(getVersion(cborValue));
        mdocDeviceResponse.setDocuments(getDocuments(cborValue));
        mdocDeviceResponse.setDocumentErrors(getDocumentErrors(cborValue));
        mdocDeviceResponse.setStatus(getStatus(cborValue));
        return mdocDeviceResponse;
    }

    private String getVersion(CBORValue cborMdoc) {
        CBORValue versionHeader = cborMdoc.get(MdocHeaderParameter.VERSION.cbor());
        if (versionHeader == null) {
            throw new IllegalInputException(
                    String.format("No mandatory '%s' header found within the mdoc!", MdocHeaderParameter.VERSION));
        }
        if (!versionHeader.isTextString()) {
            throw new IllegalInputException(
                    String.format("'%s' header shall be of Unicode String type!", MdocHeaderParameter.VERSION));
        }
        return versionHeader.asString();
    }

    private List<MdocDocument> getDocuments(CBORValue cborMdoc) {
        CBORValue documentsHeader = cborMdoc.get(MdocHeaderParameter.DOCUMENTS.cbor());
        if (documentsHeader == null) {
            // optional
            return Collections.emptyList();
        }
        if (!documentsHeader.isArray()) {
            LOG.warn("'{}' header within mdoc structure shall be represented by an Array type!", MdocHeaderParameter.DOCUMENTS);
            return Collections.emptyList();
        }
        if (documentsHeader.size() == 0) {
            LOG.warn("'{}' array is empty!", MdocHeaderParameter.DOCUMENTS);
            return Collections.emptyList();
        }
        return documentsHeader.getElements().stream()
                .map(this::parseDocument).filter(Objects::nonNull).collect(Collectors.toList());
    }

    private MdocDocument parseDocument(CBORValue docValue) {
        if (docValue == null) {
            LOG.warn("Document cannot be null!");
            return null;
        }
        if (!docValue.isMap()) {
            LOG.warn("Document object shall be represented by a Map type!");
            return null;
        }

        try {
            final MdocDocument mdocDocument = new MdocDocument();
            mdocDocument.setDocType(getDocType(docValue));
            mdocDocument.setIssuerSigned(getIssuerSigned(docValue));
            mdocDocument.setDeviceSigned(getDeviceSigned(docValue));
            mdocDocument.setErrors(getErrors(docValue));
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

    private String getDocType(CBORValue documentMap) {
        CBORValue docTypeHeader = documentMap.get(MdocHeaderParameter.DOC_TYPE.cbor());
        if (docTypeHeader == null) {
            throw new IllegalInputException(
                    String.format("No mandatory '%s' header found within the mdoc!", MdocHeaderParameter.DOC_TYPE));
        }
        if (!docTypeHeader.isTextString()) {
            throw new IllegalInputException(
                    String.format("'%s' header shall be of Unicode String type!", MdocHeaderParameter.DOC_TYPE));
        }
        return docTypeHeader.asString();
    }

    private MdocIssuerSigned getIssuerSigned(CBORValue documentMap) {
        CBORValue issuerSignedHeader = documentMap.get(MdocHeaderParameter.ISSUER_SIGNED.cbor());
        if (issuerSignedHeader == null) {
            throw new IllegalInputException(
                    String.format("No mandatory '%s' header found within the mdoc!", MdocHeaderParameter.ISSUER_SIGNED));
        }
        if (!issuerSignedHeader.isMap()) {
            throw new IllegalInputException(
                    String.format("'%s' header shall be of Map type!", MdocHeaderParameter.ISSUER_SIGNED));
        }
        return new IssuerSignedParser(issuerSignedHeader).parse();
    }

    private MdocDeviceSigned getDeviceSigned(CBORValue documentMap) {
        CBORValue deviceSignedHeader = documentMap.get(MdocHeaderParameter.DEVICE_SIGNED.cbor());
        if (deviceSignedHeader == null) {
            throw new IllegalInputException(
                    String.format("No mandatory '%s' header found within the mdoc!", MdocHeaderParameter.DEVICE_SIGNED));
        }
        if (!deviceSignedHeader.isMap()) {
            throw new IllegalInputException(
                    String.format("'%s' header shall be of Map type!", MdocHeaderParameter.DEVICE_SIGNED));
        }
        if (deviceSignedHeader.size() == 0) {
            throw new IllegalInputException(
                    String.format("'%s' header is represented by an empty map!", MdocHeaderParameter.DEVICE_SIGNED));
        }

        final MdocDeviceSigned deviceSigned = new MdocDeviceSigned();
        deviceSigned.setDeviceNameSpaces(getDeviceNameSpaces(deviceSignedHeader));
        deviceSigned.setDeviceAuth(getDeviceAuth(deviceSignedHeader));
        return deviceSigned;
    }

    private MdocDeviceNameSpaces getDeviceNameSpaces(CBORValue deviceSignedMap) {
        CBORValue namespacesHeader = deviceSignedMap.get(MdocHeaderParameter.NAMESPACES.cbor());
        return new MdocDeviceNameSpaces(namespacesHeader);
    }

    private MdocDeviceAuth getDeviceAuth(CBORValue deviceSignedMap) {
        CBORValue deviceAuthHeader = deviceSignedMap.get(MdocHeaderParameter.DEVICE_AUTH.cbor());
        if (deviceAuthHeader == null) {
            throw new IllegalInputException(
                    String.format("No mandatory '%s' header found within the mdoc!", MdocHeaderParameter.DEVICE_AUTH));
        }
        if (!deviceAuthHeader.isMap()) {
            throw new IllegalInputException(
                    String.format("'%s' header shall be of Map type!", MdocHeaderParameter.DEVICE_AUTH));
        }
        if (deviceAuthHeader.size() == 0) {
            throw new IllegalInputException(
                    String.format("'%s' header is represented by an empty map!", MdocHeaderParameter.DEVICE_AUTH));
        }

        final MdocDeviceAuth mdocDeviceAuth = new MdocDeviceAuth();
        CBORValue deviceSignature = deviceAuthHeader.get(MdocHeaderParameter.DEVICE_SIGNATURE.cbor());
        if (deviceSignature != null) {
            mdocDeviceAuth.setDeviceSignature(COSEParser.fromCBORValue(deviceSignature).parse());
        } else {
            CBORValue deviceMac = deviceAuthHeader.get(MdocHeaderParameter.DEVICE_MAC.cbor());
            if (deviceMac == null) {
                throw new IllegalInputException(
                        String.format("Either '%s' or '%s' header shall be present within mdoc DeviceAuth object!",
                                MdocHeaderParameter.DEVICE_SIGNATURE, MdocHeaderParameter.DEVICE_MAC));
            }
            if (!deviceMac.isArray()) {
                throw new IllegalInputException(
                        String.format("'%s' header shall be of Array type!", MdocHeaderParameter.DEVICE_MAC));
            }
            mdocDeviceAuth.setDeviceMac(deviceMac);
        }
        return mdocDeviceAuth;
    }

    private Map<String, MdocErrorItems> getErrors(CBORValue documentMap) {
        CBORValue errorsHeader = documentMap.get(MdocHeaderParameter.ERRORS.cbor());
        if (errorsHeader == null) {
            // optional
            return Collections.emptyMap();
        }
        if (!errorsHeader.isMap()) {
            LOG.warn("'{}' header shall be of Map type!", MdocHeaderParameter.ERRORS);
            return Collections.emptyMap();
        }
        if (errorsHeader.size() == 0) {
            LOG.warn("'{}' map is empty!", MdocHeaderParameter.ERRORS);
            return Collections.emptyMap();
        }

        final Map<String, MdocErrorItems> errors = new HashMap<>();
        List<CBORValue> errorNamespaces = errorsHeader.getKeys();
        for (CBORValue namespace : errorNamespaces) {
            if (!namespace.isTextString()) {
                LOG.warn("NameSpace object shall be of an unsigned string type! Found  : '{}'", namespace.getType());
                continue;
            }
            try {
                String namespaceString = namespace.asString();
                errors.put(namespaceString, getErrorItems(errorsHeader, namespace));
            } catch (Exception e) {
                LOG.warn("An error occurred on Errors processing : {}", e.getMessage(), e);
            }
        }
        return errors;
    }

    private MdocErrorItems getErrorItems(CBORValue errorsMap, CBORValue namespace) {
        CBORValue errorItemsMap = errorsMap.get(namespace);
        if (errorItemsMap == null) {
            throw new IllegalStateException(
                    String.format("No ErrorItems found for the namespace '%s'!", namespace.asString()));
        }
        if (!errorItemsMap.isMap()) {
            throw new IllegalInputException("ErrorItems shall be of Map type!");
        }
        if (errorItemsMap.size() == 0) {
            throw new IllegalInputException("ErrorItems object is represented by an empty map!");
        }

        final MdocErrorItems errorItems = new MdocErrorItems();
        Map<String, Long> result = new HashMap<>();
        for (CBORValue dataElementIdentifier : errorItemsMap.getKeys()) {
            if (!dataElementIdentifier.isTextString()) {
                LOG.warn("DataElementIdentifier object shall be of an unsigned string type! Found  : '{}'",
                        dataElementIdentifier.getType());
                continue;
            }
            String dataElementIdentifierString = dataElementIdentifier.asString();
            CBORValue errorCodeObject = errorItemsMap.get(dataElementIdentifier);
            if (errorCodeObject == null) {
                throw new IllegalStateException(
                        String.format("No ErrorCode found for the DataElementIdentifier '%s'!", dataElementIdentifierString));
            }
            if (!errorCodeObject.isNegativeInteger() || !errorCodeObject.isUnsignedInteger()) {
                throw new IllegalInputException("ErrorCode shall be of an Integer type!");
            }
            Long errorCodeLong = errorCodeObject.asInteger().longValue();
            result.put(dataElementIdentifierString, errorCodeLong);
        }
        errorItems.setErrorsMap(result);
        return errorItems;
    }

    private List<MdocDocumentError> getDocumentErrors(CBORValue cborMdoc) {
        CBORValue documentErrorsHeader = cborMdoc.get(MdocHeaderParameter.DOCUMENT_ERRORS.cbor());
        if (documentErrorsHeader == null) {
            // optional
            return Collections.emptyList();
        }
        if (!documentErrorsHeader.isArray()) {
            LOG.warn("'{}' header within mdoc structure shall be represented by an Array type!", MdocHeaderParameter.DOCUMENT_ERRORS);
            return Collections.emptyList();
        }
        if (documentErrorsHeader.size() == 0) {
            LOG.warn("'{}' array is empty!", MdocHeaderParameter.DOCUMENT_ERRORS);
            return Collections.emptyList();
        }

        return documentErrorsHeader.getElements().stream()
                .map(this::getDocumentError).filter(Objects::nonNull).collect(Collectors.toList());
    }

    private MdocDocumentError getDocumentError(CBORValue documentErrorMap) {
        if (documentErrorMap == null) {
            LOG.warn("DocumentError cannot be null!");
            return null;
        }
        if (!documentErrorMap.isMap()) {
            LOG.warn("DocumentError object shall be represented by a Map type!");
            return null;
        }
        if (documentErrorMap.size() != 1) {
            LOG.warn("DocumentError object shall be a Map of a single entry!");
            return null;
        }

        CBORMapEntry mapEntry = documentErrorMap.getEntries().iterator().next();
        CBORValue docTypeObject = mapEntry.key();
        if (!docTypeObject.isTextString()) {
            LOG.warn("DocType within a DocumentError shall be represented by a unicode string type!");
            return null;
        }
        CBORValue errorCodeObject = mapEntry.value();
        if (!errorCodeObject.isUnsignedInteger() && !errorCodeObject.isNegativeInteger()) {
            LOG.warn("ErrorCode within a DocumentError shall be represented by an integer type!");
            return null;
        }

        final MdocDocumentError documentError = new MdocDocumentError();
        documentError.setDocType(docTypeObject.asString());
        documentError.setErrorCode(errorCodeObject.asInteger().longValue());
        return documentError;
    }

    private Long getStatus(CBORValue cborMdoc) {
        CBORValue statusHeader = cborMdoc.get(MdocHeaderParameter.STATUS.cbor());
        if (statusHeader == null) {
            throw new IllegalInputException(
                    String.format("No mandatory '%s' header found within the mdoc!", MdocHeaderParameter.STATUS));
        }
        if (!statusHeader.isUnsignedInteger()) {
            throw new IllegalInputException(
                    String.format("'%s' header shall be of an unsigned integer type!", MdocHeaderParameter.STATUS));
        }
        return statusHeader.asInteger().longValue();
    }

    /**
     * Parses CBOR {@code DSSDocument} securely
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
