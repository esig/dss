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
package eu.europa.esig.dss.cbades;

import eu.europa.ec.digit.cddl4j.cbor.CBORDecodeException;
import eu.europa.ec.digit.cddl4j.cbor.CBORInspector;
import eu.europa.ec.digit.cddl4j.cbor.CBORMajorType;
import eu.europa.ec.digit.cddl4j.cbor.CBORValue;
import eu.europa.esig.dss.cbades.cbor.CBORArray;
import eu.europa.esig.dss.cbades.cbor.CBORObject;
import eu.europa.esig.dss.cbades.cbor.CBORUtils;
import eu.europa.esig.dss.enumerations.COSESignatureType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.spi.exception.IllegalInputException;
import eu.europa.esig.dss.utils.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * This class is used to parse a COSE signature
 *
 */
public class COSEParser extends AbstractCOSEParser {

    private static final Logger LOG = LoggerFactory.getLogger(COSEParser.class);

    /**
     * The constructor to parse a CBORObject
     *
     * @param cborObject {@link CBORObject} to parse
     * @deprecated since DSS 6.6. Use {@link }
     */
    @Deprecated
    protected COSEParser(CBORObject cborObject) {
        super(cborObject);
    }

    /**
     * The constructor to parse a CBORObject
     *
     * @param cborValue {@link CBORValue} to parse
     */
    protected COSEParser(CBORValue cborValue) {
        super(cborValue);
    }

    /**
     * Instantiates a COSEParser from a {@code DSSDocument}
     *
     * @param document {@link DSSDocument} to parse
     * @return {@link COSEParser}
     */
    public static COSEParser fromDocument(DSSDocument document) {
        Objects.requireNonNull(document, "Document cannot be null!");
        if (!isSupported(document)) {
            throw new IllegalInputException("Document is not of a COSE signature type!");
        }
        return fromCBORValue(parseCbor(document));
    }

    /**
     * Instantiates a COSEParser from a {@code CBORObject}
     *
     * @param cborObject {@link CBORObject} to parse
     * @return {@link COSEParser}
     * @deprecated since DSS 6.6. Use {@link #fromCBORValue(CBORValue)} instead.
     */
    @Deprecated
    public static COSEParser fromCBORObject(CBORObject cborObject) {
        Objects.requireNonNull(cborObject, "CBORObject cannot be null!");
        return new COSEParser(cborObject);
    }

    /**
     * Instantiates a COSEParser from a {@code CBORValue}
     *
     * @param cborValue {@link CBORValue} to parse
     * @return {@link COSEParser}
     */
    public static COSEParser fromCBORValue(CBORValue cborValue) {
        Objects.requireNonNull(cborValue, "CBORValue cannot be null!");
        return new COSEParser(cborValue);
    }

    /**
     * Instantiates a COSEParser from a byte array
     *
     * @param cborBinaries bytes to parse
     * @return {@link COSEParser}
     */
    public static COSEParser fromBinaries(byte[] cborBinaries) {
        Objects.requireNonNull(cborBinaries, "CBOR Binaries cannot be null!");
        return fromCBORValue(CBORUtils.parseCbor(cborBinaries));
    }

    /**
     * This method verifies whether the document represents a COSE structure
     *
     * @param document {@link DSSDocument} to be validated
     * @return TRUE if the document is supported, FALSE otherwise
     */
    public static boolean isSupported(DSSDocument document) {
        try (InputStream is = document.openStream()) {
            return isSupported(is);
        } catch (IOException e) {
            throw new DSSException(String.format("Unable to read the document with name '%s' : %s",
                    document.getName(), e.getMessage()));
        }
    }

    /**
     * This method verifies whether the document binaries represent a COSE structure
     *
     * @param binaries binaries to be validated
     * @return TRUE if the document is supported, FALSE otherwise
     */
    public static boolean isSupported(byte[] binaries) {
        try (InputStream is = new ByteArrayInputStream(binaries)) {
            return isSupported(is);
        } catch (IOException e) {
            throw new DSSException(String.format("Unable to read the binaries : %s", e.getMessage()));
        }
    }

    /**
     * This method verifies whether the InputStream represents a COSE structure
     *
     * @param inputStream {@link InputStream} to be validated
     * @return TRUE if the InputStream is supported, FALSE otherwise
     * @throws IOException if an error occurs on InputStream reading
     */
    public static boolean isSupported(InputStream inputStream) throws IOException {
        try (InputStream is = inputStream) {
            return isCoseStart(is);
        }
    }

    /**
     * This method verifies whether the beginning of the InputStream is a COSE structure.
     *
     * @param inputStream {@link InputStream} to check
     * @return TRUE if the beginning of the InputStream represents a valid COSE structure, FALSE otherwise
     */
    private static boolean isCoseStart(InputStream inputStream) {
        try {
            CBORInspector inspector = new CBORInspector(inputStream);
            int initialByte = inspector.read();
            if (isCoseTag(inspector, initialByte)) {
                initialByte = inspector.read();
                return isCoseArray(inspector, initialByte);
            }
            return isCoseArray(inspector, initialByte);

        } catch (Exception exception) {
            if (LOG.isTraceEnabled()) {
                LOG.trace("Error on CBOR decoding: {}. Not a valid CBOR file.", exception.getMessage());
            }
            return false;
        }
    }

    private static boolean isCoseTag(CBORInspector inspector, int initialByte) throws CBORDecodeException {
        if (CBORMajorType.fromInitialByte(initialByte) != CBORMajorType.TAG) {
            return false;
        }
        long tag = inspector.readTag(initialByte);
        return COSEConstants.COSE_SIGN_TAG == tag || COSEConstants.COSE_SIGN1_TAG == tag;
    }

    private static boolean isCoseArray(CBORInspector inspector, int initialByte) throws CBORDecodeException {
        if (CBORMajorType.fromInitialByte(initialByte) != CBORMajorType.ARRAY) {
            return false;
        }
        long length = inspector.readLength(initialByte);
        if (length == -1 || length == 4) {
            int arrayFirstByte = inspector.read();
            return CBORMajorType.fromInitialByte(arrayFirstByte) == CBORMajorType.BYTE_STRING;
        }
        return false;
    }

    /**
     * This method parses COSE signature present within a provided document
     *
     * @return {@link COSESignStructure}
     */
    public COSESignStructure parse() {
        CBORValue coseSignStructure = cborValue;
        if (cborValue.isTag()) {
            coseSignStructure = cborValue.getTaggedValue();
        }

        if (!coseSignStructure.isArray()) {
            throw new IllegalInputException("A COSE signature shall be represented by a CBOR Array type!");
        }
        if (cborValue.isTag()) {
            if (COSESignatureType.COSE_SIGN.getTag() == cborValue.getTag().longValue()) {
                return parseCOSESign(coseSignStructure, true);
            } else if (COSESignatureType.COSE_SIGN1.getTag() == cborValue.getTag().longValue()) {
                return parseCOSESign1(coseSignStructure, true);
            }
            throw new UnsupportedOperationException(String.format(
                    "The tag '%s' is not supported for COSE signature structure!", cborValue.getTag().longValue()));

        } else {
            // untagged
            assertValidCOSEStructure(coseSignStructure);
            if (isCOSESign(coseSignStructure)) {
                return parseCOSESign(coseSignStructure, false);
            } else {
                // COSE_Sign1
                return parseCOSESign1(coseSignStructure, false);
            }
        }
    }

    private COSESign parseCOSESign(CBORValue cborArray, boolean tagged) {
        List<CBORValue> arrayEntries = cborArray.getElements();
        if (Utils.collectionSize(arrayEntries) != 4) {
            throw new IllegalInputException("COSE_Sign array must have 4 entries!");
        }
        CBORValue protectedHeaderItem = arrayEntries.get(0);
        if (!protectedHeaderItem.isByteString()) {
            throw new IllegalInputException("COSE_Sign.protected header must be a bstr!");
        }
        CBORValue unprotectedHeaderItem = arrayEntries.get(1);
        if (!unprotectedHeaderItem.isMap()) {
            throw new IllegalInputException("COSE_Sign.unprotected header must be a header map!");
        }
        CBORValue payloadItem = arrayEntries.get(2);
        if (payloadItem != null && !payloadItem.isByteString() && !payloadItem.isNull()) {
            throw new IllegalInputException("COSE_Sign.payload must be a bstr or nil!");
        }
        CBORValue signaturesArray = arrayEntries.get(3);
        if (!signaturesArray.isArray()) {
            throw new IllegalInputException("COSE_Sign1.signature must be an array!");
        }

        final COSESign coseSign = new COSESign();
        coseSign.setTagged(tagged);
        coseSign.setProtectedHeader(new COSEProtectedHeader(protectedHeaderItem));
        coseSign.setUnprotectedHeader(new COSEUnprotectedHeader(unprotectedHeaderItem));
        coseSign.setPayload(payloadItem);

        List<COSESignature> coseSignatures = parseSignatures(signaturesArray);
        coseSignatures.forEach(s -> s.setParent(coseSign));
        coseSign.setSignatures(coseSignatures);

        return coseSign;
    }

    /**
     * Parses a CBORArray containing COSESignature's
     *
     * @param signaturesArray {@link CBORArray} to parse
     * @return a list of {@link COSESignature}s
     * @deprecated since DSS 6.6. Use {@link #parseSignatures(CBORValue)}.
     */
    @Deprecated
    protected List<COSESignature> parseSignatures(CBORArray signaturesArray) {
        return parseSignatures(signaturesArray.toCBORValue());
    }

    /**
     * Parses a CBOR array containing COSESignature's
     *
     * @param signaturesArray {@link CBORValue} to parse
     * @return a list of {@link COSESignature}s
     */
    protected List<COSESignature> parseSignatures(CBORValue signaturesArray) {
        if (signaturesArray.size() == 0) {
            throw new IllegalInputException("COSE_Sign.signatures array is empty!");
        }
        final List<COSESignature> signatures = new ArrayList<>();
        for (CBORValue cborValue : signaturesArray.getElements()) {
            signatures.add(parseSignature(cborValue));
        }
        return signatures;
    }

    private COSESignature parseSignature(CBORValue coseSignatureItem) {
        if (!coseSignatureItem.isArray()) {
            throw new IllegalInputException("COSE_Sign.signatures COSE_Signature entry must be an array!");
        }
        List<CBORValue> arrayItems = coseSignatureItem.getElements();
        if (Utils.collectionSize(arrayItems) != 3) {
            throw new IllegalInputException("COSE_Sign.signatures COSE_Signature array must have 3 entries!");
        }
        CBORValue protectedHeaderItem = arrayItems.get(0);
        if (!protectedHeaderItem.isByteString()) {
            throw new IllegalInputException("COSE_Signature.protected header must be a bstr!");
        }
        CBORValue unprotectedHeaderItem = arrayItems.get(1);
        if (!unprotectedHeaderItem.isMap()) {
            throw new IllegalInputException("COSE_Signature.unprotected header must be a header map!");
        }
        CBORValue signatureItem = arrayItems.get(2);
        if (!signatureItem.isByteString()) {
            throw new IllegalInputException("COSE_Signature.signature must be a bstr!");
        }
        final COSESignature coseSignature = new COSESignature();
        coseSignature.setProtectedHeader(new COSEProtectedHeader(protectedHeaderItem));
        coseSignature.setUnprotectedHeader(new COSEUnprotectedHeader(unprotectedHeaderItem));
        coseSignature.setSignature(signatureItem);
        return coseSignature;
    }

    private COSESign1 parseCOSESign1(CBORValue cborArray, boolean tagged) {
        List<CBORValue> arrayItems = cborArray.getElements();
        if (Utils.collectionSize(arrayItems) != 4) {
            throw new IllegalInputException("COSE_Sign1 array must have 4 entries!");
        }
        CBORValue protectedHeaderItem = arrayItems.get(0);
        if (!protectedHeaderItem.isByteString()) {
            throw new IllegalInputException("COSE_Sign1.protected header must be a bstr!");
        }
        CBORValue unprotectedHeaderItem = arrayItems.get(1);
        if (!unprotectedHeaderItem.isMap()) {
            throw new IllegalInputException("COSE_Sign1.unprotected header must be a header map!");
        }
        CBORValue payloadItem = arrayItems.get(2);
        if (!payloadItem.isByteString() && !payloadItem.isNull()) {
            throw new IllegalInputException("COSE_Sign1.payload must be a bstr or nil!");
        }
        CBORValue signatureItem = arrayItems.get(3);
        if (!signatureItem.isByteString()) {
            throw new IllegalInputException("COSE_Sign1.signature must be a bstr!");
        }

        final COSESign1 coseSign1 = new COSESign1();
        coseSign1.setTagged(tagged);
        coseSign1.setProtectedHeader(new COSEProtectedHeader(protectedHeaderItem));
        coseSign1.setUnprotectedHeader(new COSEUnprotectedHeader(unprotectedHeaderItem));
        coseSign1.setPayload(payloadItem);
        coseSign1.setSignature(signatureItem);
        return coseSign1;
    }

    private void assertValidCOSEStructure(CBORValue cborArray) {
        List<CBORValue> arrayItems = cborArray.getElements();
        if (Utils.collectionSize(arrayItems) != 4) {
            throw new IllegalInputException("COSE structure array must have 4 entries!");
        }
        CBORValue protectedHeaderItem = arrayItems.get(0);
        if (!protectedHeaderItem.isByteString()) {
            throw new IllegalInputException("COSE structure protected header must be a bstr!");
        }
        CBORValue unprotectedHeaderItem = arrayItems.get(1);
        if (!unprotectedHeaderItem.isMap()) {
            throw new IllegalInputException("COSE structure unprotected header must be a header map!");
        }
        CBORValue payloadItem = arrayItems.get(2);
        if (!payloadItem.isByteString() && !payloadItem.isNull()) {
            throw new IllegalInputException("COSE structure payload must be a bstr or nil!");
        }
    }

    private boolean isCOSESign(CBORValue cborArray) {
        List<CBORValue> arrayItems = cborArray.getElements();
        CBORValue signaturesItem = arrayItems.get(3);
        if (signaturesItem.isArray()) {
            // COSE_Sign
            return true;
        } else if (signaturesItem.isByteString()) {
            // COSE_Sign1
            return false;
        } else {
            throw new IllegalInputException("COSE structure signature(s) must be a bstr or array!");
        }
    }

}
