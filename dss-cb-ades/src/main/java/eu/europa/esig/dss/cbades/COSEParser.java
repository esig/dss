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

import co.nstant.in.cbor.CborException;
import co.nstant.in.cbor.decoder.TagDecoder;
import co.nstant.in.cbor.model.MajorType;
import co.nstant.in.cbor.model.Tag;
import eu.europa.esig.dss.cbades.cbor.CBORArray;
import eu.europa.esig.dss.cbades.cbor.CBORByteString;
import eu.europa.esig.dss.cbades.cbor.CBORMap;
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
     */
    protected COSEParser(CBORObject cborObject) {
        super(cborObject);
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
        return fromCBORObject(parseCbor(document));
    }

    /**
     * Instantiates a COSEParser from a {@code CBORObject}
     *
     * @param cborObject {@link CBORObject} to parse
     * @return {@link COSEParser}
     */
    public static COSEParser fromCBORObject(CBORObject cborObject) {
        Objects.requireNonNull(cborObject, "CBORObject cannot be null!");
        return new COSEParser(cborObject);
    }

    /**
     * Instantiates a COSEParser from a byte array
     *
     * @param cborBinaries bytes to parse
     * @return {@link COSEParser}
     */
    public static COSEParser fromBinaries(byte[] cborBinaries) {
        Objects.requireNonNull(cborBinaries, "CBOR Binaries cannot be null!");
        return fromCBORObject(CBORUtils.parseCbor(cborBinaries));
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
     * This method verifies whether the beginning of the InputStream is a COSE structure
     *
     * @param inputStream {@link InputStream} to check
     * @return TRUE if the beginning of the InoutStream represents a COSE valid structure, FALSE otherwise
     * @throws IOException if an error occurs on InputStream reading
     */
    private static boolean isCoseStart(InputStream inputStream) throws IOException {
        try (InputStream is = inputStream) {
            int symbol = is.read();
            if (isCoseTag(symbol, is)) {
                symbol = is.read();
                return isCoseArray(symbol, is);
            } else if (isCoseArray(symbol, is)) {
                return true;
            }
        } catch (CborException e) {
            if (LOG.isTraceEnabled()) {
                LOG.trace("Error on CBOR decoding : {}. Not a valid CBOR file.", e.getMessage());
            }
        }
        return false;
    }

    private static boolean isCoseTag(int symbol, InputStream inputStream) throws CborException {
        if (MajorType.TAG == MajorType.ofByte(symbol)) {
            TagDecoder tagDecoder = new TagDecoder(null, inputStream);
            Tag tag = tagDecoder.decode(symbol);
            return COSEConstants.COSE_SIGN_TAG == tag.getValue() || COSEConstants.COSE_SIGN1_TAG == tag.getValue();
        }
        return false;
    }

    private static boolean isCoseArray(int symbol, InputStream inputStream) throws CborException, IOException {
        if (MajorType.ARRAY == MajorType.ofByte(symbol)) {
            DSSArrayDecoder arrayDecoder = new DSSArrayDecoder(inputStream);
            long length = arrayDecoder.getLength(symbol);
            if (length == -1 || length == 4) { // -1 for not defined length, 4 for COSESign or COSESign1 structure
                int arrayFirstSymbol = inputStream.read();
                return MajorType.BYTE_STRING == MajorType.ofByte(arrayFirstSymbol);
            }
        }
        return false;
    }

    /**
     * This method parses COSE signature present within a provided document
     *
     * @return {@link COSESignStructure}
     */
    public COSESignStructure parse() {
        if (!cborObject.isArray()) {
            throw new IllegalInputException("A COSE signature shall be represented by a CBOR Array type!");
        }
        CBORArray cborArray = (CBORArray) cborObject;
        if (cborArray.isTagged()) {
            if (COSESignatureType.COSE_SIGN.getTag() == cborArray.getTag().getValue()) {
                return parseCOSESign(cborArray);
            } else if (COSESignatureType.COSE_SIGN1.getTag() == cborArray.getTag().getValue()) {
                return parseCOSESign1(cborArray);
            }
            throw new UnsupportedOperationException(String.format(
                    "The tag '%s' is not supported for COSE signature structure!", cborArray.getTag().getValue()));

        } else {
            // untagged
            assertValidCOSEStructure(cborArray);
            if (isCOSESign(cborArray)) {
                return parseCOSESign(cborArray);
            } else {
                // COSE_Sign1
                return parseCOSESign1(cborArray);
            }
        }
    }

    private COSESign parseCOSESign(CBORArray cborArray) {
        List<CBORObject> dataItems = cborArray.getValueAsList();
        if (Utils.collectionSize(dataItems) != 4) {
            throw new IllegalInputException("COSE_Sign array must have 4 entries!");
        }
        CBORObject protectedHeaderItem = dataItems.get(0);
        if (!protectedHeaderItem.isByteString()) {
            throw new IllegalInputException("COSE_Sign.protected header must be a bstr!");
        }
        CBORObject unprotectedHeaderItem = dataItems.get(1);
        if (!unprotectedHeaderItem.isMap()) {
            throw new IllegalInputException("COSE_Sign.unprotected header must be a header map!");
        }
        CBORObject payloadItem = dataItems.get(2);
        if (payloadItem != null && !payloadItem.isByteString() && !payloadItem.isNull()) {
            throw new IllegalInputException("COSE_Sign.payload must be a bstr or nil!");
        }
        CBORObject signaturesArray = dataItems.get(3);
        if (!signaturesArray.isArray()) {
            throw new IllegalInputException("COSE_Sign1.signature must be an array!");
        }

        final COSESign coseSign = new COSESign();
        coseSign.setTagged(cborArray.isTagged());
        coseSign.setProtectedHeader(new COSEProtectedHeader((CBORByteString) protectedHeaderItem));
        coseSign.setUnprotectedHeader(new COSEUnprotectedHeader((CBORMap) unprotectedHeaderItem));
        coseSign.setPayload(payloadItem);

        List<COSESignature> coseSignatures = parseSignatures((CBORArray) signaturesArray);
        coseSignatures.forEach(s -> s.setParent(coseSign));
        coseSign.setSignatures(coseSignatures);

        return coseSign;
    }

    /**
     * Parses a CBORArray containing COSESignature's
     *
     * @param signaturesArray {@link CBORArray} to parse
     * @return a list of {@link COSESignature}s
     */
    protected List<COSESignature> parseSignatures(CBORArray signaturesArray) {
        if (signaturesArray.isEmpty()) {
            throw new IllegalInputException("COSE_Sign.signatures array is empty!");
        }
        final List<COSESignature> signatures = new ArrayList<>();
        for (CBORObject cborObject : signaturesArray.getValueAsList()) {
            signatures.add(parseSignature(cborObject));
        }
        return signatures;
    }

    private COSESignature parseSignature(CBORObject coseSignatureItem) {
        if (!coseSignatureItem.isArray()) {
            throw new IllegalInputException("COSE_Sign.signatures COSE_Signature entry must be an array!");
        }
        CBORArray cborArray = (CBORArray) coseSignatureItem;
        List<CBORObject> arrayItems = cborArray.getValueAsList();
        if (Utils.collectionSize(arrayItems) != 3) {
            throw new IllegalInputException("COSE_Sign.signatures COSE_Signature array must have 3 entries!");
        }
        CBORObject protectedHeaderItem = arrayItems.get(0);
        if (!protectedHeaderItem.isByteString()) {
            throw new IllegalInputException("COSE_Signature.protected header must be a bstr!");
        }
        CBORObject unprotectedHeaderItem = arrayItems.get(1);
        if (!unprotectedHeaderItem.isMap()) {
            throw new IllegalInputException("COSE_Signature.unprotected header must be a header map!");
        }
        CBORObject signatureItem = arrayItems.get(2);
        if (!signatureItem.isByteString()) {
            throw new IllegalInputException("COSE_Signature.signature must be a bstr!");
        }
        final COSESignature coseSignature = new COSESignature();
        coseSignature.setProtectedHeader(new COSEProtectedHeader((CBORByteString) protectedHeaderItem));
        coseSignature.setUnprotectedHeader(new COSEUnprotectedHeader((CBORMap) unprotectedHeaderItem));
        coseSignature.setSignature((CBORByteString) signatureItem);
        return coseSignature;
    }

    private COSESign1 parseCOSESign1(CBORArray cborArray) {
        List<CBORObject> arrayItems = cborArray.getValueAsList();
        if (Utils.collectionSize(arrayItems) != 4) {
            throw new IllegalInputException("COSE_Sign1 array must have 4 entries!");
        }
        CBORObject protectedHeaderItem = arrayItems.get(0);
        if (!protectedHeaderItem.isByteString()) {
            throw new IllegalInputException("COSE_Sign1.protected header must be a bstr!");
        }
        CBORObject unprotectedHeaderItem = arrayItems.get(1);
        if (!unprotectedHeaderItem.isMap()) {
            throw new IllegalInputException("COSE_Sign1.unprotected header must be a header map!");
        }
        CBORObject payloadItem = arrayItems.get(2);
        if (!payloadItem.isByteString() && !payloadItem.isNull()) {
            throw new IllegalInputException("COSE_Sign1.payload must be a bstr or nil!");
        }
        CBORObject signatureItem = arrayItems.get(3);
        if (!signatureItem.isByteString()) {
            throw new IllegalInputException("COSE_Sign1.signature must be a bstr!");
        }

        final COSESign1 coseSign1 = new COSESign1();
        coseSign1.setTagged(cborArray.isTagged());
        coseSign1.setProtectedHeader(new COSEProtectedHeader((CBORByteString) protectedHeaderItem));
        coseSign1.setUnprotectedHeader(new COSEUnprotectedHeader((CBORMap) unprotectedHeaderItem));
        coseSign1.setPayload(payloadItem);
        coseSign1.setSignature((CBORByteString) signatureItem);
        return coseSign1;
    }

    private void assertValidCOSEStructure(CBORArray cborArray) {
        List<CBORObject> arrayItems = cborArray.getValueAsList();
        if (Utils.collectionSize(arrayItems) != 4) {
            throw new IllegalInputException("COSE structure array must have 4 entries!");
        }
        CBORObject protectedHeaderItem = arrayItems.get(0);
        if (!protectedHeaderItem.isByteString()) {
            throw new IllegalInputException("COSE structure protected header must be a bstr!");
        }
        CBORObject unprotectedHeaderItem = arrayItems.get(1);
        if (!unprotectedHeaderItem.isMap()) {
            throw new IllegalInputException("COSE structure unprotected header must be a header map!");
        }
        CBORObject payloadItem = arrayItems.get(2);
        if (!payloadItem.isByteString() && !payloadItem.isNull()) {
            throw new IllegalInputException("COSE structure payload must be a bstr or nil!");
        }
    }

    private boolean isCOSESign(CBORArray cborArray) {
        List<CBORObject> arrayItems = cborArray.getValueAsList();
        CBORObject signaturesItem = arrayItems.get(3);
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
