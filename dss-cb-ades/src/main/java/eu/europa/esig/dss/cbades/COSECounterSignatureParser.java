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
import eu.europa.esig.dss.cbades.cbor.CBORArray;
import eu.europa.esig.dss.cbades.cbor.CBORByteString;
import eu.europa.esig.dss.cbades.cbor.CBORMap;
import eu.europa.esig.dss.cbades.cbor.CBORObject;
import eu.europa.esig.dss.enumerations.COSESignatureType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.spi.exception.IllegalInputException;
import eu.europa.esig.dss.utils.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * This class parses a counter signature
 *
 */
public class COSECounterSignatureParser extends AbstractCOSEParser {

    private static final Logger LOG = LoggerFactory.getLogger(COSECounterSignatureParser.class);

    /** The original context of the counter signature */
    private COSESignatureType context;

    /** The target signature containing the extracted counter signature */
    private COSEStructure masterSignature;

    /**
     * The constructor to parse a CBORObject
     *
     * @param cborObject {@link CBORObject} to parse
     */
    protected COSECounterSignatureParser(CBORObject cborObject) {
        super(cborObject);
    }

    /**
     * Instantiates a COSECounterSignatureParser from a {@code DSSDocument}
     *
     * @param document {@link DSSDocument} to parse
     * @return {@link COSECounterSignatureParser}
     */
    public static COSECounterSignatureParser fromDocument(DSSDocument document) {
        Objects.requireNonNull(document, "Document cannot be null!");
        if (!isSupported(document)) {
            throw new IllegalInputException("Document is not of a COSE signature type!");
        }
        final CBORObject cborObject = parseCbor(document);
        return new COSECounterSignatureParser(cborObject);
    }

    /**
     * Instantiates a COSECounterSignatureParser from a {@code CBORObject}
     *
     * @param cborObject {@link CBORObject} to parse
     * @return {@link COSECounterSignatureParser}
     */
    public static COSECounterSignatureParser fromCBORObject(CBORObject cborObject) {
        Objects.requireNonNull(cborObject, "CBORObject cannot be null!");
        return new COSECounterSignatureParser(cborObject);
    }

    /**
     * Sets the original counter signature context it has been extracted from
     *
     * @param context {@link COSESignatureType}
     * @return this {@link COSECounterSignatureParser}
     */
    public COSECounterSignatureParser setContext(COSESignatureType context) {
        this.context = context;
        return this;
    }

    /**
     * Sets the target signature
     *
     * @param masterSignature {@link COSEStructure}
     * @return {@link COSECounterSignatureParser}
     */
    public COSECounterSignatureParser setMasterSignature(COSEStructure masterSignature) {
        this.masterSignature = masterSignature;
        return this;
    }

    /**
     * This method verifies whether the document represents a COSE counter signature structure
     *
     * @param document {@link DSSDocument} to be validated
     * @return TRUE if the document is supported, FALSE otherwise
     */
    public static boolean isSupported(DSSDocument document) {
        try (InputStream is = document.openStream()) {
            return isCoseCounterSignatureStart(is);
        } catch (IOException e) {
            throw new DSSException(String.format("Unable to read the document with name '%s' : %s",
                    document.getName(), e.getMessage()));
        }
    }

    /**
     * This method verifies whether the beginning of the InputStream is a COSE counter signature structure.
     *
     * @param inputStream {@link InputStream} to check
     * @return TRUE if the beginning of the InputStream represents a COSE counter signature structure, FALSE otherwise
     */
    private static boolean isCoseCounterSignatureStart(InputStream inputStream) {
        try {
            CBORInspector inspector = new CBORInspector(inputStream);
            int initialByte = inspector.read();
            if (isCoseCounterSignatureTag(inspector, initialByte)) {
                initialByte = inspector.read();
                return isCoseCounterSignatureArray(inspector, initialByte);
            }
            return isCoseCounterSignatureArray(inspector, initialByte);

        } catch (CBORDecodeException exception) {
            if (LOG.isTraceEnabled()) {
                LOG.trace("Error on CBOR decoding: {}. Not a valid CBOR file.", exception.getMessage());
            }
            return false;
        }
    }

    private static boolean isCoseCounterSignatureTag(CBORInspector inspector, int initialByte)
            throws CBORDecodeException {
        if (CBORMajorType.TAG != CBORMajorType.fromInitialByte(initialByte)) {
            return false;
        }
        return COSEConstants.COSE_COUNTERSIGNATURE_TAG == inspector.readTag(initialByte);
    }

    private static boolean isCoseCounterSignatureArray(CBORInspector inspector, int initialByte) throws CBORDecodeException {
        if (CBORMajorType.ARRAY != CBORMajorType.fromInitialByte(initialByte)) {
            return false;
        }

        consumeLength(inspector, initialByte);
        int arrayFirstByte = inspector.read();
        if (CBORMajorType.BYTE_STRING == CBORMajorType.fromInitialByte(arrayFirstByte)) {
            // COSE_Countersignature0
            return true;
        }
        if (CBORMajorType.ARRAY == CBORMajorType.fromInitialByte(arrayFirstByte)) {
            // COSE_Countersignature / [+ COSE_Countersignature]
            return isCoseSignature(inspector, arrayFirstByte);
        }
        return false;
    }

    private static void consumeLength(CBORInspector inspector, int initialByte) throws CBORDecodeException {
        inspector.readLength(initialByte);
    }

    private static boolean isCoseSignature(CBORInspector inspector, int initialByte) throws CBORDecodeException {
        if (CBORMajorType.ARRAY != CBORMajorType.fromInitialByte(initialByte)) {
            return false;
        }
        long arrayLength = inspector.readLength(initialByte);
        if (arrayLength == -1 || arrayLength == 3) {
            int arrayFirstByte = inspector.read();
            return CBORMajorType.BYTE_STRING == CBORMajorType.fromInitialByte(arrayFirstByte);
        }
        return false;
    }

    /**
     * This method parses COSE signature present within a provided document
     *
     * @return {@link COSECounterSignStructure}
     */
    public COSECounterSignStructure parse() {
        if (cborObject.isArray()) {
            CBORArray cborArray = (CBORArray) cborObject;
            if (cborArray.isTagged()) {
                // COSE_Countersignature
                if (COSESignatureType.COSE_COUNTER_SIGNATURE.getTag() == cborArray.getTag().getValue()) {
                    return parseCOSECounterSignature(cborArray);
                } else {
                    throw new UnsupportedOperationException(String.format(
                            "The tag '%s' is not supported for COSE counter signature structure!", cborArray.getTag().getValue()));
                }
            }
            if (entriesCBORArrays(cborArray)) {
                // [+ COSE_Countersignature]
                return parseCOSECounterSignatureArray(cborArray);
            } else {
                // COSE_Countersignature
                return parseCOSECounterSignature(cborObject);
            }

        } else if (cborObject.isByteString()) {
            // COSE_Countersignature0
            CBORByteString cborByteString = (CBORByteString) cborObject;
            return parseCOSECounterSignature0(cborByteString);

        } else {
            throw new IllegalInputException("A COSE counter signature shall be represented by a CBOR Array or ByteString type!");
        }
    }

    private boolean entriesCBORArrays(CBORArray cborArray) {
        return cborArray.getValueAsList().stream().allMatch(CBORObject::isArray);
    }

    private COSECounterSignatureArray parseCOSECounterSignatureArray(CBORArray cborArray) {
        final COSECounterSignatureArray coseCounterSignatureArray = new COSECounterSignatureArray();
        coseCounterSignatureArray.setTagged(cborArray.isTagged());
        coseCounterSignatureArray.setContext(context);
        coseCounterSignatureArray.setMasterSignature(masterSignature);
        List<COSECounterSignature> signatures = new ArrayList<>();
        for (CBORObject arrayEntry : cborArray.getValueAsList()) {
            COSECounterSignature coseCounterSignature = parseCOSECounterSignature(arrayEntry);
            signatures.add(coseCounterSignature);
        }
        coseCounterSignatureArray.setCoseCounterSignatureList(signatures);
        return coseCounterSignatureArray;
    }

    private COSECounterSignature parseCOSECounterSignature(CBORObject cborObject) {
        if (!cborObject.isArray()) {
            throw new IllegalInputException("COSE_Countersignature must be of CBORArray type!");
        }
        CBORArray cborArray = (CBORArray) cborObject;
        final List<CBORObject> arrayEntries = cborArray.getValueAsList();
        if (Utils.collectionSize(arrayEntries) != 3) {
            throw new IllegalInputException("COSE_Countersignature array must have 3 entries!");
        }
        CBORObject protectedHeaderItem = arrayEntries.get(0);
        if (!protectedHeaderItem.isByteString()) {
            throw new IllegalInputException("COSE_Countersignature.protected header must be a bstr!");
        }
        CBORObject unprotectedHeaderItem = arrayEntries.get(1);
        if (!unprotectedHeaderItem.isMap()) {
            throw new IllegalInputException("COSE_Countersignature.unprotected header must be a header map!");
        }
        CBORObject signatureItem = arrayEntries.get(2);
        if (!signatureItem.isByteString()) {
            throw new IllegalInputException("COSE_Signature.signature must be a bstr!");
        }

        final COSECounterSignature coseCounterSignature = new COSECounterSignature();
        coseCounterSignature.setContext(context);
        coseCounterSignature.setMasterSignature(masterSignature);
        coseCounterSignature.setTagged(cborArray.isTagged());
        coseCounterSignature.setProtectedHeader(new COSEProtectedHeader((CBORByteString) protectedHeaderItem));
        coseCounterSignature.setUnprotectedHeader(new COSEUnprotectedHeader((CBORMap) unprotectedHeaderItem));
        coseCounterSignature.setSignature((CBORByteString) signatureItem);
        return coseCounterSignature;
    }

    private COSECounterSignature0 parseCOSECounterSignature0(CBORByteString cborByteString) {
        final COSECounterSignature0 coseCounterSignature0 = new COSECounterSignature0();
        coseCounterSignature0.setContext(context);
        coseCounterSignature0.setMasterSignature(masterSignature);
        coseCounterSignature0.setTagged(cborByteString.isTagged());
        coseCounterSignature0.setSignature(cborByteString);
        return coseCounterSignature0;
    }

}
