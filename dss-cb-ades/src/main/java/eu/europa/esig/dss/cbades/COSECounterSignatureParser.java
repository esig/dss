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
     * @deprecated since DSS 6.6. Use {@link COSECounterSignatureParser(CBORValue)}.
     */
    @Deprecated
    protected COSECounterSignatureParser(CBORObject cborObject) {
        this(cborObject.toCBORValue());
    }

    /**
     * The constructor to parse a CBORObject
     *
     * @param cborValue {@link CBORValue} to parse
     */
    protected COSECounterSignatureParser(CBORValue cborValue) {
        super(cborValue);
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
        final CBORValue cborValue = parseCbor(document);
        return new COSECounterSignatureParser(cborValue);
    }

    /**
     * Instantiates a COSECounterSignatureParser from a {@code CBORObject}
     *
     * @param cborObject {@link CBORObject} to parse
     * @return {@link COSECounterSignatureParser}
     * @deprecated since DSS 6.6. Use {@link #fromCBORValue(CBORValue)}.
     */
    @Deprecated
    public static COSECounterSignatureParser fromCBORObject(CBORObject cborObject) {
        Objects.requireNonNull(cborObject, "CBORObject cannot be null!");
        return new COSECounterSignatureParser(cborObject.toCBORValue());
    }

    /**
     * Instantiates a COSECounterSignatureParser from a {@code CBORObject}
     *
     * @param cborValue {@link CBORValue} to parse
     * @return {@link COSECounterSignatureParser}
     */
    public static COSECounterSignatureParser fromCBORValue(CBORValue cborValue) {
        Objects.requireNonNull(cborValue, "CBORValue cannot be null!");
        return new COSECounterSignatureParser(cborValue);
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
        if (cborValue.isTag()) {
            CBORValue taggedValue = cborValue.getTaggedValue();
            if (taggedValue.isArray()) {
                // COSE_Countersignature
                if (COSESignatureType.COSE_COUNTER_SIGNATURE.getTag() == cborValue.getTag().longValue()) {
                    return parseCOSECounterSignature(cborValue);
                } else {
                    throw new UnsupportedOperationException(String.format(
                            "The tag '%s' is not supported for COSE counter signature structure!", cborValue.getTag().longValue()));
                }
            } else if (taggedValue.isByteString()) {
                // COSE_Countersignature0
                if (COSESignatureType.COSE_COUNTER_SIGNATURE0.getTag() == cborValue.getTag().longValue()) {
                    return parseCOSECounterSignature0(cborValue);
                } else {
                    throw new UnsupportedOperationException(String.format(
                            "The tag '%s' is not supported for COSE counter signature 0 structure!", cborValue.getTag().longValue()));
                }
            }
        }

        if (cborValue.isArray()) {
            if (entriesCBORArrays(cborValue)) {
                // [+ COSE_Countersignature]
                return parseCOSECounterSignatureArray(cborValue);
            } else {
                // COSE_Countersignature
                return parseCOSECounterSignature(cborValue);
            }

        } else if (cborValue.isByteString()) {
            // COSE_Countersignature0
            return parseCOSECounterSignature0(cborValue);

        } else {
            throw new IllegalInputException("A COSE counter signature shall be represented by a CBOR Array or ByteString type!");
        }
    }

    private boolean entriesCBORArrays(CBORValue cborArray) {
        return cborArray.getElements().stream().allMatch(this::isCBORArrayOrTaggedArray);
    }

    private boolean isCBORArrayOrTaggedArray(CBORValue cborValue) {
        return cborValue.isArray() || (cborValue.isTag() && cborValue.getTaggedValue().isArray());
    }

    private COSECounterSignatureArray parseCOSECounterSignatureArray(CBORValue cborArray) {
        final COSECounterSignatureArray coseCounterSignatureArray = new COSECounterSignatureArray();
        if (cborArray.isTag()) {
            coseCounterSignatureArray.setTagged(true);
            cborArray = cborArray.getTaggedValue();
        }
        coseCounterSignatureArray.setContext(context);
        coseCounterSignatureArray.setMasterSignature(masterSignature);
        List<COSECounterSignature> signatures = new ArrayList<>();
        for (CBORValue arrayEntry : cborArray.getElements()) {
            COSECounterSignature coseCounterSignature = parseCOSECounterSignature(arrayEntry);
            signatures.add(coseCounterSignature);
        }
        coseCounterSignatureArray.setCoseCounterSignatureList(signatures);
        return coseCounterSignatureArray;
    }

    private COSECounterSignature parseCOSECounterSignature(CBORValue cborArray) {
        boolean isTagged = cborArray.isTag();
        if (isTagged) {
            cborArray = cborArray.getTaggedValue();
        }

        if (!cborArray.isArray()) {
            throw new IllegalInputException("COSE_Countersignature must be of CBORArray type!");
        }

        final List<CBORValue> arrayEntries = cborArray.getElements();
        if (Utils.collectionSize(arrayEntries) != 3) {
            throw new IllegalInputException("COSE_Countersignature array must have 3 entries!");
        }
        CBORValue protectedHeaderItem = arrayEntries.get(0);
        if (!protectedHeaderItem.isByteString()) {
            throw new IllegalInputException("COSE_Countersignature.protected header must be a bstr!");
        }
        CBORValue unprotectedHeaderItem = arrayEntries.get(1);
        if (!unprotectedHeaderItem.isMap()) {
            throw new IllegalInputException("COSE_Countersignature.unprotected header must be a header map!");
        }
        CBORValue signatureItem = arrayEntries.get(2);
        if (!signatureItem.isByteString()) {
            throw new IllegalInputException("COSE_Signature.signature must be a bstr!");
        }

        final COSECounterSignature coseCounterSignature = new COSECounterSignature();
        coseCounterSignature.setContext(context);
        coseCounterSignature.setMasterSignature(masterSignature);
        coseCounterSignature.setTagged(isTagged);
        coseCounterSignature.setProtectedHeader(new COSEProtectedHeader(protectedHeaderItem));
        coseCounterSignature.setUnprotectedHeader(new COSEUnprotectedHeader(unprotectedHeaderItem));
        coseCounterSignature.setSignature(signatureItem);
        return coseCounterSignature;
    }

    private COSECounterSignature0 parseCOSECounterSignature0(CBORValue cborByteString) {
        final COSECounterSignature0 coseCounterSignature0 = new COSECounterSignature0();
        coseCounterSignature0.setContext(context);
        coseCounterSignature0.setMasterSignature(masterSignature);
        if (cborByteString.isTag()) {
            coseCounterSignature0.setTagged(true);
            cborByteString = cborByteString.getTaggedValue();
        }
        coseCounterSignature0.setSignature(cborByteString);
        return coseCounterSignature0;
    }

}
