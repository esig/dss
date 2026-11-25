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
package eu.europa.esig.dss.cbades.cbor;

import co.nstant.in.cbor.CborDecoder;
import co.nstant.in.cbor.CborEncoder;
import co.nstant.in.cbor.CborException;
import co.nstant.in.cbor.model.DataItem;
import co.nstant.in.cbor.model.Tag;
import co.nstant.in.cbor.model.UnicodeString;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.spi.DSSASN1Utils;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import org.bouncycastle.asn1.x509.IssuerSerial;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Date;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static eu.europa.esig.dss.cbades.COSEHeaderParameter.ADO_TST;
import static eu.europa.esig.dss.cbades.COSEHeaderParameter.ALG;
import static eu.europa.esig.dss.cbades.COSEHeaderParameter.CONTENT_TYPE;
import static eu.europa.esig.dss.cbades.COSEHeaderParameter.COUNTER_SIGNATURE;
import static eu.europa.esig.dss.cbades.COSEHeaderParameter.CRIT;
import static eu.europa.esig.dss.cbades.COSEHeaderParameter.CWT_CLAIMS;
import static eu.europa.esig.dss.cbades.COSEHeaderParameter.IV;
import static eu.europa.esig.dss.cbades.COSEHeaderParameter.KID;
import static eu.europa.esig.dss.cbades.COSEHeaderParameter.PARTIAL_IV;
import static eu.europa.esig.dss.cbades.COSEHeaderParameter.SIG_D;
import static eu.europa.esig.dss.cbades.COSEHeaderParameter.SIG_PID;
import static eu.europa.esig.dss.cbades.COSEHeaderParameter.SIG_PL;
import static eu.europa.esig.dss.cbades.COSEHeaderParameter.SR_ATS;
import static eu.europa.esig.dss.cbades.COSEHeaderParameter.SR_CMS;
import static eu.europa.esig.dss.cbades.COSEHeaderParameter.X5BAG;
import static eu.europa.esig.dss.cbades.COSEHeaderParameter.X5CHAIN;
import static eu.europa.esig.dss.cbades.COSEHeaderParameter.X5T;
import static eu.europa.esig.dss.cbades.COSEHeaderParameter.X5TS;
import static eu.europa.esig.dss.cbades.COSEHeaderParameter.X5U;

/**
 * Contains common util methods for working with CBOR content
 *
 */
public final class CBORUtils {

    private static final Logger LOG = LoggerFactory.getLogger(CBORUtils.class);

    /** An empty btsr value */
    public static final CBORByteString EMPTY_BYTE_STRING;

    /** The binary content encoding (RFC 2045) */
    public static final String CONTENT_ENCODING_BINARY = "binary";

    /** Tag for the CBOR "full-date" object */
    public static final long CBOR_FULL_DATE_TAG = 1004;

    /** Tag for the CBOR "uri" object */
    private static final long CBOR_URI_TAG = 32;

    /**
     * Contains protected header names that are supported and can be present in the critical ('crit') attribute
     */
    private static final Set<CBORObject> supportedCriticalHeaders;

    /**
     * Contains protected header names that are required to be present in the critical ('crit') attribute, when used
     */
    private static final Set<CBORObject> requiredCriticalHeaders;

    static {
        EMPTY_BYTE_STRING = new CBORByteString();

        supportedCriticalHeaders = Stream.of(
                /* RFC 9052 */
                ALG.cbor(), CRIT.cbor(), CONTENT_TYPE.cbor(), KID.cbor(), IV.cbor(), PARTIAL_IV.cbor(),
                /* RFC 9360 */
                X5BAG.cbor(), X5CHAIN.cbor(), X5T.cbor(), X5U.cbor(),
                /* RFC 8152 */
                COUNTER_SIGNATURE.cbor(),
                /* RFC 9597 */
                CWT_CLAIMS.cbor(),
                /* CB-AdES TS 119 152-1 headers */
                X5TS.cbor(), SR_CMS.cbor(), SIG_PL.cbor(), SR_ATS.cbor(), ADO_TST.cbor(), SIG_PID.cbor(), SIG_D.cbor()
        ).collect(Collectors.toSet());

        requiredCriticalHeaders = Stream.of(
                /* CB-AdES TS 119 152-1 headers */
                SIG_D.cbor()
        ).collect(Collectors.toSet());
    }

    /**
     * Utils class
     */
    private CBORUtils() {
        // empty
    }

    /**
     * This method creates a Tag object from the given Long value
     *
     * @param longValue {@link Long} value to convert
     * @return {@link Tag}
     */
    public static Tag toTag(Long longValue) {
        if (longValue == null) {
            return null;
        }
        return new Tag(longValue);
    }

    /**
     * This method parses a {@code DSSDocument} and returns a {@code CBORObject},
     * representing the CBOR object structure
     *
     * @param document {@link DSSDocument} to parse
     * @return {@link CBORObject}
     * @throws CborException if an error occurs on document parsing
     */
    public static CBORObject parseCbor(DSSDocument document) throws CborException {
        try (InputStream is = document.openStream()) {
            CborDecoder cborDecoder = new CborDecoder(is);
            List<DataItem> dataItems = cborDecoder.decode();
            return toCBORObject(dataItems);
        } catch (IOException e) {
            throw new DSSException(String.format("Unable to read document with name '%s' : %s", document.getName(), e.getMessage()), e);
        }
    }

    /**
     * This method parses a byte array and returns a list of {@code DataItem}s,
     * representing the CBOR object structure
     *
     * @param bytes byte array to parse
     * @return a list of {@link DataItem}s
     */
    public static CBORObject parseCbor(byte[] bytes) {
        try {
            List<DataItem> dataItems = CborDecoder.decode(bytes);
            return toCBORObject(dataItems);
        } catch (CborException e) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Error on parsing binaries: {}", Utils.toBase64(bytes));
            }
            throw new DSSException(String.format("Unable to parse binaries : %s. More detail in debug mode.", e.getMessage()), e);
        }
    }

    private static CBORObject toCBORObject(List<DataItem> dataItems) {
        if (Utils.collectionSize(dataItems) == 1) {
            return CBORObjectFactory.toCBORObject(dataItems.iterator().next());
        } else {
            return new CBORArray(dataItems);
        }
    }

    /**
     * Checks if the given document is of CBOR format
     *
     * @param document {@link DSSDocument} to check
     * @return TRUE if the document is CBOR, FALSE otherwise
     */
    public static boolean isCbor(DSSDocument document) {
        return isCbor(document.openStream());
    }

    /**
     * Checks if the given data byte array is of CBOR format
     *
     * @param input byte array to check
     * @return TRUE if the byte array data in CBOR, FALSE otherwise
     */
    public static boolean isCbor(byte[] input) {
        return isCbor(new ByteArrayInputStream(input));
    }

    /**
     * Checks if the given InputStream contains data in a CBOR format
     *
     * @param inputStream {@link InputStream} to check
     * @return TRUE if the InputStream is CBOR, FALSE otherwise
     */
    public static boolean isCbor(InputStream inputStream) {
        try (InputStream is = inputStream) {
            return new CborDecoder(is).decode() != null;
        } catch (CborException e) {
            return false;
        } catch (IOException e) {
            throw new DSSException(String.format("Unable to read InputStream : %s", e.getMessage()), e);
        }
    }

    /**
     * Serialized a given CBOR object to a byte array
     *
     * @param cborObject {@link CBORObject} to be serialized
     * @return serialized byte array
     */
    public static byte[] serializeCborObject(CBORObject cborObject) {
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            CborEncoder cborEncoder = new CborEncoder(baos).nonCanonical(); // TODO: order of elements is to be ensured on our side ?
            cborEncoder.encode(cborObject.toDataItem());
            return baos.toByteArray();
        } catch (CborException | IOException e) {
            throw new DSSException(String.format("Unable to serialize CBOR object : %s", e.getMessage()), e);
        }
    }

    /**
     * Returns a CBOR Byte String wrapped incorporation of the {@code cborObject}
     *
     * @param cborObject {@link CBORObject} to serialized and incorporate into CBOR Byte String type
     * @return {@link CBORByteString}
     */
    public static CBORByteString toCborBtsrWrapped(CBORObject cborObject) {
        return new CBORByteString(serializeCborObject(cborObject));
    }

    /**
     * Returns a CBOR Byte String wrapped incorporation of the {@code cborObject}, which also includes the #6.24 tag
     *
     * @param cborObject {@link CBORObject} to serialized and incorporate into CBOR Byte String type
     * @return {@link CBORByteString}
     */
    public static CBORByteString toCborBtsrWrappedTagged(CBORObject cborObject) {
        CBORByteString cborBtsrWrapped = toCborBtsrWrapped(cborObject);
        cborBtsrWrapped.setTag(24L);
        return cborBtsrWrapped;
    }

    /**
     * Gets {@code DigestAlgorithm} safely for a given {@code digestAlgoId}
     *
     * @param digestAlgoId {@link Long} IANA COSE Digest Algorithm identifier
     * @return {@link DigestAlgorithm} if supported, NULL otherwise
     */
    public static DigestAlgorithm getDigestAlgorithmForCoseId(Long digestAlgoId) {
        if (digestAlgoId == null) {
            return null;
        }
        try {
            return DigestAlgorithm.forCOSE(digestAlgoId);
        } catch (IllegalArgumentException e) {
            LOG.warn("Unknown Digest Algorithm with Id '{}'.", digestAlgoId);
            return null;
        }
    }

    /**
     * Parses the 'kid' header value as in IETF RFC 9035
     *
     * @param value {@link String} IssuerSerial to parse
     * @return {@link IssuerSerial}
     */
    public static IssuerSerial getIssuerSerial(byte[] value) {
        if (value != null && DSSASN1Utils.isAsn1Encoded(value)) {
            return DSSASN1Utils.getIssuerSerial(value);
        }
        return null;
    }

    /**
     * Returns a set of supported protected critical headers
     *
     * @return a set of supported protected critical header identifiers
     */
    public static Set<CBORObject> getSupportedProtectedCriticalHeaders() {
        return supportedCriticalHeaders;
    }

    /**
     * Checks if the given {@code headerId} is required to be incorporated within 'crit' header, when used
     *
     * @param headerId {@link CBORObject} header key to check
     * @return TRUE if the header is required within 'crit' header when used, FALSE otherwise
     */
    public static boolean isRequiredCriticalHeader(CBORObject headerId) {
        return requiredCriticalHeaders.contains(headerId);
    }

    /**
     * Checks of the object is an instance of a CBOR btsr type
     *
     * @param uHeader {@link CBORObject} to check
     * @return TRUE if the object is an instance of CBOR btsr type, FALSE otherwise
     */
    public static boolean isCborByteStringWrappedFormat(CBORObject uHeader) {
        return uHeader.isByteString();
    }

    /**
     * Checks if the all components are CBOR byte string encoded
     *
     * @param uHeaders {@link CBORArray} to check
     * @return TRUE if all the components are CBOR byte string encoded, FALSE otherwise
     */
    public static boolean areAllCborBtsrComponents(CBORArray uHeaders) {
        if (uHeaders != null && !uHeaders.isEmpty()) {
            for (CBORObject component : uHeaders.getValueAsList()) {
                if (!isCborByteStringWrappedFormat(component)) {
                    return false;
                }
            }
        }
        return true;
    }

    /**
     * This method parses a {@code CBORObject} representing a component of 'uHeaders' unsigned header parameter,
     * returning a value of the entry in the unified form {@code CBORMap}
     *
     * @param uHeadersEntry {@link CBORObject} to parse
     * @return {@link CBORMap} if parsing is successful, NULL otherwise
     */
    public static CBORMap parseUHeadersEntry(CBORObject uHeadersEntry) {
        if (uHeadersEntry.isByteString()) {
            LOG.trace("CBOR Byte String encoded 'uHeader' component found. Parse to CBORMap.");
            byte[] componentSerialized = ((CBORByteString) uHeadersEntry).getValueAsBytes();
            try {
                uHeadersEntry = CBORUtils.parseCbor(componentSerialized);
            } catch (Exception e) {
                if (LOG.isDebugEnabled()) {
                    LOG.warn("An error occurred on parsing 'uHeaders' component with value (b64-encoded) '{}' : {}",
                            Utils.toBase64(componentSerialized), e.getMessage(), e);
                } else {
                    LOG.warn("An error occurred on parsing 'uHeaders' component : {}", e.getMessage());
                }
            }

        } else {
            LOG.warn("Component of 'uHeaders' unsigned header parameter shall be of CBOR Byte String type! Entry is skipped.");
            return null;
        }

        if (!uHeadersEntry.isMap()) {
            LOG.warn("Encoded component of 'uHeaders' unsigned header parameter shall be of CBORMap type! Entry is skipped.");
            return null;
        }

        CBORMap uHeadersEntryMap = (CBORMap) uHeadersEntry;
        if (uHeadersEntryMap.getSize() != 1) {
            LOG.warn("Only one entry is allowed within an 'uHeaders' component! Entry is skipped.");
            return null;
        }
        return uHeadersEntryMap;
    }

    /**
     * Generates a CBOR 'full-date' object for the {@code Date}
     *
     * @param date {@link Date}
     * @return {@link CBORObject}
     */
    public static CBORObject toFullDate(Date date) {
        if (date == null) {
            return null;
        }
        String dateString = DSSUtils.formatDateToISO8601(date);
        CBORObject cborObject = CBORObjectFactory.toCBORObject(dateString);
        cborObject.setTag(CBOR_FULL_DATE_TAG);
        return cborObject;
    }

    /**
     * Obtains a CBOR object represented by a NumericDate and returns the resulted {@code Date}
     *
     * @param cborObject {@link CBORObject}
     * @return {@link Date}
     */
    public static Date fromNumericDate(CBORObject cborObject) {
        if (cborObject == null) {
            return null;
        }
        long timeValueInMilliseconds;
        if (cborObject.isUnsignedInteger() || cborObject.isNegativeInteger()) {
            CBORSimpleObject iat = (CBORSimpleObject) cborObject;
            timeValueInMilliseconds = DSSUtils.getTimeValueInMilliseconds(iat.getValueAsLong());
        } else if (cborObject.isFloatingPointNumber()) {
            CBORSimpleObject iat = (CBORSimpleObject) cborObject;
            timeValueInMilliseconds = DSSUtils.getTimeValueInMilliseconds(iat.getValueAsDouble());
        } else {
            LOG.warn("NumericDate is expected. Obtained value : {}", cborObject);
            return null;
        }
        return DSSUtils.getDateFromMilliseconds(timeValueInMilliseconds);
    }

    /**
     * Produces a tagged CBOR Uri object (tag #6.32(tstr)).
     * NOTE: The method is meant to provide a smooth migration to cddl4j project. To be removed later.
     *
     * @param uri {@link String}
     * @return {@link CBORObject}
     */
    public static CBORObject toCborUri(String uri) {
        CBORSimpleObject cborObject = new CBORSimpleObject(new UnicodeString(uri));
        cborObject.setTag(CBOR_URI_TAG);
        return cborObject;
    }

    /**
     * Obtains a String extracted from a uri encoded CBOR tagged value #6.32(tstr).
     * NOTE: The method is meant to provide a smooth migration to cddl4j project.
     * To be changed to accept CBORValue later.
     *
     * @param cborValue {@link CBORObject}
     * @return {@link String}
     */
    public static String fromUri(CBORObject cborValue) {
        if (cborValue == null) {
            return null;
        }
        if (cborValue.isTagged() && cborValue.getTag().getValue() == 32) {
            return cborValue.getValueAsString();

        } else if (cborValue.isUnicodeString()) {
            LOG.warn("uri encoded (#6.32(tstr)) CBOR value is expected. Obtained String : {}", cborValue);
            return cborValue.getValueAsString();
        }
        LOG.warn("uri encoded (#6.32(tstr)) CBOR value is expected. Obtained value : {}", cborValue);
        return null;
    }

}
