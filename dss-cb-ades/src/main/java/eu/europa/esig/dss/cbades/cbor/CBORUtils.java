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

import eu.europa.ec.digit.cddl4j.cbor.CBOR;
import eu.europa.ec.digit.cddl4j.cbor.CBORDecodeException;
import eu.europa.ec.digit.cddl4j.cbor.CBORDecoder;
import eu.europa.ec.digit.cddl4j.cbor.CBORTags;
import eu.europa.ec.digit.cddl4j.cbor.CBORValue;
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
import java.io.IOException;
import java.io.InputStream;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.time.temporal.ChronoUnit;
import java.util.Date;
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
    public static final CBORValue EMPTY_BYTE_STRING;

    /** The binary content encoding (RFC 2045) */
    public static final String CONTENT_ENCODING_BINARY = "binary";

    /**
     * Tag for the CBOR "full-date" object
     *
     * @deprecated since DSS 6.6. Please use {@link CBORTags#FULL_DATE} instead.
     */
    @Deprecated
    public static final long CBOR_FULL_DATE_TAG = 1004;

    /**
     * Contains protected header names that are supported and can be present in the critical ('crit') attribute
     */
    private static final Set<CBORValue> supportedCriticalHeaders;

    /**
     * Contains protected header names that are required to be present in the critical ('crit') attribute, when used
     */
    private static final Set<CBORValue> requiredCriticalHeaders;

    static {
        EMPTY_BYTE_STRING = CBOR.bytes(new byte[0]);

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
     * This method parses a {@code DSSDocument} and returns a {@code CBORValue},
     * representing the CBOR object structure
     *
     * @param document {@link DSSDocument} to parse
     * @return {@link CBORValue}
     * @throws CBORDecodeException if an error occurs on document parsing
     */
    public static CBORValue parseCbor(DSSDocument document) throws CBORDecodeException {
        try (InputStream is = document.openStream()) {
            return CBORDecoder.decode(is);
        } catch (IOException e) {
            throw new DSSException(String.format("Unable to read document with name '%s' : %s", document.getName(), e.getMessage()), e);
        }
    }

    /**
     * This method parses a byte array and returns a {@code CBORValue},
     * representing the CBOR object structure
     *
     * @param bytes byte array to parse
     * @return {@link CBORValue}
     */
    public static CBORValue parseCbor(byte[] bytes) {
        try {
            return CBORDecoder.decode(bytes);
        } catch (CBORDecodeException e) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Error on parsing binaries: {}", Utils.toBase64(bytes));
            }
            throw new DSSException(String.format("Unable to parse binaries : %s. More detail in debug mode.", e.getMessage()), e);
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
        return CBORDecoder.isCbor(inputStream);
    }

    /**
     * Serialized a given CBOR object to a byte array
     *
     * @param cborObject {@link CBORObject} to be serialized
     * @return serialized byte array
     * @deprecated since DSS 6.6. Use {@link #serializeCbor(CBORValue)} instead.
     */
    @Deprecated
    public static byte[] serializeCborObject(CBORObject cborObject) {
        if (cborObject != null) {
            return serializeCbor(cborObject.toCBORValue());
        }
        return null;
    }

    /**
     * Serialized a given CBOR value to a byte array
     *
     * @param cborValue {@link CBORValue} to be serialized
     * @return serialized byte array
     */
    public static byte[] serializeCbor(CBORValue cborValue) {
        try {
            return cborValue.encodeToBytes();
        } catch (Exception e) {
            throw new DSSException(String.format("Unable to serialize CBOR object : %s", e.getMessage()), e);
        }
    }

    /**
     * Returns a CBOR Byte String wrapped incorporation of the {@code cborObject}
     *
     * @param cborObject {@link CBORObject} to serialized and incorporate into CBOR Byte String type
     * @return {@link CBORByteString}
     * @deprecated since DSS 6.6. Use {@link CBOR#bytes(byte[])} from {@link #serializeCbor(CBORValue)}.
     */
    @Deprecated
    public static CBORByteString toCborBtsrWrapped(CBORObject cborObject) {
        return new CBORByteString(serializeCbor(cborObject.toCBORValue()));
    }

    /**
     * Returns a CBOR Byte String wrapped incorporation of the {@code cborObject}, which also includes the #6.24 tag
     *
     * @param cborObject {@link CBORObject} to serialized and incorporate into CBOR Byte String type
     * @return {@link CBORByteString}
     * @deprecated since DSS 6.6. Use {@link CBORTags#encodedCbor(byte[])} from {@link #serializeCbor(CBORValue)}.
     */
    @Deprecated
    public static CBORByteString toCborBtsrWrappedTagged(CBORObject cborObject) {
        return new CBORByteString(CBORTags.encodedCbor(serializeCbor(cborObject.toCBORValue())));
    }

    /**
     * Gets {@code DigestAlgorithm} safely for a given {@code digestAlgoId}
     *
     * @param digestAlgoId {@link Long} IANA COSE Digest Algorithm identifier
     * @return {@link DigestAlgorithm} if supported, null otherwise
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
    public static Set<CBORValue> getSupportedProtectedCriticalHeaders() {
        return supportedCriticalHeaders;
    }

    /**
     * Checks if the given {@code headerId} is required to be incorporated within 'crit' header, when used
     *
     * @param headerId {@link CBORObject} header key to check
     * @return TRUE if the header is required within 'crit' header when used, FALSE otherwise
     * @deprecated since DSS 6.6. Please use {@link #isRequiredCriticalHeader(CBORValue)} instead.
     */
    @Deprecated
    public static boolean isRequiredCriticalHeader(CBORObject headerId) {
        if (headerId == null) {
            return false;
        }
        return isRequiredCriticalHeader(headerId.toCBORValue());
    }

    /**
     * Checks if the given {@code headerId} is required to be incorporated within 'crit' header, when used
     *
     * @param headerId {@link CBORValue} header key to check
     * @return TRUE if the header is required within 'crit' header when used, FALSE otherwise
     */
    public static boolean isRequiredCriticalHeader(CBORValue headerId) {
        return requiredCriticalHeaders.contains(headerId);
    }

    /**
     * Checks of the object is an instance of a CBOR btsr type
     *
     * @param uHeader {@link CBORObject} to check
     * @return TRUE if the object is an instance of CBOR btsr type, FALSE otherwise
     * @deprecated since DSS 6.6. Use {@link CBORValue#isByteString()}
     */
    @Deprecated
    public static boolean isCborByteStringWrappedFormat(CBORObject uHeader) {
        return uHeader.isByteString();
    }

    /**
     * Checks if the all components are CBOR byte string encoded
     *
     * @param uHeaders {@link CBORArray} to check
     * @return TRUE if all the components are CBOR byte string encoded, FALSE otherwise
     * @deprecated since DSS 6.6. Use {@link #areAllCborBtsrComponents(CBORValue)} instead.
     */
    @Deprecated
    public static boolean areAllCborBtsrComponents(CBORArray uHeaders) {
        if (uHeaders != null) {
            return areAllCborBtsrComponents(uHeaders.toCBORValue());
        }
        return true;
    }

    /**
     * Checks if the all components are CBOR byte string encoded
     *
     * @param uHeaders {@link CBORValue} to check
     * @return TRUE if all the components are CBOR byte string encoded, FALSE otherwise
     */
    public static boolean areAllCborBtsrComponents(CBORValue uHeaders) {
        if (uHeaders != null && uHeaders.isArray() && uHeaders.size() != 0) {
            for (CBORValue component : uHeaders.getElements()) {
                if (!component.isByteString()) {
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
     * @deprecated since DSS 6.6. Use {@link #parseUHeadersEntry(CBORValue)}.
     */
    @Deprecated
    public static CBORMap parseUHeadersEntry(CBORObject uHeadersEntry) {
        if (uHeadersEntry != null) {
            return new CBORMap(parseUHeadersEntry(uHeadersEntry.toCBORValue()));
        }
        return null;
    }

    /**
     * This method parses a {@code CBORObject} representing a component of 'uHeaders' unsigned header parameter,
     * returning a value of the entry in the unified form {@code CBORMap}
     *
     * @param uHeadersEntry {@link CBORValue} to parse
     * @return {@link CBORValue} representing a CBOR map if parsing is successful, NULL otherwise
     */
    public static CBORValue parseUHeadersEntry(CBORValue uHeadersEntry) {
        if (uHeadersEntry.isByteString()) {
            LOG.trace("CBOR Byte String encoded 'uHeader' component found. Parse to CBORMap.");
            byte[] componentSerialized = uHeadersEntry.asBytes();
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
        if (uHeadersEntry.size() != 1) {
            LOG.warn("Only one entry is allowed within an 'uHeaders' component! Entry is skipped.");
            return null;
        }
        return uHeadersEntry;
    }

    /**
     * Generates a CBOR 'full-date' object for the {@code Date}
     *
     * @param date {@link Date}
     * @return {@link CBORValue}
     * @deprecated since DSS 6.6. Please use {@link CBORTags#fullDate(Date)} instead.
     */
    @Deprecated
    public static CBORValue toFullDate(Date date) {
        if (date == null) {
            return null;
        }
        String dateString = DSSUtils.formatDateToISO8601(date);
        return CBOR.tag(CBOR_FULL_DATE_TAG, CBOR.text(dateString));
    }

    /**
     * Obtains a CBOR object represented by a NumericDate and returns the resulted {@code Date}
     *
     * @param cborObject {@link CBORObject}
     * @return {@link Date}
     * @deprecated since DSS 6.6. Please use {@link #fromNumericDate(CBORValue)} instead.
     */
    @Deprecated
    public static Date fromNumericDate(CBORObject cborObject) {
        if (cborObject == null) {
            return null;
        }
        return fromNumericDate(cborObject.toCBORValue());
    }

    /**
     * Obtains a CBOR object represented by a NumericDate and returns the resulted {@code Date}
     *
     * @param cborValue {@link CBORValue}
     * @return {@link Date}
     */
    public static Date fromNumericDate(CBORValue cborValue) {
        if (cborValue == null) {
            return null;
        }
        long timeValueInMilliseconds;
        if (cborValue.isInteger()) {
            timeValueInMilliseconds = DSSUtils.getTimeValueInMilliseconds(cborValue.asInteger().longValue());
        } else if (cborValue.isFloatingPoint()) {
            timeValueInMilliseconds = DSSUtils.getTimeValueInMilliseconds(cborValue.asDouble());
        } else {
            LOG.warn("NumericDate is expected. Obtained value : {}", cborValue);
            return null;
        }
        return DSSUtils.getDateFromMilliseconds(timeValueInMilliseconds);
    }

    /**
     * Creates a formatted string from the supplied date.
     * The date/time is encoded according to RFC 3339 with second precision.
     * Fractional seconds are omitted to preserve the existing DSS date
     * serialization behavior.
     *
     * @param date {@link Date} to encode
     * @return the RFC 3339 date/time string
     */
    public static String formatToTDate(final Date date) {
        if (date == null) {
            return "N/A";
        }

        Instant instant = date.toInstant().truncatedTo(ChronoUnit.SECONDS);
        return DateTimeFormatter.ISO_INSTANT.format(instant);
    }

    /**
     * Checks whether a date string value is a valid RFC 3339 date/time.
     * NOTE: This method is different from {@link DSSUtils#isRFCDate(String)},
     * as it also handles strings with fractional seconds, as opposed to the
     * former method.
     *
     * @param dateString {@link String} the date to check
     * @return {@code true} if the string is a valid RFC 3339 date/time,
     *     {@code false} otherwise
     */
    public static boolean isTDate(final String dateString) {
        if (dateString == null) {
            return false;
        }

        try {
            Instant.parse(dateString);
            return true;
        } catch (DateTimeParseException e) {
            return false;
        }
    }

    /**
     * Parses a date string value to a {@link Date}.
     * NOTE: This method is different from {@link DSSUtils#parseRFCDate(String)},
     * as it also handles strings with milliseconds, as opposite to the former method.
     *
     * @param dateString {@link String} the date to parse
     * @return {@link Date}
     */
    public static Date parseTDate(final String dateString) {
        if (dateString == null) {
            return null;
        }

        try {
            Instant instant = Instant.parse(dateString);
            return Date.from(instant);
        } catch (DateTimeParseException e) {
            String errorMessage = "Invalid RFC 3339 date/time : {}";
            if (LOG.isDebugEnabled()) {
                LOG.warn(errorMessage, e.getMessage(), e);
            } else {
                LOG.warn(errorMessage, e.getMessage());
            }
            return null;
        }
    }

    /**
     * Obtains a String extracted from a uri encoded CBOR tagged value #6.32(tstr)
     *
     * @param cborValue {@link CBORValue}
     * @return {@link String}
     */
    public static String fromUri(CBORValue cborValue) {
        if (cborValue == null) {
            return null;
        }
        if (cborValue.isTag() && cborValue.getTag().longValue() == 32) {
            return cborValue.getTaggedValue().asString();

        } else if (cborValue.isTextString()) {
            LOG.warn("uri encoded (#6.32(tstr)) CBOR value is expected. Obtained String : {}", cborValue);
            return cborValue.asString(); // TODO : legacy handling (6.5.1, 6.6). Remove ?
        }
        LOG.warn("uri encoded (#6.32(tstr)) CBOR value is expected. Obtained value : {}", cborValue);
        return null;
    }

}
