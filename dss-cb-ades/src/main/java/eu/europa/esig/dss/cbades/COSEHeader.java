package eu.europa.esig.dss.cbades;

import eu.europa.ec.digit.cddl4j.cbor.CBOR;
import eu.europa.ec.digit.cddl4j.cbor.CBORType;
import eu.europa.ec.digit.cddl4j.cbor.CBORValue;
import eu.europa.esig.dss.cbades.cbor.CBORUtils;
import eu.europa.esig.dss.spi.exception.IllegalInputException;

import java.util.Objects;

/**
 * Abstract implementation of a COSE header (used to represent a protected and unprotected COSE headers)
 *
 */
public abstract class COSEHeader {

    /** CBOR value of the header */
    private final CBORValue value;

    /**
     * Constructor to instantiate COSE header with an empty map value
     */
    protected COSEHeader() {
        this.value = CBOR.map().value();
    }

    /**
     * Constructor to instantiate COSE header from CBOR encoded bytes
     *
     * @param encoded byte array containing the CBOR content
     */
    protected COSEHeader(byte[] encoded) {
        if (encoded.length == 0) {
            this.value = CBOR.map().value();
            return;
        }

        CBORValue value = CBORUtils.parseCbor(encoded);
        if (value.getType() != CBORType.MAP) {
            throw new IllegalInputException("COSE header must be a CBOR map");
        }

        this.value = value;
    }

    /**
     * Constructor to instantiate CBOR header from a CBOR value
     *
     * @param value {@link CBORValue}
     */
    protected COSEHeader(CBORValue value) {
        Objects.requireNonNull(value, "COSE header value must not be null");
        this.value = value;
    }

    /**
     * Gets the CBOR value, representing the complete COSE header map
     *
     * @return {@link CBORValue}
     */
    public CBORValue getValue() {
        return value;
    }

    /**
     * Gets whether the header is empty
     *
     * @return TRUE if the header is empty, FALSE otherwise
     */
    public boolean isEmpty() {
        return value == null || value.size() == 0;
    }

    /**
     * Gets the header parameter for the given {@code key}, when present
     *
     * @param key {@link CBORValue} to get the associated header parameter for
     * @return {@link CBORValue} header parameter if present, null otherwise
     */
    public CBORValue getHeader(CBORValue key) {
        return getValue().get(key);
    }

    /**
     * Puts a header parameter with the given {@code key} and {@code value}
     *
     * @param key {@link CBORValue}
     * @param value {@link CBORValue}
     */
    public void put(CBORValue key, Object value) {
        this.value.editMap().put(key, value);
    }

    /**
     * Gets the size of the COSE header (number of embedded parameters)
     *
     * @return size of the COSE header
     */
    public int getSize() {
        return value.size();
    }

}
