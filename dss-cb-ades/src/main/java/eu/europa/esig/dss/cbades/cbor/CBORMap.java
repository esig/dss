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
import eu.europa.ec.digit.cddl4j.cbor.CBORType;
import eu.europa.ec.digit.cddl4j.cbor.CBORValue;
import eu.europa.esig.dss.spi.exception.IllegalInputException;
import eu.europa.esig.dss.utils.Utils;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * Internal wrapper of a CBOR Map object
 *
 * @deprecated since DSS 6.6. Switch to {@link eu.europa.ec.digit.cddl4j.cbor.CBORValue} instead.
 */
@Deprecated
public class CBORMap extends AbstractCBORObject {

    /** Serialized map */
    private CBORByteString serializedMap;

    /**
     * Constructor to create an empty map
     */
    public CBORMap() {
        super(CBOR.map().value());
    }

    /**
     * Constructor to create a CBORMap from a CBORValue map implementation
     *
     * @param map {@link CBORValue}
     */
    public CBORMap(final CBORValue map) {
        super(requireTypeOf(map, CBORType.MAP));
    }

    /**
     * Creates a CBORMap from a serialized map
     *
     * @param serializedMap {@link CBORByteString} containing an empty or serialized map
     */
    public CBORMap(final CBORByteString serializedMap) {
        this(parseByteStringHeader(serializedMap));
        this.serializedMap = serializedMap;
    }

    private static CBORValue parseByteStringHeader(CBORByteString cborByteString) {
        byte[] valueAsBytes = cborByteString.getValueAsBytes();
        if (Utils.isArrayEmpty(valueAsBytes)) {
            return CBOR.map().value();
        }
        try {
            return CBOR.decodeFromBytes(valueAsBytes);
        } catch (Exception e) {
            throw new IllegalInputException(String.format("Unable to parse byte string a Map: %s", e.getMessage()), e);
        }
    }

    /**
     * Returns a serialized value of the protected header map
     *
     * @return {@link CBORByteString}
     */
    public CBORByteString getByteString() {
        if (serializedMap == null) {
            serializedMap = CBORUtils.toCborBtsrWrapped(this);
        }
        return serializedMap;
    }

    /**
     * Checks whether the map contains a header value for the given {@code key}
     *
     * @param key {@link CBORObject} value of the header key
     * @return TRUE if the map contains the header for the given key, FALSE otherwise
     */
    public boolean containsKey(CBORObject key) {
        return toCBORValue().getKeys().contains(CBORValueFactory.toCBORValue(key));
    }

    /**
     * Returns header value for the given key
     *
     * @param key {@link Object} value of a key to get a map value for
     * @return {@link CBORObject}
     */
    public CBORObject getHeader(Object key) {
        CBORValue cborValue = getCBORValue().get(CBORValueFactory.toCBORValue(key));
        if (cborValue != null) {
            return CBORObjectFactory.toCBORObject(cborValue);
        }
        return null;
    }

    @Override
    public Map<CBORObject, CBORObject> getValueAsMap() {
        final Map<CBORObject, CBORObject> result = new HashMap<>();
        for (CBORObject key : getKeys()) {
            CBORObject cborValue = getHeader(key);
            result.put(key, cborValue);
        }
        return result;
    }

    /**
     * Returns a list of all keys from the current CBOR Map
     *
     * @return a set of {@code CBORObject} keys
     */
    public Set<CBORObject> getKeys() {
        final Set<CBORObject> keys = new HashSet<>();
        for (CBORValue key : getCBORValue().getKeys()) {
            CBORObject keyObject = CBORObjectFactory.toCBORObject(key);
            keys.add(keyObject);
        }
        return keys;
    }

    /**
     * Gets a header value as {@code Boolean}. Returns NULL if the header is not found for the given key or
     * its value is not of Boolean type
     *
     * @param key {@link Object} value of the key
     * @return {@link Boolean} value of the header
     */
    public Boolean getAsBoolean(Object key) {
        CBORObject cborObject = getHeader(CBORObjectFactory.toCBORObject(key));
        if (cborObject != null && (cborObject.isBoolean())) {
            return cborObject.getValueAsBoolean();
        }
        return null;
    }

    /**
     * Gets a header value as {@code Long}. Returns NULL if the header is not found for the given key or
     * its value is not of UnsignedInteger or NegativeInteger type
     *
     * @param key {@link Object} value of the key
     * @return {@link Long} value of the header
     */
    public Long getAsLong(Object key) {
        CBORObject cborObject = getHeader(CBORObjectFactory.toCBORObject(key));
        if (cborObject != null && (cborObject.isUnsignedInteger() || cborObject.isNegativeInteger())) {
            return cborObject.getValueAsLong();
        }
        return null;
    }

    /**
     * Gets a header value as {@code Double}. Returns NULL if the header is not found for the given key or
     * its value is not of Special type with additional information 25, 26, or 27.
     *
     * @param key {@link Object} value of the key
     * @return {@link Double} value of the header
     */
    public Double getAsDouble(Object key) {
        CBORObject cborObject = getHeader(CBORObjectFactory.toCBORObject(key));
        if (cborObject != null && (cborObject.isFloatingPointNumber())) {
            return cborObject.getValueAsDouble();
        }
        return null;
    }

    /**
     * Gets a header value as {@code String}. Returns NULL if the header is not found for the given key or
     * its value is not of UnicodeString type
     *
     * @param key {@link Object} value of the key
     * @return {@link String} value of the header
     */
    public String getAsString(Object key) {
        CBORObject cborObject = getHeader(CBORObjectFactory.toCBORObject(key));
        if (cborObject != null && (cborObject.isUnicodeString())) {
            return cborObject.getValueAsString();
        }
        return null;
    }

    /**
     * Gets a header value as a byte array. Returns NULL if the header is not found for the given key or
     * its value is not of ByteString type
     *
     * @param key {@link Object} value of the key
     * @return a byte array value of the header
     */
    public byte[] getAsBinaries(Object key) {
        CBORObject cborObject = getHeader(CBORObjectFactory.toCBORObject(key));
        if (cborObject != null && cborObject.isByteString()) {
            return cborObject.getValueAsBytes();
        }
        return null;
    }

    /**
     * Gets a header value as {@code CBORArray}. Returns NULL if the header is not found for the given key or
     * its value is not of Array type
     *
     * @param key {@link Object} value of the key
     * @return {@link CBORArray} value of the header
     */
    public CBORArray getAsArray(Object key) {
        CBORObject cborObject = getHeader(CBORObjectFactory.toCBORObject(key));
        if (cborObject != null && cborObject.isArray()) {
            return ((CBORArray) cborObject);
        }
        return null;
    }

    /**
     * Gets a header value as {@code CBORMap}. Returns NULL if the header is not found for the given key or
     * its value is not of Map type
     *
     * @param key {@link Object} value of the key
     * @return {@link CBORMap} value of the header
     */
    public CBORMap getAsMap(Object key) {
        CBORObject cborObject = getHeader(CBORObjectFactory.toCBORObject(key));
        if (cborObject != null && cborObject.isMap()) {
            return ((CBORMap) cborObject);
        }
        return null;
    }

    /**
     * Adds a new entry to the map with a given {@code key} and {@code value}.
     * Transforms the {@code value} to the required type (if supported)
     *
     * @param key {@link Object} value of the key
     * @param cborValue {@link Object} representing the header value
     */
    public void put(Object key, Object cborValue) {
        getCBORValue().editMap().put(CBORValueFactory.toCBORValue(key), CBORValueFactory.toCBORValue(cborValue));
        clearSerializedBytes();
    }

    /**
     * Removes entry with {@code key}
     *
     * @param key {@link Object} value of the key
     */
    public void remove(Object key) {
        getCBORValue().editMap().remove(CBORValueFactory.toCBORValue(key));
        clearSerializedBytes();
    }

    private void clearSerializedBytes() {
        serializedMap = null;
    }

    /**
     * Adds all entries from the {@code map}
     *
     * @param inputMap {@link Map} to add values from
     */
    public void putAll(Map<?, ?> inputMap) {
        inputMap.forEach(this::put);
        clearSerializedBytes();
    }

    /**
     * Checks if the current map object is empty
     *
     * @return TRUE if the map is empty, FALSE otherwise
     */
    public boolean isEmpty() {
        return getSize() == 0;
    }

    /**
     * Returns size of the map
     *
     * @return size of the map
     */
    public int getSize() {
        return getCBORValue().size();
    }

}
