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

import eu.europa.ec.digit.cddl4j.cbor.CBORValue;

import java.util.List;
import java.util.Map;

/**
 * This interface represents a wrapper for CBOR objects
 *
 * @deprecated since DSS 6.6. Switch to {@link eu.europa.ec.digit.cddl4j.cbor.CBORValue} instead.
 */
@Deprecated
public interface CBORObject {

    /**
     * Returns whether the object is tagged
     *
     * @return TRUE if the object has a Tag, FALSE otherwise
     */
    boolean isTagged();

    /**
     * Gets associated CBOR Tag, when present
     *
     * @return {@link CBORTag}
     */
    CBORTag getTag();

    /**
     * Sets the tag tag for the current CBOR Object
     *
     * @param tag long tag of the tag
     */
    void setTag(long tag);

    /**
     * Returns a wrapped implementation of the CBOR value
     *
     * @return {@link CBORValue}
     */
    CBORValue toCBORValue();

    /**
     * Gets the current value or tagged value, if tagged
     *
     * @return {@link CBORValue}
     */
    CBORValue getCBORValue();

    /**
     * Returns whether the current CBOR object is of UnsignedInteger type
     *
     * @return TRUE if the current CBOR object is of UnsignedInteger type, FALSE otherwise
     */
    boolean isUnsignedInteger();

    /**
     * Returns whether the current CBOR object is of NegativeInteger type
     *
     * @return TRUE if the current CBOR object is of NegativeInteger type, FALSE otherwise
     */
    boolean isNegativeInteger();

    /**
     * Returns whether the current CBOR object is of Special type categorized by an additional type
     * as a floating point number (additional information 25, 26, or 27).
     *
     * @return TRUE if the current CBOR object is of Special floating point number type, FALSE otherwise
     */
    boolean isFloatingPointNumber();

    /**
     * Returns whether the current CBOR object is of ByteString type
     *
     * @return TRUE if the current CBOR object is of ByteString type, FALSE otherwise
     */
    boolean isByteString();

    /**
     * Returns whether the current CBOR object is of UnicodeString type
     *
     * @return TRUE if the current CBOR object is of UnicodeString type, FALSE otherwise
     */
    boolean isUnicodeString();

    /**
     * Returns whether the current CBOR object is of Boolean type
     *
     * @return TRUE if the current CBOR object is of Boolean type, FALSE otherwise
     */
    boolean isBoolean();

    /**
     * Returns whether the current CBOR object is of Null type
     *
     * @return TRUE if the current CBOR object is of Null type, FALSE otherwise
     */
    boolean isNull();

    /**
     * Returns whether the current CBOR object is of Map type
     *
     * @return TRUE if the current CBOR object is of Map type, FALSE otherwise
     */
    boolean isMap();

    /**
     * Returns whether the current CBOR object is of Array type
     *
     * @return TRUE if the current CBOR object is of Array type, FALSE otherwise
     */
    boolean isArray();

    /**
     * Returns a {@code Long} value of the object, if supported
     *
     * @return {@link Long}
     */
    Long getValueAsLong();

    /**
     * Returns a {@code Double} value of the object, if supported
     *
     * @return {@link Double}
     */
    Double getValueAsDouble();

    /**
     * Returns a {@code String} value of the object, if supported
     *
     * @return {@link String}
     */
    String getValueAsString();

    /**
     * Returns a {@code Boolean} value of the object, if supported
     *
     * @return {@link Boolean}
     */
    Boolean getValueAsBoolean();

    /**
     * Returns a byte array value
     *
     * @return byte array
     */
    byte[] getValueAsBytes();

    /**
     * Returns a current object value as a map
     *
     * @return a map
     */
    Map<CBORObject, CBORObject> getValueAsMap();

    /**
     * Returns a list of embedded {@code CBORObject}s
     *
     * @return a list of {@link CBORObject}s
     */
    List<CBORObject> getValueAsList();

}
