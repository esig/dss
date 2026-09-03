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

import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * An abstract implementation of a CBOR object wrapper
 *
 */
public abstract class AbstractCBORObject implements CBORObject {

    /** A CBOR object implementation */
    protected CBORValue value;

    /**
     * Creates a new CBOR object from the given {@code value}
     *
     * @param value {@link CBORValue}
     */
    protected AbstractCBORObject(final CBORValue value) {
        this.value = value;
    }

    @Override
    public boolean isTagged() {
        return value.isTag();
    }

    @Override
    public CBORTag getTag() {
        if (value.isTag()) {
            return new CBORTag(value);
        }
        return null;
    }

    @Override
    public void setTag(long tag) {
        this.value = CBOR.tag(tag, getCBORValue());
    }

    @Override
    public CBORValue toCBORValue() {
        return value;
    }

    /**
     * Checks if the value is integer
     *
     * @return TRUE if the value if a CBOR integer, FALSE otherwise
     */
    protected boolean isInteger() {
        CBORValue cborValue = getCBORValue();
        return cborValue.isInteger();
    }

    @Override
    public boolean isUnsignedInteger() {
        CBORValue cborValue = getCBORValue();
        return cborValue.isInteger() && cborValue.asInteger().signum() >= 0;
    }

    @Override
    public boolean isNegativeInteger() {
        CBORValue cborValue = getCBORValue();
        return cborValue.isInteger() && cborValue.asInteger().signum() < 0;
    }

    @Override
    public boolean isFloatingPointNumber() {
        CBORValue cborValue = getCBORValue();
        return cborValue.isFloatingPoint();
    }

    @Override
    public boolean isByteString() {
        CBORValue cborValue = getCBORValue();
        return cborValue.isByteString();
    }

    @Override
    public boolean isUnicodeString() {
        CBORValue cborValue = getCBORValue();
        return cborValue.isTextString();
    }

    @Override
    public boolean isBoolean() {
        CBORValue cborValue = getCBORValue();
        return cborValue.isBoolean();
    }

    @Override
    public boolean isNull() {
        CBORValue cborValue = getCBORValue();
        return cborValue.isNull();
    }

    @Override
    public boolean isMap() {
        CBORValue cborValue = getCBORValue();
        return cborValue.isMap();
    }

    @Override
    public boolean isArray() {
        CBORValue cborValue = getCBORValue();
        return cborValue.isArray();
    }

    @Override
    public CBORValue getCBORValue() {
        if (isTagged()) {
            return value.getTaggedValue();
        }
        return value;
    }

    @Override
    public Long getValueAsLong() {
        return null;
    }

    @Override
    public Double getValueAsDouble() {
        return null;
    }

    @Override
    public String getValueAsString() {
        return null;
    }

    @Override
    public Boolean getValueAsBoolean() {
        return null;
    }

    @Override
    public byte[] getValueAsBytes() {
        return null;
    }

    @Override
    public Map<CBORObject, CBORObject> getValueAsMap() {
        return null;
    }

    @Override
    public List<CBORObject> getValueAsList() {
        return null;
    }

    /**
     * Checks whether the CBOR value is of {@code type}
     *
     * @param value {@link CBORValue} to verify
     * @param type {@link CBORType}
     * @return provided {@link CBORValue}, if the check passes
     */
    protected static CBORValue requireTypeOf(CBORValue value, CBORType type) {
        CBORValue embeddedValue = value;
        if (value.isTag()) {
            if (CBORType.TAG == type) {
                return value;
            }
            embeddedValue = value.getTaggedValue();
        }
        if (type != embeddedValue.getType()) {
            throw new IllegalArgumentException(String.format("CBOR %s is expected!", type));
        }
        return value;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        AbstractCBORObject that = (AbstractCBORObject) o;
        return Objects.equals(value, that.value);
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(value);
    }

    @Override
    public String toString() {
        return value.toString();
    }

}
