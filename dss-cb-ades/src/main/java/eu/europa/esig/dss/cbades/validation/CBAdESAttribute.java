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
package eu.europa.esig.dss.cbades.validation;

import eu.europa.ec.digit.cddl4j.cbor.CBORValue;
import eu.europa.esig.dss.cbades.cbor.CBORObject;
import eu.europa.esig.dss.spi.validation.SignatureAttribute;

import java.util.Objects;

/**
 * Represents the CB-AdES header
 *
 */
public class CBAdESAttribute implements SignatureAttribute {

    private static final long serialVersionUID = 4718268120160172246L;

    /** Id of the header */
    protected CBORValue headerId;

    /** The header's value */
    protected CBORValue value;

    /** Identifies the instance */
    protected CBAdESAttributeIdentifier identifier;

    /**
     * Default constructor
     *
     * @param headerId {@link CBORObject} header id
     * @param value {@link CBORObject} value
     * @deprecated since DSS 6.6. Use {@link CBAdESAttribute(CBORValue, CBORValue)}.
     */
    @Deprecated
    public CBAdESAttribute(CBORObject headerId, CBORObject value) {
        this(headerId.toCBORValue(), value.toCBORValue());
    }

    /**
     * Default constructor
     *
     * @param headerId {@link CBORValue} header id
     * @param value {@link CBORValue} value
     */
    public CBAdESAttribute(CBORValue headerId, CBORValue value) {
        this.headerId = headerId;
        this.value = value;
    }

    /**
     * Gets the header's id
     *
     * @return {@link CBORValue}
     */
    public CBORValue getHeaderId() {
        return headerId;
    }

    /**
     * Gets the value
     *
     * @return value
     */
    public CBORValue getValue() {
        return value;
    }

    /**
     * Gets the attribute identifier
     *
     * @return {@link CBAdESAttributeIdentifier}
     */
    @Override
    public CBAdESAttributeIdentifier getIdentifier() {
        if (identifier == null) {
            identifier = CBAdESAttributeIdentifier.build(headerId, value);
        }
        return identifier;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        CBAdESAttribute that = (CBAdESAttribute) o;

        return Objects.equals(getIdentifier(), that.getIdentifier());
    }

    @Override
    public int hashCode() {
        return getIdentifier() != null ? getIdentifier().hashCode() : 0;
    }

}
