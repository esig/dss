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
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.spi.validation.identifier.SignatureAttributeIdentifier;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;

/**
 * Represents an identifier of a CB-AdES Attribute (or 'uHeaders' component)
 *
 */
public class CBAdESAttributeIdentifier extends SignatureAttributeIdentifier {

    private static final long serialVersionUID = -1421464221784448021L;

    /**
     * Default constructor
     *
     * @param data byte array
     */
    CBAdESAttributeIdentifier(byte[] data) {
        super(data);
    }

    /**
     * Builds a CB-AdES Attribute identifier
     *
     * @param headerId {@link CBORObject} id of the 'uHeaders' component
     * @param value {@link CBORObject} represent the value of the 'uHeaders' component
     * @return {@link CBAdESAttributeIdentifier}
     * @deprecated since DSS 6.6. Use {@link #build(CBORValue, CBORValue)}.
     */
    @Deprecated
    public static CBAdESAttributeIdentifier build(CBORObject headerId, CBORObject value) {
        return build(headerId.toCBORValue(), value.toCBORValue());
    }

    /**
     * Builds a CB-AdES Attribute identifier
     *
     * @param headerId {@link CBORValue} id of the 'uHeaders' component
     * @param value {@link CBORValue} represent the value of the 'uHeaders' component
     * @return {@link CBAdESAttributeIdentifier}
     */
    public static CBAdESAttributeIdentifier build(CBORValue headerId, CBORValue value) {
        return build(headerId, value, null);
    }

    /**
     * Builds the identifier for an 'uHeaders' component
     *
     * @param headerId {@link CBORObject} id of the 'uHeaders' component
     * @param value {@link CBORObject} represent the value of the 'uHeaders' component
     * @param order the order of the component within the 'uHeaders' array
     * @return {@link CBAdESAttributeIdentifier}
     * @deprecated since DSS 6.6. Use {@link #build(CBORValue, CBORValue, Integer)}.
     */
    @Deprecated
    public static CBAdESAttributeIdentifier build(CBORObject headerId, CBORObject value, Integer order) {
        return build(headerId.toCBORValue(), value.toCBORValue(), order);
    }

    /**
     * Builds the identifier for an 'uHeaders' component
     *
     * @param headerId {@link CBORValue} id of the 'uHeaders' component
     * @param value {@link CBORValue} represent the value of the 'uHeaders' component
     * @param order the order of the component within the 'uHeaders' array
     * @return {@link CBAdESAttributeIdentifier}
     */
    public static CBAdESAttributeIdentifier build(CBORValue headerId, CBORValue value, Integer order) {
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream(); DataOutputStream dos = new DataOutputStream(baos)) {
            if (headerId != null) {
                if (headerId.isInteger()) {
                    dos.writeLong(headerId.asInteger().longValue());
                } else if (headerId.isTextString()) {
                    dos.writeChars(headerId.asString());
                } else {
                    throw new UnsupportedOperationException(String.format(
                            "Unsupported attribute header key of type '%s'", headerId.getClass().getSimpleName()));
                }
            }
            if (value != null) {
                dos.writeChars(value.toString());
            }
            if (order != null) {
                dos.writeInt(order);
            }
            dos.flush();

            return new CBAdESAttributeIdentifier(baos.toByteArray());

        } catch (IOException e) {
            throw new DSSException(String.format("Unable to build a CBAdESAttributeIdentifier. Reason : %s", e.getMessage()), e);
        }
    }

}
