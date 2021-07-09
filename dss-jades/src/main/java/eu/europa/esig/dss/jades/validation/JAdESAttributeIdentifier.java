/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * 
 * This file is part of the "DSS - Digital Signature Services" project.
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.jades.validation;

import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.SignatureAttributeIdentifier;
import org.jose4j.json.internal.json_simple.JSONValue;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;

/**
 * Represents an identifier of a JAdES Attribute (or 'etsiU' component)
 */
public class JAdESAttributeIdentifier extends SignatureAttributeIdentifier {

    private static final long serialVersionUID = -1421464221784448021L;

    /**
     * Default constructor
     *
     * @param data byte array
     */
    JAdESAttributeIdentifier(byte[] data) {
        super(data);
    }

    /**
     * Builds a JAdES Attribute identifier
     *
     * @param headerName {@link String} name of the 'etsiU' component
     * @param value represent the value of the 'etsiU' component
     * @return {@link JAdESAttributeIdentifier}
     */
    public static JAdESAttributeIdentifier build(String headerName, Object value) {
        return build(headerName, value, null);
    }

    /**
     * Builds the identifier for an 'etsiU' component
     *
     * @param headerName {@link String} name of the 'etsiU' component
     * @param value represent the value of the 'etsiU' component
     * @param order the order of the component within the 'etsiU' array
     * @return {@link JAdESAttributeIdentifier}
     */
    public static JAdESAttributeIdentifier build(String headerName, Object value, Integer order) {
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream(); DataOutputStream dos = new DataOutputStream(baos)) {
            if (Utils.isStringNotEmpty(headerName)) {
                dos.writeChars(headerName);
            }
            if (value != null) {
                dos.writeChars(JSONValue.toJSONString(value));
            }
            if (order != null) {
                dos.writeInt(order);
            }
            dos.flush();

            return new JAdESAttributeIdentifier(baos.toByteArray());

        } catch (IOException e) {
            throw new DSSException(String.format("Unable to build a JAdESAttributeIdentifier. Reason : %s", e.getMessage()), e);
        }
    }

}
