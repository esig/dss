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
package eu.europa.esig.dss.cades.validation;

import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.spi.validation.identifier.SignatureAttributeIdentifier;
import org.bouncycastle.asn1.cms.Attribute;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;

/**
 * Represents a unique identifier for an attribute from a CAdES signature
 *
 */
public class CAdESAttributeIdentifier extends SignatureAttributeIdentifier {

    private static final long serialVersionUID = -1244583446667611418L;

    /**
     * Default constructor
     *
     * @param data byte array to compute the identifier
     */
    CAdESAttributeIdentifier(byte[] data) {
        super(data);
    }

    /**
     * Builds the identifier for CAdES attribute
     *
     * @param attribute {@link Attribute}
     * @param order position of the attribute within signature properties
     * @return {@link CAdESAttributeIdentifier}
     */
    public static CAdESAttributeIdentifier build(Attribute attribute, Integer order) {
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream(); DataOutputStream dos = new DataOutputStream(baos)) {
            if (attribute != null) {
                // attribute identifier + value
                dos.write(attribute.getEncoded());
            }
            if (order != null) {
                dos.write(order);
            }
            dos.flush();

            return new CAdESAttributeIdentifier(baos.toByteArray());

        } catch (IOException e) {
            throw new DSSException(String.format("Unable to build a CAdESAttributeIdentifier. Reason : %s", e.getMessage()), e);
        }
    }

}
