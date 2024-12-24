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
package eu.europa.esig.dss.xades.reference;

import eu.europa.esig.dss.model.DSSException;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.signature.XMLSignatureInput;
import org.w3c.dom.Node;

import java.io.IOException;

/**
 * Represents an {@code XMLSignatureInput} wrapper
 *
 */
public class DSSTransformOutput {

    /** The cached XMLSignatureInput */
    private final XMLSignatureInput xmlSignatureInput;

    /**
     * Default constructor to instantiate object from XMLSignatureInput
     *
     * @param xmlSignatureInput {@link XMLSignatureInput}
     */
    public DSSTransformOutput(XMLSignatureInput xmlSignatureInput) {
        this.xmlSignatureInput = xmlSignatureInput;
    }

    /**
     * Instantiates the object from a {@code Node}
     *
     * @param node {@link Node}
     */
    public DSSTransformOutput(Node node) {
        this(new XMLSignatureInput(node));
    }

    /**
     * Returns an {@code XMLSignatureInput}
     *
     * @return {@link XMLSignatureInput}
     */
    protected XMLSignatureInput getXmlSignatureInput() {
        return xmlSignatureInput;
    }

    /**
     * Returns bytes after performing transforms
     *
     * @return byte array
     */
    public byte[] getBytes() {
        try {
            return xmlSignatureInput.getBytes();
        } catch (IOException | XMLSecurityException e) {
            throw new DSSException(String.format("Cannot extract Transform output bytes. Reason : [%s]", e.getMessage()), e);
        }
    }

}
