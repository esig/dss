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
package eu.europa.esig.dss.xades.validation;

import eu.europa.esig.dss.xml.utils.DomUtils;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.spi.validation.identifier.SignatureAttributeIdentifier;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;

/**
 * Represents an identifier of a XAdES Attribute
 */
public class XAdESAttributeIdentifier extends SignatureAttributeIdentifier {

    private static final long serialVersionUID = 178331193990451357L;

    /**
     * Default constructor
     *
     * @param data byte array
     */
    XAdESAttributeIdentifier(byte[] data) {
        super(data);
    }

    /**
     * Builds the {@code XAdESAttributeIdentifier} from the given property {@code Node}
     *
     * @param node {@link Node}
     * @return {@link XAdESAttributeIdentifier}
     */
    public static XAdESAttributeIdentifier build(Node node) {
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream(); DataOutputStream dos = new DataOutputStream(baos)) {
            dos.write(getBinaries(node));
            dos.writeInt(getOrder(node));

            return new XAdESAttributeIdentifier(baos.toByteArray());

        } catch (IOException e) {
            throw new DSSException(String.format("Unable to build a XAdES Attribute Identifier : %s", e.getMessage()), e);
        }
    }

    private static byte[] getBinaries(Node node) {
        return DomUtils.serializeNode(node);
    }

    private static int getOrder(Node node) {
        Node parentNode = node.getParentNode();
        if (parentNode != null) {
            NodeList childNodes = parentNode.getChildNodes();
            for (int ii = 0; ii < childNodes.getLength(); ii++) {
                Node child = childNodes.item(ii);
                if (node == child) {
                    return ii;
                }
            }
        }
        return 0;
    }

}
