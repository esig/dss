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
package eu.europa.esig.dss.applet.util;

import java.io.InputStream;

import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMResult;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamSource;

import org.w3c.dom.Document;

import eu.europa.esig.dss.XmlDom;

/**
 * TODO
 *
 *
 *
 *
 *
 *
 */
abstract class XsltConverter {

    /**
     * @param xmlDom the xmlDom representing the report
     * @return a DOM XHTML standalone document.
     */
    public Document renderAsHtml(XmlDom xmlDom) {

        TransformerFactory transformerFactory = TransformerFactory.newInstance();
        try {
            final InputStream xslStream = getXsltFileClasspathResource();
            Transformer transformer = transformerFactory.newTransformer(new StreamSource(xslStream));

            final DOMResult domResult = new DOMResult();
            final DOMSource xmlSource = new DOMSource(xmlDom.getRootElement().getOwnerDocument());

            transformer.transform(xmlSource, domResult);

            return (Document) domResult.getNode();
        } catch (TransformerException e) {
            throw new RuntimeException(e);
        }
    }

    abstract InputStream getXsltFileClasspathResource();
}
