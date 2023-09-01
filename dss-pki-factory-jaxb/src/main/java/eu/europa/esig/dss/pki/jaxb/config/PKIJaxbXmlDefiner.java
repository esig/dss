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
package eu.europa.esig.dss.pki.jaxb.config;

import eu.europa.esig.dss.jaxb.common.XmlDefinerUtils;
import eu.europa.esig.dss.pki.jaxb.ObjectFactory;
import org.xml.sax.SAXException;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.transform.Source;
import javax.xml.transform.Templates;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.stream.StreamSource;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;
import java.io.IOException;
import java.io.InputStream;

/**
 * This class is used to provide an XSD schema for a PKI and templates
 *
 */
public final class PKIJaxbXmlDefiner {

    /** The location of PKI XSD */
    private static final String PKI_SCHEMA_LOCATION = "/xsd/PKI.xsd";

    /**
     * Singleton
     */
    private PKIJaxbXmlDefiner() {
        // empty
    }

    /** ObjectFactory instance */
    public static final ObjectFactory OBJECT_FACTORY = new ObjectFactory();

    /** JAXBContext (thread-safe) */
    private static JAXBContext jc;

    /** Schema (thread-safe) */
    private static Schema schema;

    /** SVG Templates (thread-safe) */
    private static Templates svgTemplates;

    /**
     * Gets the JAXB context
     *
     * @return {@link JAXBContext}
     * @throws JAXBException if an exception occurs
     */
    public static JAXBContext getJAXBContext() throws JAXBException {
        if (jc == null) {
            jc = JAXBContext.newInstance(ObjectFactory.class);
        }
        return jc;
    }

    /**
     * Gets the XSD Schema for the PKI
     *
     * @return {@link Schema}
     * @throws IOException if XSD reading exception occurs
     * @throws SAXException if an exception occurs
     */
    public static Schema getSchema() throws IOException, SAXException {
        if (schema == null) {
            try (InputStream inputStream = PKIJaxbXmlDefiner.class.getResourceAsStream(PKI_SCHEMA_LOCATION)) {
                SchemaFactory sf = XmlDefinerUtils.getInstance().getSecureSchemaFactory();
                schema = sf.newSchema(new Source[]{new StreamSource(inputStream)});
            }
        }
        return schema;
    }

    /**
     * Gets the SVG template
     *
     * @return {@link Templates}
     * @throws TransformerConfigurationException if an exception occurs
     * @throws IOException if file reading exception occurs
     */
    public static Templates getSvgTemplates() throws TransformerConfigurationException, IOException {
        if (svgTemplates == null) {
//			svgTemplates = loadTemplates(PKI_XSLT_SVG_LOCATION);
        }
        return svgTemplates;
    }

    private static Templates loadTemplates(String path) throws TransformerConfigurationException, IOException {
        try (InputStream is = PKIJaxbXmlDefiner.class.getResourceAsStream(path)) {
            TransformerFactory transformerFactory = XmlDefinerUtils.getInstance().getSecureTransformerFactory();
            return transformerFactory.newTemplates(new StreamSource(is));
        }
    }

}
