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
package eu.europa.esig.dss.xml.common;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

/**
 * This class is used to build a {@code DocumentBuilderFactory}
 *
 */
public class DocumentBuilderFactoryBuilder extends AbstractFactoryBuilder<DocumentBuilderFactory> {

    private static final Logger LOG = LoggerFactory.getLogger(DocumentBuilderFactoryBuilder.class);

    /**
     * Default constructor building a secure pre-configured instance of {@code DocumentBuilderFactoryBuilder}
     */
    protected DocumentBuilderFactoryBuilder() {
        enableFeature("http://xml.org/sax/features/namespaces"); // .setNamespaceAware(true)
        // XInclude is set to "false" by default. Enforcing of the feature value can throw an exception
        // if the implementation does not support the property
        // disableFeature("http://apache.org/xml/features/xinclude"); // .setXIncludeAware(false)
        enableFeature("http://apache.org/xml/features/dom/create-entity-ref-nodes"); // .setExpandEntityReferences(false);
        // disable external entities details :
        // https://www.owasp.org/index.php/XML_External_Entity_(XXE)_Prevention_Cheat_Sheet#Java
        enableFeature("http://apache.org/xml/features/disallow-doctype-decl");
        disableFeature("http://xml.org/sax/features/external-general-entities");
        disableFeature("http://xml.org/sax/features/external-parameter-entities");
        disableFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd");
        // Sonar: XML parsers should not be vulnerable to XXE attacks
        setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
        setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
    }

    /**
     * Instantiates a pre-configured with security features {@code DocumentBuilderFactoryBuilder}
     *
     * @return default {@link DocumentBuilderFactoryBuilder}
     */
    public static DocumentBuilderFactoryBuilder getSecureDocumentBuilderFactoryBuilder() {
        return new DocumentBuilderFactoryBuilder();
    }

    /**
     * Builds the configured {@code DocumentBuilderFactory}
     *
     * @return {@link DocumentBuilderFactory}
     */
    public DocumentBuilderFactory build() {
        DocumentBuilderFactory documentBuilderFactory = instantiateFactory();
        setSecurityFeatures(documentBuilderFactory);
        setSecurityAttributes(documentBuilderFactory);
        return documentBuilderFactory;
    }

    @Override
    protected DocumentBuilderFactory instantiateFactory() {
        return DocumentBuilderFactory.newInstance();
    }

    @Override
    public DocumentBuilderFactoryBuilder enableFeature(String feature) {
        return (DocumentBuilderFactoryBuilder) super.enableFeature(feature);
    }

    @Override
    public DocumentBuilderFactoryBuilder disableFeature(String feature) {
        return (DocumentBuilderFactoryBuilder) super.disableFeature(feature);
    }

    @Override
    public DocumentBuilderFactoryBuilder setAttribute(String attribute, Object value) {
        return (DocumentBuilderFactoryBuilder) super.setAttribute(attribute, value);
    }

    @Override
    public DocumentBuilderFactoryBuilder removeAttribute(String attribute) {
        return (DocumentBuilderFactoryBuilder) super.removeAttribute(attribute);
    }

    @Override
    protected void setSecurityFeature(DocumentBuilderFactory factory, String feature, Boolean value) {
        try {
            factory.setFeature(feature, value);
        } catch (ParserConfigurationException e) {
            String message = String.format("SECURITY : unable to set feature '%s' = '%s' (more details in LOG debug)", feature, value);
            if (LOG.isDebugEnabled()) {
                LOG.warn(message, e);
            } else {
                LOG.warn(message);
            }
        }
    }

    @Override
    protected void setSecurityAttribute(DocumentBuilderFactory factory, String attribute, Object value) {
        try {
            factory.setAttribute(attribute, value);
        } catch (IllegalArgumentException e) {
            String message = String.format("SECURITY : unable to set attribute '%s' = '%s' (more details in LOG debug)", attribute, value);
            if (LOG.isDebugEnabled()) {
                LOG.warn(message, e);
            } else {
                LOG.warn(message);
            }
        }
    }

}
