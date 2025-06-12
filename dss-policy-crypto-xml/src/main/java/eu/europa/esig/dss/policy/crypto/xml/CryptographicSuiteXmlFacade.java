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
package eu.europa.esig.dss.policy.crypto.xml;

import eu.europa.esig.dss.jaxb.common.AbstractJaxbFacade;
import eu.europa.esig.dss.model.policy.CryptographicSuite;
import eu.europa.esig.dss.policy.crypto.xml.jaxb.SecuritySuitabilityPolicyType;
import jakarta.xml.bind.JAXBContext;
import jakarta.xml.bind.JAXBElement;
import jakarta.xml.bind.JAXBException;
import org.xml.sax.SAXException;

import javax.xml.stream.XMLStreamException;
import javax.xml.validation.Schema;
import java.io.IOException;
import java.io.InputStream;
import java.util.Objects;

/**
 * Performs marshalling/unmarshalling operation for the ETSI TS 119 312/322 XML schema
 *
 */
public class CryptographicSuiteXmlFacade extends AbstractJaxbFacade<SecuritySuitabilityPolicyType> {

    /**
     * Default constructor
     */
    protected CryptographicSuiteXmlFacade() {
        // empty
    }

    /**
     * Initializes a new {@code CryptographicSuitesFacade}
     *
     * @return {@link CryptographicSuiteXmlFacade}
     */
    public static CryptographicSuiteXmlFacade newFacade() {
        return new CryptographicSuiteXmlFacade();
    }

    @Override
    protected JAXBContext getJAXBContext() throws JAXBException {
        return CryptographicSuiteXmlUtils.getInstance().getJAXBContext();
    }

    @Override
    protected Schema getSchema() throws SAXException {
        return CryptographicSuiteXmlUtils.getInstance().getSchema();
    }

    @Override
    protected JAXBElement<SecuritySuitabilityPolicyType> wrap(SecuritySuitabilityPolicyType jaxbObject) {
        return CryptographicSuiteXmlUtils.OBJECT_FACTORY.createSecuritySuitabilityPolicy(jaxbObject);
    }

    /**
     * Gets the cryptographic suite from the {@code InputStream}
     *
     * @param is {@link InputStream}
     * @return {@link CryptographicSuite}
     * @throws JAXBException if {@link JAXBException} occurs
     * @throws XMLStreamException if {@link XMLStreamException} occurs
     * @throws IOException if {@link IOException} occurs
     * @throws SAXException if {@link SAXException} occurs
     */
    public CryptographicSuite getCryptographicSuite(InputStream is) throws JAXBException, XMLStreamException, IOException, SAXException {
        Objects.requireNonNull(is, "The provided cryptographic suite is null");
        return new CryptographicSuiteXmlWrapper(unmarshall(is));
    }

}
