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

import eu.europa.esig.dss.jaxb.common.XSDAbstractUtils;
import eu.europa.esig.dss.policy.crypto.xml.jaxb.ObjectFactory;
import eu.europa.esig.xmldsig.XmlDSigUtils;
import jakarta.xml.bind.JAXBContext;
import jakarta.xml.bind.JAXBException;

import javax.xml.transform.Source;
import javax.xml.transform.stream.StreamSource;
import java.util.List;

/**
 * ETSI TS 119 312/322 XML schema utils
 *
 */
public class CryptographicSuiteXmlUtils extends XSDAbstractUtils {

    /** The object factory to use */
    public static final ObjectFactory OBJECT_FACTORY = new ObjectFactory();

    /** The Validation Policy XSD schema location */
    private static final String CRYPTO_SUITES_CATALOGUES_SCHEMA_LOCATION = "/xsd/rfc5698.xsd";

    /** The Validation Policy XSD schema location */
    private static final String CRYPTO_SUITES_ALGOCAT_SCHEMA_LOCATION = "/xsd/19322algocatxmlschema.xsd";

    /** Singleton */
    private static CryptographicSuiteXmlUtils singleton;

    /** Cached JAXBContext */
    private JAXBContext jc;

    /**
     * Empty constructor
     */
    private CryptographicSuiteXmlUtils() {
        // empty
    }

    /**
     * Returns instance of {@code CryptographicSuitesXmlUtils}
     *
     * @return {@link CryptographicSuiteXmlUtils}
     */
    public static CryptographicSuiteXmlUtils getInstance() {
        if (singleton == null) {
            singleton = new CryptographicSuiteXmlUtils();
        }
        return singleton;
    }

    /**
     * Gets the {@code JAXBContext}
     *
     * @return {@link JAXBContext}
     * @throws JAXBException if an exception occurs
     */
    public JAXBContext getJAXBContext() throws JAXBException {
        if (jc == null) {
            jc = JAXBContext.newInstance(ObjectFactory.class, eu.europa.esig.xmldsig.jaxb.ObjectFactory.class,
                    eu.europa.esig.dss.policy.crypto.xml.jaxb.algocat.ObjectFactory.class);
        }
        return jc;
    }

    @Override
    public List<Source> getXSDSources() {
        List<Source> xsdSources = XmlDSigUtils.getInstance().getXSDSources();
        xsdSources.add(new StreamSource(CryptographicSuiteXmlUtils.class.getResourceAsStream(CRYPTO_SUITES_CATALOGUES_SCHEMA_LOCATION)));
        xsdSources.add(new StreamSource(CryptographicSuiteXmlUtils.class.getResourceAsStream(CRYPTO_SUITES_ALGOCAT_SCHEMA_LOCATION)));
        return xsdSources;
    }

}
