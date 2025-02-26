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
package eu.europa.esig.trustedlist;

import eu.europa.esig.dss.jaxb.common.XSDAbstractUtils;
import eu.europa.esig.trustedlist.jaxb.tsl.ObjectFactory;
import eu.europa.esig.xades.XAdESUtils;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.transform.Source;
import javax.xml.transform.stream.StreamSource;
import java.util.List;

/**
 * Trusted Lists Utils for validation against the CID 2015/1505 requirements, ETSI TS 119 612 v2.1.1 XSD schema.
 * Also uses ETSI TS 101 903 XAdES schema, instead of ETSI EN 319 132-1 XSD.
 *
 */
public final class TrustedList211Utils extends XSDAbstractUtils {

    /** The Trusted List TS 119 612 v2.1.1 XSD schema location */
    public static final String TRUSTED_LIST_211_SCHEMA_LOCATION = "/xsd/ts_119612v020101_xsd.xsd";
    public static final String TRUSTED_LIST_SIE_SCHEMA_LOCATION = "/xsd/ts_119612v020101_sie_xsd.xsd";
    public static final String TRUSTED_LIST_ADDITIONALTYPES_SCHEMA_LOCATION = "/xsd/ts_119612v020101_additionaltypes_xsd.xsd";

    /** Singleton */
    private static TrustedList211Utils singleton;

    /** JAXBContext */
    private JAXBContext jc;

    /**
     * Empty constructor
     */
    private TrustedList211Utils() {
        // empty
    }

    /**
     * Returns instance of {@code TrustedList211Utils}
     *
     * @return {@link TrustedList211Utils}
     */
    public static TrustedList211Utils getInstance() {
        if (singleton == null) {
            singleton = new TrustedList211Utils();
        }
        return singleton;
    }

    @Override
    public JAXBContext getJAXBContext() throws JAXBException {
        if (jc == null) {
            jc = JAXBContext.newInstance(ObjectFactory.class, eu.europa.esig.xmldsig.jaxb.ObjectFactory.class,
                    eu.europa.esig.xades.jaxb.xades132.ObjectFactory.class,
                    eu.europa.esig.xades.jaxb.xades141.ObjectFactory.class,
                    eu.europa.esig.trustedlist.jaxb.tslx.ObjectFactory.class,
                    eu.europa.esig.trustedlist.jaxb.ecc.ObjectFactory.class);
        }
        return jc;
    }

    @Override
    public List<Source> getXSDSources() {
        List<Source> xsdSources = XAdESUtils.getInstance().getXSDSources();
        xsdSources.add(new StreamSource(TrustedListUtils.class.getResourceAsStream(TRUSTED_LIST_211_SCHEMA_LOCATION)));
        xsdSources.add(new StreamSource(TrustedListUtils.class.getResourceAsStream(TRUSTED_LIST_SIE_SCHEMA_LOCATION)));
        xsdSources.add(new StreamSource(TrustedListUtils.class.getResourceAsStream(TRUSTED_LIST_ADDITIONALTYPES_SCHEMA_LOCATION)));
        return xsdSources;
    }

}
