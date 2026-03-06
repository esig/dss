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
package eu.europa.esig.lote.xml;

import eu.europa.esig.dss.jaxb.common.XSDAbstractUtils;
import eu.europa.esig.lote.jaxb.ObjectFactory;
import eu.europa.esig.xmldsig.XmlDSigUtils;
import jakarta.xml.bind.JAXBContext;
import jakarta.xml.bind.JAXBException;

import javax.xml.transform.Source;
import javax.xml.transform.stream.StreamSource;
import java.util.List;

/**
 * ETSI TS 119 602 List of Trusted Entities XML Utils
 *
 */
public class LOTEUtils extends XSDAbstractUtils {

    /** The Object Factory to use */
    public static final ObjectFactory OBJECT_FACTORY = new ObjectFactory();

    public static final String LOTE_SCHEMA_LOCATION = "/xsd/1960201_xsd_schema.xsd";
    public static final String LOTE_SIE_SCHEMA_LOCATION = "/xsd/1960201_xsd_schema_sie.xsd";
    public static final String LOTE_TIE_SCHEMA_LOCATION = "/xsd/1960201_xsd_schema_tie.xsd";

    /** Singleton */
    private static LOTEUtils singleton;

    /** JAXBContext */
    private JAXBContext jc;

    /**
     * Empty constructor
     */
    private LOTEUtils() {
        // empty
    }

    /**
     * Returns instance of {@code LOTEUtils}
     *
     * @return {@link LOTEUtils}
     */
    public static LOTEUtils getInstance() {
        if (singleton == null) {
            singleton = new LOTEUtils();
        }
        return singleton;
    }

    @Override
    public JAXBContext getJAXBContext() throws JAXBException {
        if (jc == null) {
            jc = JAXBContext.newInstance(ObjectFactory.class, eu.europa.esig.xmldsig.jaxb.ObjectFactory.class,
                    eu.europa.esig.lote.jaxb.sie.ObjectFactory.class,
                    eu.europa.esig.lote.jaxb.tie.ObjectFactory.class);
        }
        return jc;
    }

    @Override
    public List<Source> getXSDSources() {
        List<Source> xsdSources = XmlDSigUtils.getInstance().getXSDSources();
        xsdSources.add(new StreamSource(LOTEUtils.class.getResourceAsStream(LOTE_SCHEMA_LOCATION)));
        xsdSources.add(new StreamSource(LOTEUtils.class.getResourceAsStream(LOTE_SIE_SCHEMA_LOCATION)));
        xsdSources.add(new StreamSource(LOTEUtils.class.getResourceAsStream(LOTE_TIE_SCHEMA_LOCATION)));
        return xsdSources;
    }

}
