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
package eu.europa.esig.xmlers;

import eu.europa.esig.dss.jaxb.common.XSDAbstractUtils;
import eu.europa.esig.xmlers.jaxb.ObjectFactory;
import jakarta.xml.bind.JAXBContext;
import jakarta.xml.bind.JAXBException;

import javax.xml.transform.Source;
import javax.xml.transform.stream.StreamSource;
import java.util.ArrayList;
import java.util.List;

/**
 * Common XML Evidence Records schema utils
 *
 */
public final class XMLEvidenceRecordUtils extends XSDAbstractUtils {

    /** The Object Factory to use */
    public static final ObjectFactory OBJECT_FACTORY = new ObjectFactory();

    /** The XMLERS XSD schema path */
    public static final String XML_ER = "/xsd/rfc6283_ers.xsd";

    /** Singleton */
    private static XMLEvidenceRecordUtils singleton;

    /** JAXBContext */
    private JAXBContext jc;

    /**
     * Empty constructor
     */
    private XMLEvidenceRecordUtils() {
        // empty
    }

    /**
     * Returns the instance of {@code XMLEvidenceRecordUtils}
     *
     * @return {@link XMLEvidenceRecordUtils}
     */
    public static XMLEvidenceRecordUtils getInstance() {
        if (singleton == null) {
            singleton = new XMLEvidenceRecordUtils();
        }
        return singleton;
    }

    @Override
    public JAXBContext getJAXBContext() throws JAXBException {
        if (jc == null) {
            jc = JAXBContext.newInstance(ObjectFactory.class);
        }
        return jc;
    }

    @Override
    public List<Source> getXSDSources() {
        List<Source> xsdSources = new ArrayList<>();
        xsdSources.add(new StreamSource(XMLEvidenceRecordUtils.class.getResourceAsStream(XML_ER)));
        return xsdSources;
    }

}
