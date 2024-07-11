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

import eu.europa.esig.dss.jaxb.common.AbstractJaxbFacade;
import eu.europa.esig.xmlers.jaxb.EvidenceRecordType;
import jakarta.xml.bind.JAXBContext;
import jakarta.xml.bind.JAXBElement;
import jakarta.xml.bind.JAXBException;
import org.xml.sax.SAXException;

import javax.xml.validation.Schema;

/**
 * Performs marshalling/unmarshalling operation for a XML Evidence Records XML
 *
 */
public class XMLEvidenceRecordFacade extends AbstractJaxbFacade<EvidenceRecordType> {

    /** XMLER utils */
    private static final XMLEvidenceRecordUtils XMLER_UTILS = XMLEvidenceRecordUtils.getInstance();

    /**
     * Default constructor
     */
    protected XMLEvidenceRecordFacade() {
        // empty
    }

    /**
     * Creates a new facade
     *
     * @return {@link XMLEvidenceRecordFacade}
     */
    public static XMLEvidenceRecordFacade newFacade() {
        return new XMLEvidenceRecordFacade();
    }

    @Override
    protected JAXBContext getJAXBContext() throws JAXBException {
        return XMLER_UTILS.getJAXBContext();
    }

    @Override
    protected Schema getSchema() throws SAXException {
        return XMLER_UTILS.getSchema();
    }

    @Override
    protected JAXBElement<EvidenceRecordType> wrap(EvidenceRecordType jaxbObject) {
        return XMLEvidenceRecordUtils.OBJECT_FACTORY.createEvidenceRecord(jaxbObject);
    }

}
