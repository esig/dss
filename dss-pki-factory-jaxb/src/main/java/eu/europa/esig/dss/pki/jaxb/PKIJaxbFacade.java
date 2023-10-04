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
package eu.europa.esig.dss.pki.jaxb;


import eu.europa.esig.dss.jaxb.common.AbstractJaxbFacade;
import org.xml.sax.SAXException;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.validation.Schema;
import java.io.IOException;

/**
 * This class is used to marshall/unmarshal Pki report
 */
public class PKIJaxbFacade extends AbstractJaxbFacade<XmlPki> {

    /**
     * Default constructor
     */
    protected PKIJaxbFacade() {
        // empty
    }

    /**
     * Creates a new instance of {@link PKIJaxbFacade}
     *
     * @return {@link PKIJaxbFacade}
     */
    public static PKIJaxbFacade newFacade() {
        return new PKIJaxbFacade();
    }

    @Override
    protected JAXBContext getJAXBContext() throws JAXBException {
        return PKIJaxbXmlDefiner.getJAXBContext();
    }

    @Override
    protected Schema getSchema() throws IOException, SAXException {
        return PKIJaxbXmlDefiner.getSchema();
    }

    @Override
    protected JAXBElement<XmlPki> wrap(XmlPki pki) {
        return PKIJaxbXmlDefiner.OBJECT_FACTORY.createPki(pki);
    }

}
