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
package eu.europa.esig.trustedlist.mra;

import eu.europa.esig.trustedlist.TrustedListFacade;
import org.xml.sax.SAXException;

import jakarta.xml.bind.JAXBContext;
import jakarta.xml.bind.JAXBException;
import javax.xml.validation.Schema;

/**
 * Performs marshalling/unmarshalling operation for a TrustedList XML with applied MRA scheme
 *
 */
public class MRAFacade extends TrustedListFacade {

    /** MRA utils */
    private static final MRAUtils MRA_UTILS = MRAUtils.getInstance();

    /**
     * Default constructor
     */
    protected MRAFacade() {
        // empty
    }

    /**
     * Creates a new facade
     *
     * @return {@link MRAFacade}
     */
    public static MRAFacade newFacade() {
        return new MRAFacade();
    }

    @Override
    protected JAXBContext getJAXBContext() throws JAXBException {
        return MRA_UTILS.getJAXBContext();
    }

    @Override
    protected Schema getSchema() throws SAXException {
        return MRA_UTILS.getSchema();
    }

}
