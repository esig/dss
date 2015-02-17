/*
 * DSS - Digital Signature Services
 *
 * Copyright (C) 2013 European Commission, Directorate-General Internal Market and Services (DG MARKT), B-1049 Bruxelles/Brussel
 *
 * Developed by: 2013 ARHS Developments S.A. (rue Nicolas Bové 2B, L-1253 Luxembourg) http://www.arhs-developments.com
 *
 * This file is part of the "DSS - Digital Signature Services" project.
 *
 * "DSS - Digital Signature Services" is free software: you can redistribute it and/or modify it under the terms of
 * the GNU Lesser General Public License as published by the Free Software Foundation, either version 2.1 of the
 * License, or (at your option) any later version.
 *
 * DSS is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License along with
 * "DSS - Digital Signature Services".  If not, see <http://www.gnu.org/licenses/>.
 */

package eu.europa.ec.markt.dss.validation102853.tsl;

import java.io.IOException;
import java.io.InputStream;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;

import org.w3c.dom.Document;

import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.exception.DSSNullException;
import eu.europa.ec.markt.tsl.jaxb.tsl.ObjectFactory;
import eu.europa.ec.markt.tsl.jaxb.tsl.TrustStatusListType;

/**
 * Utility class for parsing Trusted List
 *
 * @version $Revision: 946 $ - $Date: 2011-06-06 17:15:14 +0200 (Mon, 06 Jun 2011) $
 */

abstract class TrustServiceListFactory {

    /**
     * @param input
     * @return
     * @throws IOException
     */
    @SuppressWarnings("unchecked")
    public static TrustStatusList newInstance(InputStream input) throws IOException {
        TrustStatusListType trustServiceStatusList;
        try {
            Unmarshaller unmarshaller = getUnmarshaller();
            JAXBElement<TrustStatusListType> jaxbElement = (JAXBElement<TrustStatusListType>) unmarshaller.unmarshal(input);
            trustServiceStatusList = jaxbElement.getValue();
        } catch (JAXBException e) {
            throw new IOException("TSL parse error: " + e.getMessage(), e);
        }
        return new TrustStatusList(trustServiceStatusList);
    }

    /**
     * @param tslDocument
     * @return
     * @throws DSSException
     */
    @SuppressWarnings("unchecked")
    public static TrustStatusList newInstance(final Document tslDocument) throws DSSException {

        if (null == tslDocument) {

            throw new DSSNullException(Document.class);
        }
        TrustStatusListType trustServiceStatusList;
        try {

            final Unmarshaller unmarshaller = getUnmarshaller();
            final JAXBElement<TrustStatusListType> jaxbElement = (JAXBElement<TrustStatusListType>) unmarshaller.unmarshal(tslDocument);
            trustServiceStatusList = jaxbElement.getValue();
        } catch (JAXBException e) {

            throw new DSSException("TSL parse error.", e);
        }
        return new TrustStatusList(trustServiceStatusList);
    }

    private static Unmarshaller getUnmarshaller() throws JAXBException {

        JAXBContext jaxbContext = JAXBContext.newInstance(ObjectFactory.class, ObjectFactory.class, eu.europa.ec.markt.tsl.jaxb.ecc.ObjectFactory.class);
        final Unmarshaller unmarshaller = jaxbContext.createUnmarshaller();
        return unmarshaller;
    }
}
