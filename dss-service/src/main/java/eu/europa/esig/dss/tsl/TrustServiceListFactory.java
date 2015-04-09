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
package eu.europa.esig.dss.tsl;

import java.io.IOException;
import java.io.InputStream;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;

import org.w3c.dom.Document;

import eu.europa.esig.dss.DSSException;
import eu.europa.esig.jaxb.tsl.ObjectFactory;
import eu.europa.esig.jaxb.tsl.TrustStatusListType;

/**
 * Utility class for parsing Trusted List
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

			throw new NullPointerException();
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

		JAXBContext jaxbContext = JAXBContext.newInstance(ObjectFactory.class, ObjectFactory.class, eu.europa.esig.jaxb.ecc.ObjectFactory.class);
		final Unmarshaller unmarshaller = jaxbContext.createUnmarshaller();
		return unmarshaller;
	}
}
