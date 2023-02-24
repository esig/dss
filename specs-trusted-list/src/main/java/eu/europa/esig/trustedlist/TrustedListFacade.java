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

import eu.europa.esig.dss.jaxb.common.AbstractJaxbFacade;
import eu.europa.esig.trustedlist.jaxb.tsl.TrustStatusListType;
import org.xml.sax.SAXException;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.validation.Schema;
import java.io.IOException;

/**
 * Performs marshalling/unmarshalling operation for a TrustedList XML
 */
public class TrustedListFacade extends AbstractJaxbFacade<TrustStatusListType> {

	/** TL utils */
	private static final TrustedListUtils TL_UTILS = TrustedListUtils.getInstance();

	/**
	 * Default constructor
	 */
	protected TrustedListFacade() {
		// empty
	}

	/**
	 * Creates a new facade
	 *
	 * @return {@link TrustedListFacade}
	 */
	public static TrustedListFacade newFacade() {
		return new TrustedListFacade();
	}

	@Override
	protected JAXBContext getJAXBContext() throws JAXBException {
		return TL_UTILS.getJAXBContext();
	}

	@Override
	protected Schema getSchema() throws IOException, SAXException {
		return TL_UTILS.getSchema();
	}

	@Override
	protected JAXBElement<TrustStatusListType> wrap(TrustStatusListType jaxbObject) {
		return TrustedListUtils.OBJECT_FACTORY.createTrustServiceStatusList(jaxbObject);
	}

}
