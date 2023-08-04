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
package eu.europa.esig.saml;

import eu.europa.esig.dss.jaxb.common.XSDAbstractUtils;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.transform.Source;
import javax.xml.transform.stream.StreamSource;
import java.util.ArrayList;
import java.util.List;

/**
 * SOAP envelop utils
 */
public class SoapEnvelopeUtils extends XSDAbstractUtils {

	public static final String XML_SOAP_SCHEMA_LOCATION = "/xsd/schemas.xmlsoap.org.xsd";

	/** Singleton */
	private static SoapEnvelopeUtils singleton;

	/** JAXBContext */
	private JAXBContext jc;

	/**
	 * Empty constructor
	 */
	private SoapEnvelopeUtils() {
		// empty
	}

	/**
	 * Returns instance of {@code SoapEnvelopeUtils}
	 *
	 * @return {@link SoapEnvelopeUtils}
	 */
	public static SoapEnvelopeUtils getInstance() {
		if (singleton == null) {
			singleton = new SoapEnvelopeUtils();
		}
		return singleton;
	}

	@Override
	public JAXBContext getJAXBContext() throws JAXBException {
		if (jc == null) {
			jc = JAXBContext.newInstance(eu.europa.esig.soap.jaxb.envelope.ObjectFactory.class);
		}
		return jc;
	}

	@Override
	public List<Source> getXSDSources() {
		List<Source> xsdSources = new ArrayList<>();
		xsdSources.add(new StreamSource(SoapEnvelopeUtils.class.getResourceAsStream(XML_SOAP_SCHEMA_LOCATION)));
		return xsdSources;
	}

}
