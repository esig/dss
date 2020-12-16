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
package eu.europa.esig.xmldsig;

import eu.europa.esig.xmldsig.jaxb.ObjectFactory;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.transform.Source;
import javax.xml.transform.stream.StreamSource;
import java.util.ArrayList;
import java.util.List;

/**
 * XMLDSIG schema utils
 */
public final class XmlDSigUtils extends XSDAbstractUtils {

	/** XML schema location */
	public static final String XML_SCHEMA_LOCATION = "/xsd/xml.xsd";

	/** XMLDSIG schema location */
	public static final String XMLDSIG_SCHEMA_LOCATION = "/xsd/xmldsig-core-schema.xsd";

	/** XMLDSIG Filter 2.0 schema location */
	public static final String XMLDSIG_FILTER2_SCHEMA_LOCATION = "/xsd/xmldsig-filter2.xsd";

	/** Singleton */
	private static XmlDSigUtils singleton;

	/** JAXBContext */
	private JAXBContext jc;

	private XmlDSigUtils() {
	}

	/**
	 * Returns instance of {@code XmlDSigUtils}
	 *
	 * @return {@link XmlDSigUtils}
	 */
	public static XmlDSigUtils getInstance() {
		if (singleton == null) {
			singleton = new XmlDSigUtils();
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
		xsdSources.add(new StreamSource(XmlDSigUtils.class.getResourceAsStream(XML_SCHEMA_LOCATION)));
		xsdSources.add(new StreamSource(XmlDSigUtils.class.getResourceAsStream(XMLDSIG_SCHEMA_LOCATION)));
		xsdSources.add(new StreamSource(XmlDSigUtils.class.getResourceAsStream(XMLDSIG_FILTER2_SCHEMA_LOCATION)));
		return xsdSources;
	}

}
