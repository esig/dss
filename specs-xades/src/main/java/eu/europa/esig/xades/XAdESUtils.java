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
package eu.europa.esig.xades;

import eu.europa.esig.dss.jaxb.common.XSDAbstractUtils;
import eu.europa.esig.xmldsig.XmlDSigUtils;
import eu.europa.esig.xmldsig.jaxb.ObjectFactory;

import jakarta.xml.bind.JAXBContext;
import jakarta.xml.bind.JAXBException;
import javax.xml.transform.Source;
import javax.xml.transform.stream.StreamSource;
import java.util.List;

/**
 * Common XAdES schema utils
 */
public final class XAdESUtils extends XSDAbstractUtils {

	/** The XAdES 1.3.2 XSD schema */
	public static final String XADES_SCHEMA_LOCATION = "/xsd/XAdES.xsd";

	/** The XAdES 1.4.1 XSD schema */
	public static final String XADES_141_SCHEMA_LOCATION = "/xsd/XAdESv141.xsd";

	/** Singleton */
	private static XAdESUtils singleton;

	/** JAXBContext */
	private JAXBContext jc;

	/**
	 * Empty constructor
	 */
	private XAdESUtils() {
		// empty
	}

	/**
	 * Returns instance of {@code XAdESUtils}
	 *
	 * @return {@link XAdESUtils}
	 */
	public static XAdESUtils getInstance() {
		if (singleton == null) {
			singleton = new XAdESUtils();
		}
		return singleton;
	}

	@Override
	public JAXBContext getJAXBContext() throws JAXBException {
		if (jc == null) {
			jc = JAXBContext.newInstance(ObjectFactory.class, eu.europa.esig.xades.jaxb.xades132.ObjectFactory.class,
					eu.europa.esig.xades.jaxb.xades141.ObjectFactory.class);
		}
		return jc;
	}

	@Override
	public List<Source> getXSDSources() {
		List<Source> xsdSources = XmlDSigUtils.getInstance().getXSDSources();
		xsdSources.add(new StreamSource(XAdESUtils.class.getResourceAsStream(XADES_SCHEMA_LOCATION)));
		xsdSources.add(new StreamSource(XAdESUtils.class.getResourceAsStream(XADES_141_SCHEMA_LOCATION)));
		return xsdSources;
	}
	
}
