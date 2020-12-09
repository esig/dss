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
package eu.europa.esig.xades;

import eu.europa.esig.xmldsig.XSDAbstractUtils;
import eu.europa.esig.xmldsig.XmlDSigUtils;
import eu.europa.esig.xmldsig.jaxb.ObjectFactory;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.transform.Source;
import javax.xml.transform.stream.StreamSource;
import java.util.List;

/**
 * XAdES 1.2.2 schema utils
 */
public final class XAdES122Utils extends XSDAbstractUtils {

	/** The XAdES 1.2.2 XSD schema */
	public static final String XADES_122_SCHEMA_LOCATION = "/xsd/XAdESv122.xsd";

	/** Singleton */
	private static XAdES122Utils singleton;

	/** JAXBContext */
	private JAXBContext jc;

	private XAdES122Utils() {
	}

	/**
	 * Returns instance of {@code XAdES122Utils}
	 *
	 * @return {@link XAdES122Utils}
	 */
	public static XAdES122Utils getInstance() {
		if (singleton == null) {
			singleton = new XAdES122Utils();
		}
		return singleton;
	}

	@Override
	public JAXBContext getJAXBContext() throws JAXBException {
		if (jc == null) {
			jc = JAXBContext.newInstance(ObjectFactory.class, eu.europa.esig.xades.jaxb.xades122.ObjectFactory.class);
		}
		return jc;
	}

	@Override
	public List<Source> getXSDSources() {
		List<Source> xsdSources = XmlDSigUtils.getInstance().getXSDSources();
		xsdSources.add(new StreamSource(XAdES122Utils.class.getResourceAsStream(XADES_122_SCHEMA_LOCATION)));
		return xsdSources;
	}

}
