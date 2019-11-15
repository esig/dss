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

import java.util.ArrayList;
import java.util.List;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.transform.Source;
import javax.xml.transform.stream.StreamSource;
import javax.xml.validation.Schema;

import org.xml.sax.SAXException;

import eu.europa.esig.dss.jaxb.parsers.XmlDefinerUtils;
import eu.europa.esig.xmldsig.jaxb.ObjectFactory;

public final class XmlDSigUtils extends XSDAbstractUtils {

	public static final String XML_SCHEMA_LOCATION = "/xsd/xml.xsd";
	public static final String XMLDSIG_SCHEMA_LOCATION = "/xsd/xmldsig-core-schema.xsd";
	
	private static XmlDSigUtils xmlDSigUtils;

	protected static JAXBContext jc;
	protected static Schema schema;

	private XmlDSigUtils() {
	}
	
	public static XmlDSigUtils newInstance() {
		if (xmlDSigUtils == null) {
			xmlDSigUtils = new XmlDSigUtils();
		}
		 return xmlDSigUtils;
	}

	@Override
	public JAXBContext getJAXBContext() throws JAXBException {
		if (jc == null) {
			jc = JAXBContext.newInstance(ObjectFactory.class);
		}
		return jc;
	}

	@Override
	public Schema getSchema() throws SAXException {
		if (schema == null) {
			schema = XmlDefinerUtils.getSchema(getXSDSources());
		}
		return schema;
	}

	@Override
	public List<Source> getXSDSources() {
		List<Source> xsdSources = new ArrayList<Source>();
		xsdSources.add(new StreamSource(XmlDSigUtils.class.getResourceAsStream(XML_SCHEMA_LOCATION)));
		xsdSources.add(new StreamSource(XmlDSigUtils.class.getResourceAsStream(XMLDSIG_SCHEMA_LOCATION)));
		return xsdSources;
	}

}
