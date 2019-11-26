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
package eu.europa.esig.dss.jaxb.parsers;

import java.util.List;

import javax.xml.XMLConstants;
import javax.xml.transform.Source;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerFactory;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;

import org.xml.sax.SAXException;

public final class XmlDefinerUtils {
	
	/**
	 * Returns a Schema for a list of defined xsdSources
	 * @param xsdSources a list of {@link Source}s
	 * @return {@link Schema}
	 * @throws SAXException in case of exception
	 */
	public static Schema getSchema(List<Source> xsdSources) throws SAXException {
		SchemaFactory sf = XmlDefinerUtils.getSecureSchemaFactory();
		return sf.newSchema(xsdSources.toArray(new Source[xsdSources.size()]));
	}

	public static SchemaFactory getSecureSchemaFactory() throws SAXException {
		SchemaFactory sf = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
		sf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
		sf.setProperty(XMLConstants.ACCESS_EXTERNAL_DTD, "");
		sf.setProperty(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
		return sf;
	}

	public static TransformerFactory getSecureTransformerFactory() throws TransformerConfigurationException {
		TransformerFactory transformerFactory = TransformerFactory.newInstance();
		transformerFactory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
		transformerFactory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
		transformerFactory.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "");
		return transformerFactory;
	}

}
