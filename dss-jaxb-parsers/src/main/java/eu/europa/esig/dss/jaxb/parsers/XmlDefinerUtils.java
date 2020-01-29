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
import java.util.Objects;

import javax.xml.XMLConstants;
import javax.xml.transform.Source;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerFactory;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;
import javax.xml.validation.Validator;

import org.xml.sax.SAXException;

public final class XmlDefinerUtils {
	
	/**
	 * Returns a Schema for a list of defined xsdSources
	 * 
	 * @param xsdSources
	 *                   a list of {@link Source}s
	 * @return {@link Schema}
	 * @throws SAXException
	 *                      in case of exception
	 */
	public static Schema getSchema(List<Source> xsdSources) throws SAXException {
		Objects.requireNonNull(xsdSources, "XSD Source(s) must be provided");
		SchemaFactory sf = getSecureSchemaFactory();
		return sf.newSchema(xsdSources.toArray(new Source[xsdSources.size()]));
	}

	/**
	 * Returns a SchemaFactory with enabled security features (disabled external
	 * DTD/XSD + secure processing
	 * 
	 * @return {@link SchemaFactory}
	 * @throws SAXException
	 *                      in case of exception
	 */
	public static SchemaFactory getSecureSchemaFactory() throws SAXException {
		SchemaFactory sf = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
		sf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
		sf.setProperty(XMLConstants.ACCESS_EXTERNAL_DTD, "");
		sf.setProperty(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
		return sf;
	}

	/**
	 * Returns a TransformerFactory with enabled security features (disabled
	 * external DTD/XSD + secure processing
	 * 
	 * @return {@link TransformerFactory}
	 * @throws TransformerConfigurationException
	 *                                           in case of exception
	 */
	public static TransformerFactory getSecureTransformerFactory() throws TransformerConfigurationException {
		TransformerFactory transformerFactory = TransformerFactory.newInstance();
		transformerFactory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
		transformerFactory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
		transformerFactory.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "");
		return transformerFactory;
	}

	/**
	 * The method protects the validator against XXE
	 * (https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html#validator)
	 * 
	 * @param validator
	 *                  the validator to be configured against XXE
	 * @throws SAXException
	 *                      in case of exception
	 */
	public static void avoidXXE(Validator validator) throws SAXException {
		Objects.requireNonNull(validator, "Validator must be provided");
		validator.setProperty(XMLConstants.ACCESS_EXTERNAL_DTD, "");
		validator.setProperty(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
	}

}
