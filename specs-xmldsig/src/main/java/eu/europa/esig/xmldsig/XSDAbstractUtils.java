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

import java.io.IOException;
import java.util.Arrays;
import java.util.List;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.transform.Source;
import javax.xml.validation.Schema;
import javax.xml.validation.Validator;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xml.sax.SAXException;

import eu.europa.esig.dss.jaxb.parsers.XmlDefinerUtils;

public abstract class XSDAbstractUtils {

	private static final Logger LOG = LoggerFactory.getLogger(XSDAbstractUtils.class);
	
	private static final String EMPTY_STRING = "";

	/**
	 * Returns a JAXBContext
	 * @return {@link JAXBContext}
	 * @throws JAXBException in case of an exception
	 */
	public abstract JAXBContext getJAXBContext() throws JAXBException;
	
	/**
	 * Returns a default module {@code Schema}
	 * @return {@link Schema}
	 * @throws SAXException in case of an exception
	 */
	public abstract Schema getSchema() throws SAXException;
	
	/**
	 * Returns a list of module-specific XSD {@code Source}s
	 * @return list of XSD {@link Source}s
	 */
	public abstract List<Source> getXSDSources();
	
	/**
	 * Returns a Schema with custom sources
	 * @param sources an array of custom {@link Source}s
	 * @return {@link Schema}
	 * @throws SAXException in case of an exception
	 */
	public Schema getSchema(Source... sources) throws SAXException {
		List<Source> xsdSources = getXSDSources();
		if (sources != null) {
			xsdSources.addAll(Arrays.asList(sources));
		}
		return XmlDefinerUtils.getSchema(xsdSources);
	}

	/**
	 * This method allows to validate an XML against the module-default XSD schema.
	 *
	 * @param xmlSource
	 *            {@code Source} XML to validate
	 * @return null if the XSD validates the XML, error message otherwise
	 */
	public String validateAgainstXSD(final Source xmlSource) {
		try {
			validate(getSchema(), xmlSource);
			return EMPTY_STRING;
		} catch (Exception e) {
			String errorMessage = String.format("Error during the XML schema validation! Reason : [%s]", e.getMessage());
			if (LOG.isDebugEnabled()) {
				LOG.warn(errorMessage, e);
			} else {
				LOG.warn(errorMessage);
			}
			return e.getMessage();
		}
	}

	/**
	 * This method allows to validate an XML against the module-default XSD schema plus custom sources.
	 *
	 * @param xmlSource
	 *            {@code Source} XML to validate
	 * @param sources
	 *            {@code Source}s to validate against (custom schemas)
	 * @return null if the XSD validates the XML, error message otherwise
	 */
	public String validateAgainstXSD(final Source xmlSource, Source... sources) {
		try {
			validate(getSchema(sources), xmlSource);
			return EMPTY_STRING;
		} catch (Exception e) {
			LOG.warn("Error during the XML schema validation!", e);
			return e.getMessage();
		}
	}
	
	private void validate(final Schema schema, final Source xmlSource) throws SAXException, IOException {
		Validator validator = schema.newValidator();
		XmlDefinerUtils.avoidXXE(validator);
		validator.validate(xmlSource);
	}

}
