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
package eu.europa.esig.dss.jaxb.common;

import eu.europa.esig.dss.jaxb.common.exception.XSDValidationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xml.sax.SAXException;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.transform.Source;
import javax.xml.validation.Schema;
import javax.xml.validation.Validator;
import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * Abstract class for XSD Utils
 *
 */
public abstract class XSDAbstractUtils {

	private static final Logger LOG = LoggerFactory.getLogger(XSDAbstractUtils.class);

	/** Cached schema */
	private Schema schema;

	/**
	 * Empty constructor
	 */
	protected XSDAbstractUtils() {
		// empty
	}

	/**
	 * Returns a JAXBContext
	 * 
	 * @return the created {@link JAXBContext}
	 * @throws JAXBException
	 *                       in case of an exception
	 */
	public abstract JAXBContext getJAXBContext() throws JAXBException;

	/**
	 * Returns a list of module-specific XSD {@code Source}s
	 * 
	 * @return list of XSD {@link Source}s
	 */
	public abstract List<Source> getXSDSources();

	/**
	 * Returns a default module {@code Schema}. The result is cached
	 * 
	 * @return the created {@link Schema}
	 * @throws SAXException
	 *                      in case of an exception
	 */
	public Schema getSchema() throws SAXException {
		if (schema == null) {
			schema = XmlDefinerUtils.getInstance().getSchema(getXSDSources());
		}
		return schema;
	}

	/**
	 * Returns a Schema with custom sources
	 * 
	 * @param sources
	 *                an array of custom {@link Source}s
	 * @return {@link Schema}
	 * @throws SAXException
	 *                      in case of an exception
	 */
	public Schema getSchema(Source... sources) throws SAXException {
		List<Source> xsdSources = getXSDSources();
		if (sources != null) {
			xsdSources.addAll(Arrays.asList(sources));
		}
		return XmlDefinerUtils.getInstance().getSchema(xsdSources);
	}

	/**
	 * This method allows to validate an XML against the module-default XSD schema.
	 *
	 * @param xmlSource {@code Source} XML to validate
	 * @return empty list if the XSD validates the XML, error messages otherwise
	 */
	public List<String> validateAgainstXSD(final Source xmlSource) {
		try {
			validate(xmlSource, getSchema(), true);
			return Collections.emptyList();
		} catch (XSDValidationException e) {
			return e.getAllMessages();
		} catch (Exception e) {
			LOG.warn("An exception occurred : {}", e.getMessage(), e);
			return Arrays.asList(e.getMessage());
		}
	}

	/**
	 * This method allows to validate an XML against the module-default XSD schema
	 * plus custom sources.
	 *
	 * @param xmlSource     {@code Source} XML to validate
	 * @param schemaSources {@code Source}s to validate against (custom schemas)
	 * @return empty list if the XSD validates the XML, error messages otherwise
	 */
	public List<String> validateAgainstXSD(final Source xmlSource, Source... schemaSources) {
		try {
			validate(xmlSource, getSchema(schemaSources), true);
			return Collections.emptyList();
		} catch (XSDValidationException e) {
			return e.getAllMessages();
		} catch (Exception e) {
			LOG.warn("An exception occurred : {}", e.getMessage(), e);
			return Arrays.asList(e.getMessage());
		}
	}

	/**
	 * This method allows to validate an XML against the module-default XSD schema plus custom sources.
	 *
	 * @param xmlSource
	 *                         the {@code Source}s to validate against (custom schemas)
	 * @param schema
	 *                         the used {@code Schema} to validate
	 * @param secureValidation
	 *                         enable/disable the secure validation (protection against XXE)
	 * @throws IOException if an exception occurs
	 */
	public void validate(final Source xmlSource, final Schema schema, boolean secureValidation)
			throws IOException {
		Validator validator = schema.newValidator();
		try {
			if (secureValidation) {
				XmlDefinerUtils.getInstance().configure(validator);
			}
			validator.validate(xmlSource);
		} catch (SAXException e) {
			throw new XSDValidationException(Arrays.asList(e.getMessage()));
		} finally {
			XmlDefinerUtils.getInstance().postProcess(validator);
		}
	}

}
