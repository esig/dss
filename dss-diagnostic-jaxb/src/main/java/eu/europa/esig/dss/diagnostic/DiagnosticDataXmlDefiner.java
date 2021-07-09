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
package eu.europa.esig.dss.diagnostic;

import eu.europa.esig.dss.diagnostic.jaxb.ObjectFactory;
import eu.europa.esig.dss.jaxb.common.XmlDefinerUtils;
import org.xml.sax.SAXException;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.transform.Source;
import javax.xml.transform.Templates;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.stream.StreamSource;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;
import java.io.IOException;
import java.io.InputStream;

/**
 * This class is used to provide an XSD schema for a DiagnosticData and templates
 *
 */
public final class DiagnosticDataXmlDefiner {

	/** The location of DiagnosticData XSD */
	private static final String DIAGNOSTIC_DATA_SCHEMA_LOCATION = "/xsd/DiagnosticData.xsd";
	
	/** The location of DiagnosticData XSLT remplate */
	private static final String DIAGNOSTIC_DATA_XSLT_SVG_LOCATION = "/xslt/svg/diagnostic-data.xslt";

	/**
	 * Singleton
	 */
	private DiagnosticDataXmlDefiner() {
	}

	/** ObjectFactory instance */
	public static final ObjectFactory OBJECT_FACTORY = new ObjectFactory();

	/** JAXBContext (thread-safe) */
	private static JAXBContext jc;

	/** Schema (thread-safe) */
	private static Schema schema;

	/** SVG Templates (thread-safe) */
	private static Templates svgTemplates;
	
	/**
	 * Gets the JAXB context
	 *
	 * @return {@link JAXBContext}
	 * @throws JAXBException if an exception occurs
	 */
	public static JAXBContext getJAXBContext() throws JAXBException {
		if (jc == null) {
			jc = JAXBContext.newInstance(ObjectFactory.class);
		}
		return jc;
	}

	/**
	 * Gets the XSD Schema for the DiagnosticData
	 *
	 * @return {@link Schema}
	 * @throws IOException if XSD reading exception occurs
	 * @throws SAXException if an exception occurs
	 */
	public static Schema getSchema() throws IOException, SAXException {
		if (schema == null) {
			try (InputStream isXSDDiagnosticData = DiagnosticDataXmlDefiner.class.getResourceAsStream(DIAGNOSTIC_DATA_SCHEMA_LOCATION)) {
				SchemaFactory sf = XmlDefinerUtils.getInstance().getSecureSchemaFactory();
				schema = sf.newSchema(new Source[] { new StreamSource(isXSDDiagnosticData) });
			}
		}
		return schema;
	}

	/**
	 * Gets the SVG template
	 *
	 * @return {@link Templates}
	 * @throws TransformerConfigurationException if an exception occurs
	 * @throws IOException if file reading exception occurs
	 */
	public static Templates getSvgTemplates() throws TransformerConfigurationException, IOException {
		if (svgTemplates == null) {
			svgTemplates = loadTemplates(DIAGNOSTIC_DATA_XSLT_SVG_LOCATION);
		}
		return svgTemplates;
	}
	
	private static Templates loadTemplates(String path) throws TransformerConfigurationException, IOException {
		try (InputStream is = DiagnosticDataXmlDefiner.class.getResourceAsStream(path)) {
			TransformerFactory transformerFactory = XmlDefinerUtils.getInstance().getSecureTransformerFactory();
			return transformerFactory.newTemplates(new StreamSource(is));
		}
	}

}
