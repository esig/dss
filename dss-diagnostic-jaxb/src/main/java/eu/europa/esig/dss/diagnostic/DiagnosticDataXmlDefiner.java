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

import java.io.IOException;
import java.io.InputStream;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.transform.Source;
import javax.xml.transform.Templates;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.stream.StreamSource;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;

import org.xml.sax.SAXException;

import eu.europa.esig.dss.diagnostic.jaxb.ObjectFactory;
import eu.europa.esig.dss.jaxb.common.XmlDefinerUtils;

public final class DiagnosticDataXmlDefiner {

	private static final String DIAGNOSTIC_DATA_SCHEMA_LOCATION = "/xsd/DiagnosticData.xsd";
	
	private static final String DIAGNOSTIC_DATA_XSLT_SVG_LOCATION = "/xslt/svg/diagnostic-data.xslt";

	private DiagnosticDataXmlDefiner() {
	}

	public static final ObjectFactory OBJECT_FACTORY = new ObjectFactory();

	// Thread-safe
	private static JAXBContext jc;
	// Thread-safe
	private static Schema schema;

	// Thread-safe
	private static Templates svgTemplates;
	
	public static JAXBContext getJAXBContext() throws JAXBException {
		if (jc == null) {
			jc = JAXBContext.newInstance(ObjectFactory.class);
		}
		return jc;
	}

	public static Schema getSchema() throws IOException, SAXException {
		if (schema == null) {
			try (InputStream isXSDDiagnosticData = DiagnosticDataXmlDefiner.class.getResourceAsStream(DIAGNOSTIC_DATA_SCHEMA_LOCATION)) {
				SchemaFactory sf = XmlDefinerUtils.getInstance().getSecureSchemaFactory();
				schema = sf.newSchema(new Source[] { new StreamSource(isXSDDiagnosticData) });
			}
		}
		return schema;
	}

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
