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
package eu.europa.esig.dss.detailedreport;

import eu.europa.esig.dss.detailedreport.jaxb.ObjectFactory;
import eu.europa.esig.dss.xml.common.XmlDefinerUtils;
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
 * Contains the cached copies of relevant schema/templates for DetailedReport generation
 */
public final class DetailedReportXmlDefiner {

	/** The XSD Detailed Report schema */
	private static final String DETAILED_REPORT_SCHEMA_LOCATION = "/xsd/DetailedReport.xsd";

	/** The XSLT for Bootstrap 4 HTML generation path */
	private static final String DETAILED_REPORT_XSLT_HTML_BOOTSTRAP4_LOCATION = "/xslt/html/detailed-report-bootstrap4.xslt";

	/** The XSLT for PDF detailed report generation path */
	private static final String DETAILED_REPORT_XSLT_PDF_LOCATION = "/xslt/pdf/detailed-report.xslt";

	private DetailedReportXmlDefiner() {
		// empty
	}

	/** Used to create a JAXB objects */
	public static final ObjectFactory OBJECT_FACTORY = new ObjectFactory();

	/**
	 * Handles a JAXB Object
	 *
	 * NOTE: Thread-safe
	 */
	private static JAXBContext jc;

	/**
	 * The cached Detailed Report schema
	 *
	 * NOTE: Thread-safe
	 */
	private static Schema schema;

	/**
	 * The cached Bootstrap 4 HTML template
	 *
	 * NOTE: Thread-safe
	 */
	private static Templates htmlBootstrap4Templates;

	/**
	 * The cached PDF template
	 *
	 * NOTE: Thread-safe
	 */
	private static Templates pdfTemplates;

	/**
	 * Gets the {@code JAXBContext}
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
	 * Gets the {@code Schema}
	 *
	 * @return {@link Schema}
	 * @throws IOException if an IOException occurs
	 * @throws SAXException if an SAXException occurs
	 */
	public static Schema getSchema() throws IOException, SAXException {
		if (schema == null) {
			try (InputStream isXSDDetailedReport = DetailedReportXmlDefiner.class.getResourceAsStream(DETAILED_REPORT_SCHEMA_LOCATION)) {
				SchemaFactory sf = XmlDefinerUtils.getInstance().getSecureSchemaFactory();
				schema = sf.newSchema(new Source[] { new StreamSource(isXSDDetailedReport) });
			}
		}
		return schema;
	}

	/**
	 * Gets the HTML Bootstrap 4 template
	 *
	 * @return {@link Templates}
	 * @throws TransformerConfigurationException if an TransformerConfigurationException occurs
	 * @throws IOException if an IOException occurs
	 */
	public static Templates getHtmlBootstrap4Templates() throws TransformerConfigurationException, IOException {
		if (htmlBootstrap4Templates == null) {
			htmlBootstrap4Templates = loadTemplates(DETAILED_REPORT_XSLT_HTML_BOOTSTRAP4_LOCATION);
		}
		return htmlBootstrap4Templates;
	}

	/**
	 * Gets the PDF template
	 *
	 * @return {@link Templates}
	 * @throws TransformerConfigurationException if an TransformerConfigurationException occurs
	 * @throws IOException if an IOException occurs
	 */
	public static Templates getPdfTemplates() throws TransformerConfigurationException, IOException {
		if (pdfTemplates == null) {
			pdfTemplates = loadTemplates(DETAILED_REPORT_XSLT_PDF_LOCATION);
		}
		return pdfTemplates;
	}

	private static Templates loadTemplates(String path) throws TransformerConfigurationException, IOException {
		try (InputStream is = DetailedReportXmlDefiner.class.getResourceAsStream(path)) {
			TransformerFactory transformerFactory = XmlDefinerUtils.getInstance().getSecureTransformerFactory();
			return transformerFactory.newTemplates(new StreamSource(is));
		}
	}

}
