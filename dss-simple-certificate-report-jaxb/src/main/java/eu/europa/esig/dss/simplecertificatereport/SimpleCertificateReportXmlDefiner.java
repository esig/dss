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
package eu.europa.esig.dss.simplecertificatereport;

import eu.europa.esig.dss.jaxb.common.XmlDefinerUtils;
import eu.europa.esig.dss.simplecertificatereport.jaxb.ObjectFactory;
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
 * Contains cached certificate simple report schemas and templates
 */
public final class SimpleCertificateReportXmlDefiner {

	/** The XSD Certificate Simple Report schema */
	private static final String SIMPLE_CERTIFICATE_REPORT_SCHEMA_LOCATION = "/xsd/SimpleCertificateReport.xsd";

	/** The XSLT for Bootstrap 3 HTML generation path */
	private static final String SIMPLE_CERTIFICATE_REPORT_XSLT_HTML_BOOTSTRAP3_LOCATION = "/xslt/html/simple-certificate-report.xslt";

	/** The XSLT for Bootstrap 4 HTML generation path */
	private static final String SIMPLE_CERTIFICATE_REPORT_XSLT_HTML_BOOTSTRAP4_LOCATION = "/xslt/html/simple-certificate-report-bootstrap4.xslt";

	/** The XSLT for PDF simple report generation path */
	private static final String SIMPLE_CERTIFICATE_REPORT_XSLT_PDF_LOCATION = "/xslt/pdf/simple-certificate-report.xslt";

	private SimpleCertificateReportXmlDefiner() {
	}

	/** The object factory to use */
	public static final ObjectFactory OBJECT_FACTORY = new ObjectFactory();

	/**
	 * Cached JAXBContext
	 *
	 * NOTE: Thread-safe
	 */
	private static JAXBContext jc;

	/**
	 * Cached Schema
	 *
	 * NOTE: Thread-safe
	 */
	private static Schema schema;

	/**
	 * Cached Bootstrap 3 Template
	 *
	 * NOTE: Thread-safe
	 */
	private static Templates htmlBootstrap3Templates;

	/**
	 * Cached Bootstrap 4 Template
	 *
	 * NOTE: Thread-safe
	 */
	private static Templates htmlBootstrap4Templates;

	/**
	 * Cached PDF Template
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
	 * @throws IOException if IOException occurs
	 * @throws SAXException if SAXException occurs
	 */
	public static Schema getSchema() throws IOException, SAXException {
		if (schema == null) {
			try (InputStream inputStream = SimpleCertificateReportXmlDefiner.class.getResourceAsStream(SIMPLE_CERTIFICATE_REPORT_SCHEMA_LOCATION)) {
				SchemaFactory sf = XmlDefinerUtils.getInstance().getSecureSchemaFactory();
				schema = sf.newSchema(new Source[] { new StreamSource(inputStream) });
			}
		}
		return schema;
	}

	/**
	 * Gets the HTML Bootstrap 3 template
	 *
	 * @return {@link Templates}
	 * @throws TransformerConfigurationException if TransformerConfigurationException occurs
	 * @throws IOException if IOException occurs
	 */
	public static Templates getHtmlBootstrap3Templates() throws TransformerConfigurationException, IOException {
		if (htmlBootstrap3Templates == null) {
			htmlBootstrap3Templates = loadTemplates(SIMPLE_CERTIFICATE_REPORT_XSLT_HTML_BOOTSTRAP3_LOCATION);
		}
		return htmlBootstrap3Templates;
	}

	/**
	 * Gets the HTML Bootstrap 4 template
	 *
	 * @return {@link Templates}
	 * @throws TransformerConfigurationException if TransformerConfigurationException occurs
	 * @throws IOException if IOException occurs
	 */
	public static Templates getHtmlBootstrap4Templates() throws TransformerConfigurationException, IOException {
		if (htmlBootstrap4Templates == null) {
			htmlBootstrap4Templates = loadTemplates(SIMPLE_CERTIFICATE_REPORT_XSLT_HTML_BOOTSTRAP4_LOCATION);
		}
		return htmlBootstrap4Templates;
	}

	/**
	 * Gets the PDF template
	 *
	 * @return {@link Templates}
	 * @throws TransformerConfigurationException if TransformerConfigurationException occurs
	 * @throws IOException if IOException occurs
	 */
	public static Templates getPdfTemplates() throws TransformerConfigurationException, IOException {
		if (pdfTemplates == null) {
			pdfTemplates = loadTemplates(SIMPLE_CERTIFICATE_REPORT_XSLT_PDF_LOCATION);
		}
		return pdfTemplates;
	}

	private static Templates loadTemplates(String path) throws TransformerConfigurationException, IOException {
		try (InputStream is = SimpleCertificateReportXmlDefiner.class.getResourceAsStream(path)) {
			TransformerFactory transformerFactory = XmlDefinerUtils.getInstance().getSecureTransformerFactory();
			return transformerFactory.newTemplates(new StreamSource(is));
		}
	}

}
