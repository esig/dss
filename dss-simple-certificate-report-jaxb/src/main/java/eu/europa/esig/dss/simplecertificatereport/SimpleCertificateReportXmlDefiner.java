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

import eu.europa.esig.dss.jaxb.parsers.XmlDefinerUtils;
import eu.europa.esig.dss.simplecertificatereport.jaxb.ObjectFactory;

public final class SimpleCertificateReportXmlDefiner {

	public static final String SIMPLE_CERTIFICATE_REPORT_SCHEMA_LOCATION = "/xsd/SimpleCertificateReport.xsd";
	public static final String SIMPLE_CERTIFICATE_REPORT_XSLT_HTML_BOOTSTRAP3_LOCATION = "/xslt/html/simple-certificate-report.xslt";
	public static final String SIMPLE_CERTIFICATE_REPORT_XSLT_HTML_BOOTSTRAP4_LOCATION = "/xslt/html/simple-certificate-report-bootstrap4.xslt";
	public static final String SIMPLE_CERTIFICATE_REPORT_XSLT_PDF_LOCATION = "/xslt/pdf/simple-certificate-report.xslt";

	private SimpleCertificateReportXmlDefiner() {
	}

	public static final ObjectFactory OBJECT_FACTORY = new ObjectFactory();

	// Thread-safe
	private static JAXBContext jc;
	// Thread-safe
	private static Schema schema;

	// Thread-safe
	private static Templates htmlBootstrap3Templates;
	private static Templates htmlBootstrap4Templates;
	private static Templates pdfTemplates;

	public static JAXBContext getJAXBContext() throws JAXBException {
		if (jc == null) {
			jc = JAXBContext.newInstance(ObjectFactory.class);
		}
		return jc;
	}

	public static Schema getSchema() throws IOException, SAXException {
		if (schema == null) {
			try (InputStream inputStream = SimpleCertificateReportXmlDefiner.class.getResourceAsStream(SIMPLE_CERTIFICATE_REPORT_SCHEMA_LOCATION)) {
				SchemaFactory sf = XmlDefinerUtils.getInstance().getSecureSchemaFactory();
				schema = sf.newSchema(new Source[] { new StreamSource(inputStream) });
			}
		}
		return schema;
	}

	public static Templates getHtmlBootstrap3Templates() throws TransformerConfigurationException, IOException {
		if (htmlBootstrap3Templates == null) {
			htmlBootstrap3Templates = loadTemplates(SIMPLE_CERTIFICATE_REPORT_XSLT_HTML_BOOTSTRAP3_LOCATION);
		}
		return htmlBootstrap3Templates;
	}

	public static Templates getHtmlBootstrap4Templates() throws TransformerConfigurationException, IOException {
		if (htmlBootstrap4Templates == null) {
			htmlBootstrap4Templates = loadTemplates(SIMPLE_CERTIFICATE_REPORT_XSLT_HTML_BOOTSTRAP4_LOCATION);
		}
		return htmlBootstrap4Templates;
	}

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
