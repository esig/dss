package eu.europa.esig.dss.jaxb.detailedreport;

import java.io.IOException;
import java.io.InputStream;

import javax.xml.XMLConstants;
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

public final class DetailedReportXmlDefiner {

	public static final String DETAILED_REPORT_SCHEMA_LOCATION = "/xsd/DetailedReport.xsd";
	public static final String DETAILED_REPORT_XSLT_HTML_LOCATION = "/xslt/html/detailed-report.xslt";
	public static final String DETAILED_REPORT_XSLT_PDF_LOCATION = "/xslt/pdf/detailed-report.xslt";

	private DetailedReportXmlDefiner() {
	}

	// Thread-safe
	private static JAXBContext jc;
	// Thread-safe
	private static Schema schema;

	// Thread-safe
	private static Templates htmlTemplates;
	// Thread-safe
	private static Templates pdfTemplates;

	public static JAXBContext getJAXBContext() throws JAXBException {
		if (jc == null) {
			jc = JAXBContext.newInstance(ObjectFactory.class);
		}
		return jc;
	}

	public static Schema getSchema() throws IOException, SAXException {
		if (schema == null) {
			try (InputStream isXSDDetailedReport = DetailedReportXmlDefiner.class.getResourceAsStream(DETAILED_REPORT_SCHEMA_LOCATION)) {
				SchemaFactory sf = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
				schema = sf.newSchema(new Source[] { new StreamSource(isXSDDetailedReport) });
			}
		}
		return schema;
	}

	public static Templates getHtmlTemplates() throws TransformerConfigurationException, IOException {
		if (htmlTemplates == null) {
			try (InputStream inputStream = DetailedReportXmlDefiner.class.getResourceAsStream(DETAILED_REPORT_XSLT_HTML_LOCATION)) {
				TransformerFactory transformerFactory = getSecureTransformerFactory();
				htmlTemplates = transformerFactory.newTemplates(new StreamSource(inputStream));
			}
		}
		return htmlTemplates;
	}

	public static Templates getPdfTemplates() throws TransformerConfigurationException, IOException {
		if (pdfTemplates == null) {
			try (InputStream inputStream = DetailedReportXmlDefiner.class.getResourceAsStream(DETAILED_REPORT_XSLT_PDF_LOCATION)) {
				TransformerFactory transformerFactory = getSecureTransformerFactory();
				pdfTemplates = transformerFactory.newTemplates(new StreamSource(inputStream));
			}
		}
		return pdfTemplates;

	}

	private static TransformerFactory getSecureTransformerFactory() throws TransformerConfigurationException {
		TransformerFactory transformerFactory = TransformerFactory.newInstance();
		transformerFactory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
		transformerFactory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
		transformerFactory.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "");
		return transformerFactory;
	}

}
