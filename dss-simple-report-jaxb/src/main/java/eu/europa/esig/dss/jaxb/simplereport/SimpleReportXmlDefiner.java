package eu.europa.esig.dss.jaxb.simplereport;

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

public final class SimpleReportXmlDefiner {

	public static final String SIMPLE_REPORT_SCHEMA_LOCATION = "/xsd/SimpleReport.xsd";
	public static final String SIMPLE_REPORT_XSLT_HTML_BOOTSTRAP3_LOCATION = "/xslt/html/simple-report.xslt";
	public static final String SIMPLE_REPORT_XSLT_HTML_BOOTSTRAP4_LOCATION = "/xslt/html/simple-report-bootstrap4.xslt";
	public static final String SIMPLE_REPORT_XSLT_PDF_LOCATION = "/xslt/pdf/simple-report.xslt";

	private SimpleReportXmlDefiner() {
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
			try (InputStream inputStream = SimpleReportXmlDefiner.class.getResourceAsStream(SIMPLE_REPORT_SCHEMA_LOCATION)) {
				SchemaFactory sf = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
				sf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
				schema = sf.newSchema(new Source[] { new StreamSource(inputStream) });
			}
		}
		return schema;
	}

	public static Templates getHtmlBootstrap3Templates() throws TransformerConfigurationException, IOException {
		if (htmlBootstrap3Templates == null) {
			htmlBootstrap3Templates = loadTemplates(SIMPLE_REPORT_XSLT_HTML_BOOTSTRAP3_LOCATION);
		}
		return htmlBootstrap3Templates;
	}

	public static Templates getHtmlBootstrap4Templates() throws TransformerConfigurationException, IOException {
		if (htmlBootstrap4Templates == null) {
			htmlBootstrap4Templates = loadTemplates(SIMPLE_REPORT_XSLT_HTML_BOOTSTRAP4_LOCATION);
		}
		return htmlBootstrap4Templates;
	}

	public static Templates getPdfTemplates() throws TransformerConfigurationException, IOException {
		if (pdfTemplates == null) {
			pdfTemplates = loadTemplates(SIMPLE_REPORT_XSLT_PDF_LOCATION);
		}
		return pdfTemplates;
	}

	private static Templates loadTemplates(String path) throws TransformerConfigurationException, IOException {
		try (InputStream is = SimpleReportXmlDefiner.class.getResourceAsStream(path)) {
			TransformerFactory transformerFactory = getSecureTransformerFactory();
			return transformerFactory.newTemplates(new StreamSource(is));
		}
	}

	private static TransformerFactory getSecureTransformerFactory() throws TransformerConfigurationException {
		TransformerFactory transformerFactory = TransformerFactory.newInstance();
		transformerFactory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
		transformerFactory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
		transformerFactory.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "");
		return transformerFactory;
	}

}
