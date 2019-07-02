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
	public static final String SIMPLE_REPORT_XSLT_HTML_LOCATION = "/xslt/html/simple-report.xslt";
	public static final String SIMPLE_REPORT_XSLT_PDF_LOCATION = "/xslt/pdf/simple-report.xslt";

	private SimpleReportXmlDefiner() {
	}

	public static final ObjectFactory OBJECT_FACTORY = new ObjectFactory();

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
			try (InputStream inputStream = SimpleReportXmlDefiner.class.getResourceAsStream(SIMPLE_REPORT_SCHEMA_LOCATION)) {
				SchemaFactory sf = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
				schema = sf.newSchema(new Source[] { new StreamSource(inputStream) });
			}
		}
		return schema;
	}

	public static Templates getHtmlTemplates() throws TransformerConfigurationException, IOException {
		if (htmlTemplates == null) {
			try (InputStream inputStream = SimpleReportXmlDefiner.class.getResourceAsStream(SIMPLE_REPORT_XSLT_HTML_LOCATION)) {
				TransformerFactory transformerFactory = getSecureTransformerFactory();
				htmlTemplates = transformerFactory.newTemplates(new StreamSource(inputStream));
			}
		}
		return htmlTemplates;
	}

	public static Templates getPdfTemplates() throws TransformerConfigurationException, IOException {
		if (pdfTemplates == null) {
			try (InputStream inputStream = SimpleReportXmlDefiner.class.getResourceAsStream(SIMPLE_REPORT_XSLT_PDF_LOCATION)) {
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
