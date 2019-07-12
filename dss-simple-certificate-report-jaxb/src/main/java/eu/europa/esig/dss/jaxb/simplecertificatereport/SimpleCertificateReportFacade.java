package eu.europa.esig.dss.jaxb.simplecertificatereport;

import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.util.JAXBSource;
import javax.xml.transform.Result;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.stream.StreamResult;
import javax.xml.transform.stream.StreamSource;
import javax.xml.validation.Schema;

import org.xml.sax.SAXException;

import eu.europa.esig.dss.jaxb.parsers.AbstractJaxbFacade;

public class SimpleCertificateReportFacade extends AbstractJaxbFacade<XmlSimpleCertificateReport> {

	public static SimpleCertificateReportFacade newFacade() {
		return new SimpleCertificateReportFacade();
	}

	@Override
	protected JAXBContext getJAXBContext() throws JAXBException {
		return SimpleCertificateReportXmlDefiner.getJAXBContext();
	}

	@Override
	protected Schema getSchema() throws IOException, SAXException {
		return SimpleCertificateReportXmlDefiner.getSchema();
	}

	@Override
	protected JAXBElement<XmlSimpleCertificateReport> wrap(XmlSimpleCertificateReport simpleCertificateReport) {
		return SimpleCertificateReportXmlDefiner.OBJECT_FACTORY.createSimpleCertificateReport(simpleCertificateReport);
	}

	public String generateHtmlReport(XmlSimpleCertificateReport simpleCertificateReport) throws IOException, TransformerException, JAXBException {
		try (StringWriter stringWriter = new StringWriter()) {
			generateHtmlReport(simpleCertificateReport, new StreamResult(stringWriter));
			return stringWriter.toString();
		}
	}

	public void generateHtmlReport(XmlSimpleCertificateReport simpleCertificateReport, Result result) throws IOException, TransformerException, JAXBException {
		Transformer transformer = SimpleCertificateReportXmlDefiner.getHtmlBootstrap3Templates().newTransformer();
		transformer.transform(new JAXBSource(getJAXBContext(), wrap(simpleCertificateReport)), result);
	}

	public String generateHtmlReport(String marshalledSimpleCertificateReport) throws IOException, TransformerException {
		try (StringWriter stringWriter = new StringWriter()) {
			generateHtmlReport(marshalledSimpleCertificateReport, new StreamResult(stringWriter));
			return stringWriter.toString();
		}
	}

	public void generateHtmlReport(String marshalledSimpleCertificateReport, Result result) throws IOException, TransformerException {
		Transformer transformer = SimpleCertificateReportXmlDefiner.getHtmlBootstrap3Templates().newTransformer();
		transformer.transform(new StreamSource(new StringReader(marshalledSimpleCertificateReport)), result);
	}

}
