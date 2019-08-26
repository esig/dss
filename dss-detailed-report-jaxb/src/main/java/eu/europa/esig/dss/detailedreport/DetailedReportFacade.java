package eu.europa.esig.dss.detailedreport;

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

import eu.europa.esig.dss.detailedreport.jaxb.XmlDetailedReport;
import eu.europa.esig.dss.jaxb.parsers.AbstractJaxbFacade;

public class DetailedReportFacade extends AbstractJaxbFacade<XmlDetailedReport> {

	public static DetailedReportFacade newFacade() {
		return new DetailedReportFacade();
	}

	@Override
	protected JAXBContext getJAXBContext() throws JAXBException {
		return DetailedReportXmlDefiner.getJAXBContext();
	}

	@Override
	protected Schema getSchema() throws IOException, SAXException {
		return DetailedReportXmlDefiner.getSchema();
	}

	@Override
	protected JAXBElement<XmlDetailedReport> wrap(XmlDetailedReport detailedReport) {
		return DetailedReportXmlDefiner.OBJECT_FACTORY.createDetailedReport(detailedReport);
	}

	public String generateHtmlReport(XmlDetailedReport detailedReport) throws IOException, TransformerException, JAXBException {
		try (StringWriter stringWriter = new StringWriter()) {
			generateHtmlReport(detailedReport, new StreamResult(stringWriter));
			return stringWriter.toString();
		}
	}

	public void generateHtmlReport(XmlDetailedReport detailedReport, Result result) throws IOException, TransformerException, JAXBException {
		Transformer transformer = DetailedReportXmlDefiner.getHtmlBootstrap3Templates().newTransformer();
		transformer.transform(new JAXBSource(getJAXBContext(), wrap(detailedReport)), result);
	}

	public String generateHtmlReport(String marshalledDetailedReport) throws IOException, TransformerException {
		try (StringWriter stringWriter = new StringWriter()) {
			generateHtmlReport(marshalledDetailedReport, new StreamResult(stringWriter));
			return stringWriter.toString();
		}
	}

	public void generateHtmlReport(String marshalledDetailedReport, Result result) throws IOException, TransformerException {
		Transformer transformer = DetailedReportXmlDefiner.getHtmlBootstrap3Templates().newTransformer();
		transformer.transform(new StreamSource(new StringReader(marshalledDetailedReport)), result);
	}

	public void generatePdfReport(XmlDetailedReport detailedReport, Result result) throws IOException, TransformerException, JAXBException {
		Transformer transformer = DetailedReportXmlDefiner.getPdfTemplates().newTransformer();
		transformer.transform(new JAXBSource(getJAXBContext(), wrap(detailedReport)), result);
	}

	public void generatePdfReport(String marshalledDetailedReport, Result result) throws IOException, TransformerException {
		Transformer transformer = DetailedReportXmlDefiner.getPdfTemplates().newTransformer();
		transformer.transform(new StreamSource(new StringReader(marshalledDetailedReport)), result);
	}

}
