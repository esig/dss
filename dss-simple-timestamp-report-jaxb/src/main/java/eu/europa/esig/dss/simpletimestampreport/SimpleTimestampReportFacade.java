package eu.europa.esig.dss.simpletimestampreport;

import java.io.IOException;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.validation.Schema;

import org.xml.sax.SAXException;

import eu.europa.esig.dss.jaxb.parsers.AbstractJaxbFacade;
import eu.europa.esig.dss.simpletimestampreport.jaxb.XmlSimpleTimestampReport;

public class SimpleTimestampReportFacade extends AbstractJaxbFacade<XmlSimpleTimestampReport> {

	public static SimpleTimestampReportFacade newFacade() {
		return new SimpleTimestampReportFacade();
	}

	@Override
	protected JAXBContext getJAXBContext() throws JAXBException {
		return SimpleTimestampReportXmlDefiner.getJAXBContext();
	}

	@Override
	protected Schema getSchema() throws IOException, SAXException {
		return SimpleTimestampReportXmlDefiner.getSchema();
	}

	@Override
	protected JAXBElement<XmlSimpleTimestampReport> wrap(XmlSimpleTimestampReport simpleTimestampReport) {
		return SimpleTimestampReportXmlDefiner.OBJECT_FACTORY.createSimpleTimestampReport(simpleTimestampReport);
	}

}
