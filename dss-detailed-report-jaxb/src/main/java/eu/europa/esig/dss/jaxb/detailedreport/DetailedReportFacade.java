package eu.europa.esig.dss.jaxb.detailedreport;

import java.io.IOException;
import java.io.StringWriter;

import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;

import org.xml.sax.SAXException;

import eu.europa.esig.dss.MarshallerBuilder;

public class DetailedReportFacade {

	public static DetailedReportFacade newFacade() {
		return new DetailedReportFacade();
	}

	public String marshall(XmlDetailedReport detailedReport, boolean validate) throws JAXBException, IOException, SAXException {
		MarshallerBuilder marshallerBuilder = new MarshallerBuilder(DetailedReportXmlDefiner.getJAXBContext(), DetailedReportXmlDefiner.getSchema());
		marshallerBuilder.setIndent(true);
		marshallerBuilder.setValidate(validate);
		Marshaller marshaller = marshallerBuilder.buildMarshaller();

		StringWriter writer = new StringWriter();
		marshaller.marshal(DetailedReportXmlDefiner.OBJECT_FACTORY.createDetailedReport(detailedReport), writer);
		return writer.toString();
	}

}
