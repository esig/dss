package eu.europa.esig.dss.simpletimestampreport;

import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.io.IOException;

import javax.xml.bind.JAXBException;

import org.junit.jupiter.api.Test;
import org.xml.sax.SAXException;

public class SimpleTimestampReportXmlDefinerTest {

	@Test
	public void getJAXBContext() throws SAXException, JAXBException {
		assertNotNull(SimpleTimestampReportXmlDefiner.getJAXBContext());
		assertNotNull(SimpleTimestampReportXmlDefiner.getJAXBContext());
	}

	@Test
	public void getSchema() throws SAXException, IOException {
		assertNotNull(SimpleTimestampReportXmlDefiner.getSchema());
		assertNotNull(SimpleTimestampReportXmlDefiner.getSchema());
	}

}
