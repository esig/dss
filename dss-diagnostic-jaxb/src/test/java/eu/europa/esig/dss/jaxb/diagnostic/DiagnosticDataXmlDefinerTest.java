package eu.europa.esig.dss.jaxb.diagnostic;

import static org.junit.Assert.assertNotNull;

import org.junit.Test;
import org.xml.sax.SAXException;

public class DiagnosticDataXmlDefinerTest {

	@Test
	public void getJAXBContext() throws SAXException {
		assertNotNull(DiagnosticDataXmlDefiner.getJAXBContext());
		assertNotNull(DiagnosticDataXmlDefiner.getJAXBContext());
	}

	@Test
	public void getSchema() throws SAXException {
		assertNotNull(DiagnosticDataXmlDefiner.getSchema());
		assertNotNull(DiagnosticDataXmlDefiner.getSchema());
	}

}
