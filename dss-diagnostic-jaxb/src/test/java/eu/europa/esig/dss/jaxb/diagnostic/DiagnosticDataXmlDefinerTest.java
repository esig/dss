package eu.europa.esig.dss.jaxb.diagnostic;

import static org.junit.Assert.assertNotNull;

import org.junit.Test;

public class DiagnosticDataXmlDefinerTest {

	@Test
	public void getJAXBContext() throws Exception {
		assertNotNull(DiagnosticDataXmlDefiner.getJAXBContext());
		assertNotNull(DiagnosticDataXmlDefiner.getJAXBContext());
	}

	@Test
	public void getSchema() throws Exception {
		assertNotNull(DiagnosticDataXmlDefiner.getSchema());
		assertNotNull(DiagnosticDataXmlDefiner.getSchema());
	}

}
