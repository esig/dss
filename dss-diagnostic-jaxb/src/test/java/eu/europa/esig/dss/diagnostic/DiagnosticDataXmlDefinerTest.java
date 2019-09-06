package eu.europa.esig.dss.diagnostic;

import static org.junit.Assert.assertNotNull;

import org.junit.Test;

import eu.europa.esig.dss.diagnostic.DiagnosticDataXmlDefiner;

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
