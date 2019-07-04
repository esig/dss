package eu.europa.esig.dss.jaxb.simplecertificatereport;

import static org.junit.Assert.assertNotNull;

import java.io.IOException;

import javax.xml.bind.JAXBException;
import javax.xml.transform.Templates;
import javax.xml.transform.TransformerConfigurationException;

import org.junit.Test;
import org.xml.sax.SAXException;

public class SimpleCertificateReportXmlDefinerTest {

	@Test
	public void getJAXBContext() throws SAXException, JAXBException {
		assertNotNull(SimpleCertificateReportXmlDefiner.getJAXBContext());
		assertNotNull(SimpleCertificateReportXmlDefiner.getJAXBContext());
	}

	@Test
	public void getSchema() throws SAXException, IOException {
		assertNotNull(SimpleCertificateReportXmlDefiner.getSchema());
		assertNotNull(SimpleCertificateReportXmlDefiner.getSchema());
	}

	@Test
	public void getHtmlBootstrap3Templates() throws IOException, TransformerConfigurationException {
		Templates htmlTemplates = SimpleCertificateReportXmlDefiner.getHtmlBootstrap3Templates();
		assertNotNull(htmlTemplates);
		assertNotNull(htmlTemplates.newTransformer());

		assertNotNull(SimpleCertificateReportXmlDefiner.getHtmlBootstrap3Templates());
	}

	@Test
	public void getHtmlBootstrap4Templates() throws IOException, TransformerConfigurationException {
		Templates htmlTemplates = SimpleCertificateReportXmlDefiner.getHtmlBootstrap4Templates();
		assertNotNull(htmlTemplates);
		assertNotNull(htmlTemplates.newTransformer());

		assertNotNull(SimpleCertificateReportXmlDefiner.getHtmlBootstrap4Templates());
	}

}
