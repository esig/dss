package eu.europa.esig.dss.simplereport;

import static org.junit.Assert.assertNotNull;

import java.io.IOException;

import javax.xml.bind.JAXBException;
import javax.xml.transform.Templates;
import javax.xml.transform.TransformerConfigurationException;

import org.junit.Test;
import org.xml.sax.SAXException;

import eu.europa.esig.dss.simplereport.SimpleReportXmlDefiner;

public class SimpleReportXmlDefinerTest {

	@Test
	public void getJAXBContext() throws SAXException, JAXBException {
		assertNotNull(SimpleReportXmlDefiner.getJAXBContext());
		assertNotNull(SimpleReportXmlDefiner.getJAXBContext());
	}

	@Test
	public void getSchema() throws SAXException, IOException {
		assertNotNull(SimpleReportXmlDefiner.getSchema());
		assertNotNull(SimpleReportXmlDefiner.getSchema());
	}

	@Test
	public void getHtmlBootstrap3Templates() throws IOException, TransformerConfigurationException {
		Templates htmlTemplates = SimpleReportXmlDefiner.getHtmlBootstrap3Templates();
		assertNotNull(htmlTemplates);
		assertNotNull(htmlTemplates.newTransformer());

		assertNotNull(SimpleReportXmlDefiner.getHtmlBootstrap3Templates());
	}

	@Test
	public void getHtmlBootstrap4Templates() throws IOException, TransformerConfigurationException {
		Templates htmlTemplates = SimpleReportXmlDefiner.getHtmlBootstrap4Templates();
		assertNotNull(htmlTemplates);
		assertNotNull(htmlTemplates.newTransformer());

		assertNotNull(SimpleReportXmlDefiner.getHtmlBootstrap4Templates());
	}

	@Test
	public void getPdfTemplates() throws IOException, TransformerConfigurationException {
		Templates htmlTemplates = SimpleReportXmlDefiner.getPdfTemplates();
		assertNotNull(htmlTemplates);
		assertNotNull(htmlTemplates.newTransformer());

		assertNotNull(SimpleReportXmlDefiner.getPdfTemplates());
	}

}
