package eu.europa.esig.dss.jaxb.simplereport;

import static org.junit.Assert.assertNotNull;

import java.io.IOException;

import javax.xml.bind.JAXBException;
import javax.xml.transform.Templates;
import javax.xml.transform.TransformerConfigurationException;

import org.junit.Test;
import org.xml.sax.SAXException;

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
	public void getHtmlTemplates() throws IOException, TransformerConfigurationException {
		Templates htmlTemplates = SimpleReportXmlDefiner.getHtmlTemplates();
		assertNotNull(htmlTemplates);
		assertNotNull(htmlTemplates.newTransformer());

		assertNotNull(SimpleReportXmlDefiner.getHtmlTemplates());
	}

	@Test
	public void getPdfTemplates() throws IOException, TransformerConfigurationException {
		Templates htmlTemplates = SimpleReportXmlDefiner.getPdfTemplates();
		assertNotNull(htmlTemplates);
		assertNotNull(htmlTemplates.newTransformer());

		assertNotNull(SimpleReportXmlDefiner.getPdfTemplates());
	}

}
