package eu.europa.esig.dss.jaxb.detailedreport;

import static org.junit.Assert.assertNotNull;

import java.io.IOException;

import javax.xml.bind.JAXBException;
import javax.xml.transform.Templates;
import javax.xml.transform.TransformerConfigurationException;

import org.junit.Test;
import org.xml.sax.SAXException;

public class DetailedReportXmlDefinerTest {

	@Test
	public void getJAXBContext() throws SAXException, JAXBException {
		assertNotNull(DetailedReportXmlDefiner.getJAXBContext());
		assertNotNull(DetailedReportXmlDefiner.getJAXBContext());
	}

	@Test
	public void getSchema() throws SAXException, IOException {
		assertNotNull(DetailedReportXmlDefiner.getSchema());
		assertNotNull(DetailedReportXmlDefiner.getSchema());
	}

	@Test
	public void getHtmlTemplates() throws IOException, TransformerConfigurationException {
		Templates htmlTemplates = DetailedReportXmlDefiner.getHtmlTemplates();
		assertNotNull(htmlTemplates);
		assertNotNull(htmlTemplates.newTransformer());

		assertNotNull(DetailedReportXmlDefiner.getHtmlTemplates());
	}

	@Test
	public void getPdfTemplates() throws IOException, TransformerConfigurationException {
		Templates htmlTemplates = DetailedReportXmlDefiner.getPdfTemplates();
		assertNotNull(htmlTemplates);
		assertNotNull(htmlTemplates.newTransformer());

		assertNotNull(DetailedReportXmlDefiner.getPdfTemplates());
	}

}
