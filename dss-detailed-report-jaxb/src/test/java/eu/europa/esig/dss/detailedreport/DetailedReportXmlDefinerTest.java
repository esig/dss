package eu.europa.esig.dss.detailedreport;

import static org.junit.Assert.assertNotNull;

import java.io.IOException;

import javax.xml.bind.JAXBException;
import javax.xml.transform.Templates;
import javax.xml.transform.TransformerConfigurationException;

import org.junit.Test;
import org.xml.sax.SAXException;

import eu.europa.esig.dss.detailedreport.DetailedReportXmlDefiner;

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
	public void getHtmlBootstrap3Templates() throws IOException, TransformerConfigurationException {
		Templates htmlTemplates = DetailedReportXmlDefiner.getHtmlBootstrap3Templates();
		assertNotNull(htmlTemplates);
		assertNotNull(htmlTemplates.newTransformer());

		assertNotNull(DetailedReportXmlDefiner.getHtmlBootstrap3Templates());
	}

	@Test
	public void getHtmlBootstrap4Templates() throws IOException, TransformerConfigurationException {
		Templates htmlTemplates = DetailedReportXmlDefiner.getHtmlBootstrap4Templates();
		assertNotNull(htmlTemplates);
		assertNotNull(htmlTemplates.newTransformer());

		assertNotNull(DetailedReportXmlDefiner.getHtmlBootstrap4Templates());
	}

	@Test
	public void getPdfTemplates() throws IOException, TransformerConfigurationException {
		Templates htmlTemplates = DetailedReportXmlDefiner.getPdfTemplates();
		assertNotNull(htmlTemplates);
		assertNotNull(htmlTemplates.newTransformer());

		assertNotNull(DetailedReportXmlDefiner.getPdfTemplates());
	}

}
