package eu.europa.esig.dss.jaxb.simplecertificatereport;

import static org.junit.Assert.assertNotNull;

import javax.xml.XMLConstants;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.stream.StreamSource;

import org.junit.Test;

public class XSLTValidatorTest {

	private static TransformerFactory TF;

	static {
		TF = TransformerFactory.newInstance();
		try {
			TF.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
			TF.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
			TF.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "");
		} catch (Exception e) {
			throw new RuntimeException("Unable to initialize a secure TransformerFactory", e);
		}
	}

	@Test
	public void validateXsltHTML() throws TransformerConfigurationException {
		Transformer transformer = TF.newTransformer(new StreamSource("src/main/resources/xslt/html/simple-certificate-report.xslt"));
		assertNotNull(transformer);
	}

}
