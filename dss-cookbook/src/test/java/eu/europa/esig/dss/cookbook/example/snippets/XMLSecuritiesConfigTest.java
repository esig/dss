package eu.europa.esig.dss.cookbook.example.snippets;

import static org.junit.jupiter.api.Assertions.assertNotNull;

import javax.xml.XMLConstants;
import javax.xml.transform.TransformerFactory;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.DomUtils;
import eu.europa.esig.dss.alert.DSSExceptionAlert;
import eu.europa.esig.dss.jaxb.TransformerFactoryBuilder;
import eu.europa.esig.dss.jaxb.XmlDefinerUtils;

public class XMLSecuritiesConfigTest {
	
	@Test
	public void test() throws Exception {

		// tag::demo[]
		
		// Obtain a singleton instance of {@link XmlDefinerUtils}
		XmlDefinerUtils xmlDefinerUtils = XmlDefinerUtils.getInstance();
		
		// returns a predefined {@link TransformerFactoryBuilder} with all securities in place
		TransformerFactoryBuilder transformerBuilder = TransformerFactoryBuilder.getSecureTransformerBuilder();
		
		// allows to enable a feature
		transformerBuilder.enableFeature(XMLConstants.FEATURE_SECURE_PROCESSING);
		
		// allows to disable a feature
		transformerBuilder.disableFeature("FEATURE_TO_DISABLE");
		
		// allows to set an attribute with a value
		transformerBuilder.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
		
		// sets an alert in case of exception on feature/attribute setting
		transformerBuilder.setSecurityExceptionAlert(new DSSExceptionAlert());
		
		// sets the transformer (will be applied for all calls)
		xmlDefinerUtils.setTransformerFactoryBuilder(transformerBuilder);

		// end::demo[]
		
		TransformerFactory transformerFactory = transformerBuilder.build();
		assertNotNull(transformerFactory);

		// tag::dbf[]
		
		// allows enabling of a feature
		DomUtils.enableFeature("http://xml.org/sax/features/external-general-entities");
		
		// allows disabling of a feature
		DomUtils.disableFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd");
		
		// end::dbf[]
		
	}

}
