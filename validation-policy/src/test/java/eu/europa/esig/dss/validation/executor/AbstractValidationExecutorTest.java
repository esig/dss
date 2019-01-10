package eu.europa.esig.dss.validation.executor;

import static org.junit.Assert.assertNotNull;

import java.io.FileInputStream;
import java.io.InputStream;

import javax.xml.XMLConstants;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.Unmarshaller;
import javax.xml.transform.Source;
import javax.xml.transform.stream.StreamSource;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;

import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.policy.EtsiValidationPolicy;
import eu.europa.esig.jaxb.policy.ConstraintsParameters;

public class AbstractValidationExecutorTest {

	@SuppressWarnings("unchecked")
	protected <T extends Object> T getJAXBObjectFromString(InputStream is, Class<T> clazz, String xsd) throws Exception {
		JAXBContext context = JAXBContext.newInstance(clazz.getPackage().getName());
		Unmarshaller unmarshaller = context.createUnmarshaller();
		if (Utils.isStringNotEmpty(xsd)) {
			SchemaFactory sf = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
			InputStream inputStream = this.getClass().getResourceAsStream(xsd);
			Source source = new StreamSource(inputStream);
			Schema schema = sf.newSchema(source);
			unmarshaller.setSchema(schema);
		}
		return (T) unmarshaller.unmarshal(is);
	}
	
	protected ConstraintsParameters loadConstraintsParameters(String policyConstraintFile) throws Exception {
		FileInputStream policyFis = new FileInputStream(policyConstraintFile);
		ConstraintsParameters policyJaxB = getJAXBObjectFromString(policyFis, ConstraintsParameters.class, "/xsd/policy.xsd");
		return policyJaxB;
	}

	protected EtsiValidationPolicy loadPolicy(String policyConstraintFile) throws Exception {
		ConstraintsParameters policyJaxB = loadConstraintsParameters(policyConstraintFile);
		assertNotNull(policyJaxB);
		return new EtsiValidationPolicy(policyJaxB);
	}

}
