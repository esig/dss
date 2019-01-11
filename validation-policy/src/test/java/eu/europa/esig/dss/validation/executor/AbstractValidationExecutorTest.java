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
import eu.europa.esig.dss.validation.policy.XmlUtils;
import eu.europa.esig.jaxb.policy.ConstraintsParameters;

public class AbstractValidationExecutorTest {
	
	protected ConstraintsParameters loadConstraintsParameters(String policyConstraintFile) throws Exception {
		FileInputStream policyFis = new FileInputStream(policyConstraintFile);
		ConstraintsParameters policyJaxB = XmlUtils.getJAXBObjectFromString(policyFis, ConstraintsParameters.class, "/xsd/policy.xsd");
		return policyJaxB;
	}

	protected EtsiValidationPolicy loadPolicy(String policyConstraintFile) throws Exception {
		ConstraintsParameters policyJaxB = loadConstraintsParameters(policyConstraintFile);
		assertNotNull(policyJaxB);
		return new EtsiValidationPolicy(policyJaxB);
	}

}
