package eu.europa.esig.dss.validation.executor;

import static org.junit.Assert.assertNotNull;

import java.io.FileInputStream;

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

	protected EtsiValidationPolicy loadDefaultPolicy() throws Exception {
		return loadPolicy("src/main/resources/policy/constraint.xml");
	}

}
