package eu.europa.esig.dss.validation.executor;

import static org.junit.Assert.assertNotNull;

import java.io.File;

import eu.europa.esig.dss.validation.policy.EtsiValidationPolicy;
import eu.europa.esig.jaxb.policy.ConstraintsParameters;
import eu.europa.esig.jaxb.policy.ValidationPolicyFacade;

public class AbstractValidationExecutorTest {
	
	protected ConstraintsParameters loadConstraintsParameters(String policyConstraintFile) throws Exception {
		return ValidationPolicyFacade.newFacade().unmarshall(new File(policyConstraintFile));
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
