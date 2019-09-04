package eu.europa.esig.dss.validation.executor;

import java.io.File;

import eu.europa.esig.dss.policy.ValidationPolicy;
import eu.europa.esig.dss.policy.ValidationPolicyFacade;

public abstract class AbstractTestValidationExecutor {
	
	protected ValidationPolicy loadPolicy(String policyConstraintFile) throws Exception {
		return ValidationPolicyFacade.newFacade().getValidationPolicy(new File(policyConstraintFile));
	}

	protected ValidationPolicy loadDefaultPolicy() throws Exception {
		return ValidationPolicyFacade.newFacade().getDefaultValidationPolicy();
	}

}
