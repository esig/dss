package eu.europa.dss.signature.policy.validation;

import java.util.Map;

public interface SignaturePolicyValidator {
	public Map<String, String> validate();
}
