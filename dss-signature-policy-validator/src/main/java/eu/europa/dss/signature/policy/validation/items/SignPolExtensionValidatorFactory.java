package eu.europa.dss.signature.policy.validation.items;

import eu.europa.esig.dss.validation.AdvancedSignature;

public class SignPolExtensionValidatorFactory {

	public static ItemValidator createValidator(AdvancedSignature signature, Object currentObj) {
		
		// If there is nothing to validate or the validation is unknown, return an empty ItemValidator
		return new ItemValidator() {
			public boolean validate() {
				return true;
			}
		};
	}

}
