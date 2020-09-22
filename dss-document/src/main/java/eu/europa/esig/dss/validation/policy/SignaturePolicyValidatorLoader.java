package eu.europa.esig.dss.validation.policy;

import java.util.Iterator;
import java.util.ServiceLoader;

import eu.europa.esig.dss.validation.SignaturePolicy;

/**
 * Loads a relevant {@code SignaturePolicyValidator} for the provided {@code SignaturePolicy}
 *
 */
public class SignaturePolicyValidatorLoader {
	
	private final SignaturePolicy signaturePolicy;
	
	public SignaturePolicyValidatorLoader(SignaturePolicy signaturePolicy) {
		this.signaturePolicy = signaturePolicy;
	}
	
	/**
	 * Loads with a ServiceLoader and returns the relevant validator for a {@code SignaturePolicy}
	 * 
	 * @return {@link SignaturePolicyValidator}
	 */
	public SignaturePolicyValidator loadValidator() {
		ServiceLoader<SignaturePolicyValidator> loader = ServiceLoader.load(SignaturePolicyValidator.class);
		Iterator<SignaturePolicyValidator> validatorOptions = loader.iterator();

		SignaturePolicyValidator validator = null;
		if (validatorOptions.hasNext()) {
			for (SignaturePolicyValidator signaturePolicyValidator : loader) {
				signaturePolicyValidator.setSignaturePolicy(signaturePolicy);
				if (signaturePolicyValidator.canValidate()) {
					validator = signaturePolicyValidator;
					break;
				}
			}
		}

		if (validator == null) {
			// if not empty and no other implementation is found for ASN1 signature policies
			validator = new BasicASNSignaturePolicyValidator();
			validator.setSignaturePolicy(signaturePolicy);
		}
		
		return validator;
	}

}
