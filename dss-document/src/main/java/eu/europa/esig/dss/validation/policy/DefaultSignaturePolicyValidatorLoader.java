package eu.europa.esig.dss.validation.policy;

import eu.europa.esig.dss.validation.SignaturePolicy;

import java.util.Iterator;
import java.util.ServiceLoader;

/**
 * Loads a relevant {@code SignaturePolicyValidator} based on the policy content
 *
 */
public class DefaultSignaturePolicyValidatorLoader implements SignaturePolicyValidatorLoader {

    /**
     * The validator to be used when only a basic validation according to the signature format is required
     *
     * NOTE: can be null (the best corresponding validator will be loaded)
     */
    private SignaturePolicyValidator defaultSignaturePolicyValidator;

    /**
     * This method sets a {@code SignaturePolicyValidator} to be used for default signature policy processing
     * according to the signature format (when {@code SignaturePolicy.hashAsInTechnicalSpecification == false})
     *
     * @param defaultSignaturePolicyValidator {@link SignaturePolicyValidator}
     */
    public void setDefaultSignaturePolicyValidator(SignaturePolicyValidator defaultSignaturePolicyValidator) {
        this.defaultSignaturePolicyValidator = defaultSignaturePolicyValidator;
    }

    /**
     * Loads with a ServiceLoader and returns the relevant validator for a {@code SignaturePolicy}
     *
     * @param signaturePolicy {@link SignaturePolicy} to get a relevant validator for
     * @return {@link SignaturePolicyValidator}
     */
    @Override
    public SignaturePolicyValidator loadValidator(final SignaturePolicy signaturePolicy) {
        SignaturePolicyValidator validator = null;
        if (defaultSignaturePolicyValidator != null && !signaturePolicy.isHashAsInTechnicalSpecification()) {
            validator = defaultSignaturePolicyValidator;

        } else {
            ServiceLoader<SignaturePolicyValidator> loader = ServiceLoader.load(SignaturePolicyValidator.class);
            Iterator<SignaturePolicyValidator> validatorOptions = loader.iterator();

            if (validatorOptions.hasNext()) {
                for (SignaturePolicyValidator signaturePolicyValidator : loader) {
                    if (signaturePolicyValidator.canValidate(signaturePolicy)) {
                        validator = signaturePolicyValidator;
                        break;
                    }
                }
            }
            if (validator == null) {
                // if not empty and no other implementation is found for ASN1 signature policies
                validator = new BasicASNSignaturePolicyValidator();
            }
        }
        return validator;
    }

}
