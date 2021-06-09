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
     * Loads with a ServiceLoader and returns the relevant validator for a {@code SignaturePolicy}
     *
     * @param signaturePolicy {@link SignaturePolicy} to get a relevant validator for
     * @return {@link SignaturePolicyValidator}
     */
    @Override
    public SignaturePolicyValidator loadValidator(final SignaturePolicy signaturePolicy) {
        ServiceLoader<SignaturePolicyValidator> loader = ServiceLoader.load(SignaturePolicyValidator.class);
        Iterator<SignaturePolicyValidator> validatorOptions = loader.iterator();

        SignaturePolicyValidator validator = null;
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
        return validator;
    }

}
