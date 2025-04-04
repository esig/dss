package eu.europa.esig.dss.model.policy;

import eu.europa.esig.dss.model.DSSDocument;

import java.io.InputStream;

/**
 * Interface containing methods to load a {@code eu.europa.esig.dss.model.policy.ValidationPolicy} from a file
 *
 */
public interface ValidationPolicyFactory {

    /**
     * Evaluates whether the validation policy {@code DSSDocument} is supported by the current implementation
     *
     * @param validationPolicyDocument {@link DSSDocument} containing validation policy
     * @return TRUE if the file is supported, FALSE otherwise
     */
    boolean isSupported(DSSDocument validationPolicyDocument);

    /**
     * Loads a default validation policy provided by the implementation
     *
     * @return {@link ValidationPolicy}
     */
    ValidationPolicy loadDefaultValidationPolicy();

    /**
     * Loads a validation policy from a {@code DSSDocument} provided to the method
     *
     * @param validationPolicyDocument {@link DSSDocument}
     * @return {@link ValidationPolicy}
     */
    ValidationPolicy loadValidationPolicy(DSSDocument validationPolicyDocument);

    /**
     * Loads a validation policy from an {@code InputStream} provided to the method
     *
     * @param validationPolicyInputStream {@link InputStream}
     * @return {@link ValidationPolicy}
     */
    ValidationPolicy loadValidationPolicy(InputStream validationPolicyInputStream);

}
