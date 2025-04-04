package eu.europa.esig.dss.validation.policy;

import eu.europa.esig.dss.enumerations.Context;
import eu.europa.esig.dss.enumerations.SubContext;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.policy.CryptographicSuite;
import eu.europa.esig.dss.model.policy.CryptographicSuiteFactory;
import eu.europa.esig.dss.model.policy.ValidationPolicy;
import eu.europa.esig.dss.model.policy.ValidationPolicyFactory;
import eu.europa.esig.dss.utils.Utils;

import java.io.File;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.ServiceLoader;

/**
 * This class creates an instance of {@code ValidationPolicy}
 *
 */
public class ValidationPolicyLoader {

    /** Validation policy file, when provided */
    private final DSSDocument validationPolicyDocument;

    /** Map of cryptographic suite Files and their applicability scopes */
    private final Map<DSSDocument, List<ContextAndSubContext>> cryptographicSuitesMap = new HashMap<>();

    /**
     * Empty constructor
     */
    protected ValidationPolicyLoader() {
        this.validationPolicyDocument = null;
    }

    /**
     * Constructor to create a {@code ValidationPolicyFactory} using a custom validation policy file
     */
    protected ValidationPolicyLoader(DSSDocument validationPolicyDocument) {
        this.validationPolicyDocument = validationPolicyDocument;
    }

    /**
     * Creates an instance of {@code ValidationPolicyFactory} from a default validation policy
     *
     * @return {@link ValidationPolicyLoader}
     */
    public static ValidationPolicyLoader fromDefaultValidationPolicy() {
        return new ValidationPolicyLoader();
    }

    /**
     * Creates an instance of {@code ValidationPolicyFactory} from a custom validation policy file
     *
     * @param validationPolicy {@link File} validation policy file
     * @return {@link ValidationPolicyLoader}
     */
    public static ValidationPolicyLoader fromValidationPolicy(DSSDocument validationPolicy) {
        return new ValidationPolicyLoader(validationPolicy);
    }

    /**
     * Creates an instance of {@code ValidationPolicyFactory} from a custom validation policy {@code InputStream}
     *
     * @param validationPolicyStream {@link InputStream} validation policy file
     * @return {@link ValidationPolicyLoader}
     */
    public static ValidationPolicyLoader fromValidationPolicy(InputStream validationPolicyStream) {
        return new ValidationPolicyLoader(new InMemoryDocument(validationPolicyStream));
    }

    /**
     * Creates an instance of {@code ValidationPolicyFactory} from a custom validation policy file
     *
     * @param validationPolicyFile {@link File} validation policy file
     * @return {@link ValidationPolicyLoader}
     */
    public static ValidationPolicyLoader fromValidationPolicy(File validationPolicyFile) {
        return fromValidationPolicy(new FileDocument(validationPolicyFile));
    }

    /**
     * Creates an instance of {@code ValidationPolicyFactory} from a custom validation policy file
     *
     * @param validationPolicyFilePath {@link String} path to the validation policy file
     * @return {@link ValidationPolicyLoader}
     */
    public static ValidationPolicyLoader fromValidationPolicy(String validationPolicyFilePath) {
        return fromValidationPolicy(new File(validationPolicyFilePath));
    }

    /**
     * Sets a global cryptographic suite {@code DSSDocument}.
     * The suite will overwrite all cryptographic constraints defined in the original {@code ValidationPolicy} file.
     * It is also will be used when a cryptographic suite is not provided for a specific scope.
     * The method {@code #setCryptographicSuiteForScope} can be used to specify constraints for a specific scope.
     *
     * @param cryptographicSuite {@link DSSDocument}
     */
    public void setGlobalCryptographicSuite(DSSDocument cryptographicSuite) {
        setCryptographicSuiteForScope(cryptographicSuite, null);
    }

    /**
     * Sets a global cryptographic suite {@code InputStream}.
     * The suite will overwrite all cryptographic constraints defined in the original {@code ValidationPolicy} file.
     * It is also will be used when a cryptographic suite is not provided for a specific scope.
     * The method {@code #setCryptographicSuiteForScope} can be used to specify constraints for a specific scope.
     *
     * @param cryptographicSuiteIS {@link InputStream}
     */
    public void setGlobalCryptographicSuite(InputStream cryptographicSuiteIS) {
        setCryptographicSuiteForScope(cryptographicSuiteIS, null);
    }

    /**
     * Sets a global cryptographic suite {@code File}.
     * The suite will overwrite all cryptographic constraints defined in the original {@code ValidationPolicy} file.
     * It is also will be used when a cryptographic suite is not provided for a specific scope.
     * The method {@code #setCryptographicSuiteForScope} can be used to specify constraints for a specific scope.
     *
     * @param cryptographicSuiteFile {@link File}
     */
    public void setGlobalCryptographicSuite(File cryptographicSuiteFile) {
        setCryptographicSuiteForScope(cryptographicSuiteFile, null);
    }

    /**
     * Sets a global cryptographic suite file.
     * The suite will overwrite all cryptographic constraints defined in the original {@code ValidationPolicy} file.
     * It is also will be used when a cryptographic suite is not provided for a specific scope.
     * The method {@code #setCryptographicSuiteForScope} can be used to specify constraints for a specific scope.
     *
     * @param cryptographicSuiteFilePath {@link String}
     */
    public void setGlobalCryptographicSuite(String cryptographicSuiteFilePath) {
        setCryptographicSuiteForScope(cryptographicSuiteFilePath, null);
    }

    /**
     * Sets a cryptographic suite {@code DSSDocument} for the given Context.
     * The supported contexts are: SIGNATURE, COUNTER_SIGNATURE, TIMESTAMP, EVIDENCE_RECORD, REVOCATION.
     * The cryptographic suite will be used only for the specific scope.
     *
     * @param cryptographicSuite {@link DSSDocument}
     */
    public void setCryptographicSuiteForScope(DSSDocument cryptographicSuite, Context context) {
        setCryptographicSuiteForScope(cryptographicSuite, context, null);
    }

    /**
     * Sets a cryptographic suite {@code InputStream} for the given Context.
     * The supported contexts are: SIGNATURE, COUNTER_SIGNATURE, TIMESTAMP, EVIDENCE_RECORD, REVOCATION.
     * The cryptographic suite will be used only for the specific scope.
     *
     * @param cryptographicSuiteIS {@link InputStream}
     */
    public void setCryptographicSuiteForScope(InputStream cryptographicSuiteIS, Context context) {
        setCryptographicSuiteForScope(cryptographicSuiteIS, context, null);
    }

    /**
     * Sets a cryptographic suite {@code File} for the given Context.
     * The supported contexts are: SIGNATURE, COUNTER_SIGNATURE, TIMESTAMP, EVIDENCE_RECORD, REVOCATION.
     * The cryptographic suite will be used only for the specific scope.
     *
     * @param cryptographicSuiteFile {@link File}
     */
    public void setCryptographicSuiteForScope(File cryptographicSuiteFile, Context context) {
        setCryptographicSuiteForScope(cryptographicSuiteFile, context, null);
    }

    /**
     * Sets a cryptographic suite file for the given Context.
     * The supported contexts are: SIGNATURE, COUNTER_SIGNATURE, TIMESTAMP, EVIDENCE_RECORD, REVOCATION.
     * The cryptographic suite will be used only for the specific scope.
     *
     * @param cryptographicSuiteFilePath {@link File}
     */
    public void setCryptographicSuiteForScope(String cryptographicSuiteFilePath, Context context) {
        setCryptographicSuiteForScope(cryptographicSuiteFilePath, context, null);
    }

    /**
     * Sets a cryptographic suite {@code DSSDocument} for the given Context and SubContext.
     * The supported contexts are: SIGNATURE, COUNTER_SIGNATURE, TIMESTAMP, EVIDENCE_RECORD, REVOCATION.
     * The supported subContext are: SIGNING_CERT and CA_CERTIFICATE.
     * The cryptographic suite will be used only for the specific scope.
     *
     * @param cryptographicSuite {@link DSSDocument}
     */
    public void setCryptographicSuiteForScope(DSSDocument cryptographicSuite, Context context, SubContext subContext) {
        cryptographicSuitesMap.computeIfAbsent(cryptographicSuite, k -> new ArrayList<>())
                .add(new ContextAndSubContext(context, subContext));
    }

    /**
     * Sets a cryptographic suite {@code InputStream} for the given Context and SubContext.
     * The supported contexts are: SIGNATURE, COUNTER_SIGNATURE, TIMESTAMP, EVIDENCE_RECORD, REVOCATION.
     * The supported subContext are: SIGNING_CERT and CA_CERTIFICATE.
     * The cryptographic suite will be used only for the specific scope.
     *
     * @param cryptographicSuiteIS {@link InputStream}
     */
    public void setCryptographicSuiteForScope(InputStream cryptographicSuiteIS, Context context, SubContext subContext) {
        setCryptographicSuiteForScope(new InMemoryDocument(cryptographicSuiteIS), context, subContext);
    }

    /**
     * Sets a cryptographic suite {@code File} for the given Context and SubContext.
     * The supported contexts are: SIGNATURE, COUNTER_SIGNATURE, TIMESTAMP, EVIDENCE_RECORD, REVOCATION.
     * The supported subContext are: SIGNING_CERT and CA_CERTIFICATE.
     * The cryptographic suite will be used only for the specific scope.
     *
     * @param cryptographicSuiteFile {@link File}
     */
    public void setCryptographicSuiteForScope(File cryptographicSuiteFile, Context context, SubContext subContext) {
        setCryptographicSuiteForScope(new FileDocument(cryptographicSuiteFile), context, subContext);
    }

    /**
     * Sets a cryptographic suite file for the given Context and SubContext.
     * The supported contexts are: SIGNATURE, COUNTER_SIGNATURE, TIMESTAMP, EVIDENCE_RECORD, REVOCATION.
     * The supported subContext are: SIGNING_CERT and CA_CERTIFICATE.
     * The cryptographic suite will be used only for the specific scope.
     *
     * @param cryptographicSuiteFilePath {@link File}
     */
    public void setCryptographicSuiteForScope(String cryptographicSuiteFilePath, Context context, SubContext subContext) {
        setCryptographicSuiteForScope(new File(cryptographicSuiteFilePath), context, subContext);
    }

    /**
     * Builds a {@code ValidationPolicy}
     *
     * @return {@link ValidationPolicy}
     */
    public ValidationPolicy create() {
        ValidationPolicy validationPolicy;
        if (validationPolicyDocument == null) {
            validationPolicy = loadDefaultPolicy();
        } else {
            validationPolicy = loadPolicy(validationPolicyDocument);
        }

        if (Utils.isMapNotEmpty(cryptographicSuitesMap)) {
            for (DSSDocument cryptographicSuiteDocument : cryptographicSuitesMap.keySet()) {
                ValidationPolicyWithCryptographicSuite validationPolicyWithCryptographicSuite =
                        new ValidationPolicyWithCryptographicSuite(validationPolicy);
                CryptographicSuite cryptographicSuite = loadCryptographicSuite(cryptographicSuiteDocument);
                for (ContextAndSubContext scope : cryptographicSuitesMap.get(cryptographicSuiteDocument)) {
                    if (scope == null) {
                        validationPolicyWithCryptographicSuite.setCryptographicSuite(cryptographicSuite);
                    } else {
                        validationPolicyWithCryptographicSuite.setCryptographicSuite(cryptographicSuite, scope.getContext(), scope.getSubContext());
                    }
                }
                validationPolicy = validationPolicyWithCryptographicSuite;
            }
        }
        return validationPolicy;
    }

    /**
     * Loads a default validation policy
     *
     * @return {@link ValidationPolicy}
     */
    protected ValidationPolicy loadDefaultPolicy() {
        ServiceLoader<ValidationPolicyFactory> loader = ServiceLoader.load(ValidationPolicyFactory.class);
        Iterator<ValidationPolicyFactory> factoryOptions = loader.iterator();

        if (factoryOptions.hasNext()) {
            // Loads the first one
            return factoryOptions.next().loadDefaultValidationPolicy();
        }
        throw new UnsupportedOperationException("No ValidationPolicyFactory has been found! " +
                "Please add 'dss-policy-jaxb' module to the classpath or create your own implementation.");
    }

    /**
     * Loads a validation policy from the given {@code DSSDocument}
     *
     * @param validationPolicyDocument {@link DSSDocument} representing the validation policy document
     * @return {@link ValidationPolicy}
     */
    protected ValidationPolicy loadPolicy(DSSDocument validationPolicyDocument) {
        ServiceLoader<ValidationPolicyFactory> loader = ServiceLoader.load(ValidationPolicyFactory.class);
        Iterator<ValidationPolicyFactory> factoryOptions = loader.iterator();

        if (factoryOptions.hasNext()) {
            for (ValidationPolicyFactory factory : loader) {
                if (factory.isSupported(validationPolicyDocument)) {
                    return factory.loadValidationPolicy(validationPolicyDocument);
                }
            }
            return factoryOptions.next().loadDefaultValidationPolicy();
        }
        throw new UnsupportedOperationException("No suitable ValidationPolicyFactory has been found! " +
                "Please add 'dss-policy-jaxb' module to the classpath for a DSS XML Validation Policy or " +
                "create your own implementation for a custom policy.");
    }

    private CryptographicSuite loadCryptographicSuite(DSSDocument cryptographicSuiteDocument) {
        ServiceLoader<CryptographicSuiteFactory> loader = ServiceLoader.load(CryptographicSuiteFactory.class);
        Iterator<CryptographicSuiteFactory> factoryOptions = loader.iterator();

        if (factoryOptions.hasNext()) {
            for (CryptographicSuiteFactory factory : loader) {
                if (factory.isSupported(cryptographicSuiteDocument)) {
                    return factory.loadCryptographicSuite(cryptographicSuiteDocument);
                }
            }
        }
        throw new UnsupportedOperationException("No suitable CryptographicSuiteFactory has been found! " +
                "Please add 'dss-policy-crypto-xml' or 'dss-policy-crypto-json' module to the classpath for " +
                "a Cryptographic Suite support or create your own implementation for a custom cryptographic suite policy.");
    }

}
