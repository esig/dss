package eu.europa.esig.cbor;

import eu.europa.ec.digit.cddl4j.cbor.CBORValue;
import eu.europa.ec.digit.cddl4j.validator.CddlValidator;
import eu.europa.ec.digit.cddl4j.validator.schema.CddlSchema;
import eu.europa.ec.digit.cddl4j.validator.schema.operator.ControlOperator;
import eu.europa.ec.digit.cddl4j.validator.schema.type.CddlType;
import eu.europa.ec.digit.cddl4j.validator.validation.ValidationContext;
import eu.europa.ec.digit.cddl4j.validator.validation.ValidationError;
import eu.europa.ec.digit.cddl4j.validator.validation.ValidationResult;

import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Abstract class containing the logic for execution of the CBOR structure conformance validation against a CDDL schema
 *
 */
public abstract class CBORSchemaAbstractUtils {

    /** CDDL Schema */
    private CddlSchema cddlSchema;

    /**
     * Empty constructor
     */
    protected CBORSchemaAbstractUtils() {
        // empty
    }

    /**
     * Validates a CBOR against CDDL Schema
     *
     * @param is {@link InputStream} representing a CBOR to validate
     * @return a list of {@link String} messages containing errors occurred during
     *         the validation process, empty list when validation succeeds
     */
    public List<String> validateAgainstSchema(InputStream is) {
        ValidationResult validationResult = getCddlSchema().validate(is);
        return getValidationErrors(validationResult, null);
    }

    /**
     * Validates a CBOR against CDDL Schema using a specific root element rule
     *
     * @param is {@link InputStream} representing a CBOR to validate
     * @param rootRule {@link String} root rule
     * @return a list of {@link String} messages containing errors occurred during
     *         the validation process, empty list when validation succeeds
     */
    public List<String> validateAgainstSchema(InputStream is, String rootRule) {
        ValidationResult validationResult = getCddlSchema().validate(is, rootRule);
        return getValidationErrors(validationResult, rootRule);
    }

    /**
     * Validates a CBOR against CDDL schema
     *
     * @param cborBytes {@link String} representing a CBOR to validate
     * @return a list of {@link String} messages containing errors occurred during
     *         the validation process, empty list when validation succeeds
     */
    public List<String> validateAgainstSchema(byte[] cborBytes) {
        ValidationResult validationResult = getCddlSchema().validate(cborBytes);
        return getValidationErrors(validationResult, null);
    }

    /**
     * Validates a CBOR against CDDL schema using a specific root element rule
     *
     * @param cborBytes {@link String} representing a CBOR to validate
     * @param rootRule {@link String} root rule
     * @return a list of {@link String} messages containing errors occurred during
     *         the validation process, empty list when validation succeeds
     */
    public List<String> validateAgainstSchema(byte[] cborBytes, String rootRule) {
        ValidationResult validationResult = getCddlSchema().validate(cborBytes, rootRule);
        return getValidationErrors(validationResult, rootRule);
    }

    /**
     * Validates a CBOR against CDDL schema
     *
     * @param cborValue {@link CBORValue} representing a CBOR to validate
     * @return a list of {@link String} messages containing errors occurred during
     *         the validation process, empty list when validation succeeds
     */
    public List<String> validateAgainstSchema(CBORValue cborValue) {
        ValidationResult validationResult = getCddlSchema().validate(cborValue);
        return getValidationErrors(validationResult, null);
    }

    /**
     * Validates a CBOR against CDDL schema using a specific root element rule
     *
     * @param cborValue {@link CBORValue} representing a CBOR to validate
     * @param rootRule {@link String} root rule
     * @return a list of {@link String} messages containing errors occurred during
     *         the validation process, empty list when validation succeeds
     */
    public List<String> validateAgainstSchema(CBORValue cborValue, String rootRule) {
        ValidationResult validationResult = getCddlSchema().validate(cborValue, rootRule);
        return getValidationErrors(validationResult, rootRule);
    }

    /**
     * Gets a list of validation errors from the obtained validation result
     *
     * @param validationResult {@link ValidationResult}
     * @return a list of {@link String} errors. Empty list when validation succeeds.
     */
    protected List<String> getValidationErrors(ValidationResult validationResult, String rootRule) {
        if (validationResult != null && !validationResult.isValid()) {
            List<ValidationError> validationErrors = validationResult.getErrors();
            if (validationErrors != null && !validationErrors.isEmpty()) {
                validationErrors = filterValidationErrors(validationErrors, false);
                return validationErrors.stream().map(e -> toString(e, rootRule)).collect(Collectors.toList());
            }
        }
        return Collections.emptyList();
    }

    /**
     * This method filters validation messages in a way to return an error cause except of the root choice error,
     * in order to get a more relevant information of the error
     *
     * @param validationErrors a list of {@link ValidationError}s
     * @param cause if the current list of errors are the cause
     * @return a list of filtered {@link ValidationError}s
     */
    protected List<ValidationError> filterValidationErrors(List<ValidationError> validationErrors, boolean cause) {
        List<ValidationError> filteredErrors = new ArrayList<>();
        for (ValidationError validationError : validationErrors) {
            if (validationError.getMessage().contains("alternative (") || validationError.getMessage().contains("choice (")) {
                List<ValidationError> causeErrors = filterValidationErrors(validationError.getCauses(), true);
                if (causeErrors != null && !causeErrors.isEmpty()) {
                    if (filteredErrors.isEmpty()) {
                        filteredErrors.addAll(causeErrors);
                    } else {
                        if (containsAny(filteredErrors, causeErrors)) {
                            filteredErrors = intersection(filteredErrors, causeErrors);
                        } else {
                            filteredErrors.add(validationError);
                        }
                    }
                    continue;
                }
            }
            if (cause) {
                if ("/".equals(validationError.getInstancePath())) {
                    continue;
                }
            }
            filteredErrors.add(validationError);
        }
        return filteredErrors;
    }

    private boolean containsAny(List<ValidationError> originalList, List<ValidationError> listToCompare) {
        return originalList.stream().anyMatch(listToCompare::contains);
    }

    private List<ValidationError> intersection(List<ValidationError> originalList, List<ValidationError> listToCompare) {
        return originalList.stream().distinct().filter(listToCompare::contains).collect(Collectors.toList());
    }

    /**
     * Creates a validation message string, containing the element path, ignoring the causes
     *
     * @param validationError {@link ValidationError}
     * @return {@link String}
     */
    protected String toString(ValidationError validationError, String rootRule) {
        StringBuilder sb = new StringBuilder();
        if (rootRule != null) {
            sb.append(rootRule);
            sb.append(": ");
        }
        if (validationError.getInstancePath().isEmpty()) {
            sb.append("/");
        } else {
            sb.append(validationError.getInstancePath());
        }
        return String.format("[%s] %s", sb.toString(), validationError.getMessage());
    }

    /**
     * Gets the CDDL schema.
     * Returns a cached CDDL schema instance. Loads the schema at the first iteration.
     *
     * @return {@link CddlSchema}
     */
    protected CddlSchema getCddlSchema() {
        if (cddlSchema == null) {
            // TODO : .default control operator is not yet supported in cddl4j 0.1.0, update when possible
            cddlSchema = loadSchema(getSchemaLocation())
                    .withControlOperators(Collections.singletonList(DefaultControLOperator.INSTANCE));
        }
        return cddlSchema;
    }

    /**
     * Loads the CDDL schema
     *
     * @param schemaURI {@link String} URI to the schema in the resources
     * @return {@link CddlSchema}
     */
    protected CddlSchema loadSchema(String schemaURI) {
        return CddlValidator.loadSchemaFromResource(schemaURI);
    }

    /**
     * Gets the schema location URI in resources
     *
     * @return {@link String}
     */
    public abstract String getSchemaLocation();

    /**
     * Implements handling of the .default control operator
     */
    private static final class DefaultControLOperator implements ControlOperator {

        /** Singleton instance. */
        public static final DefaultControLOperator INSTANCE = new DefaultControLOperator();

        /**
         * Default constructor
         */
        private DefaultControLOperator() {
            // Singleton.
        }

        @Override
        public String getName() {
            return ".default";
        }

        @Override
        public ValidationResult validate(CBORValue value, CddlType controller, ValidationContext ctx) {
            return ValidationResult.success(); // no processing required
        }

    }

}
