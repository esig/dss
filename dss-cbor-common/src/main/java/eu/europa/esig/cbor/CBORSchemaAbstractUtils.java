package eu.europa.esig.cbor;

import eu.europa.ec.digit.cddl4j.cbor.CBORValue;
import eu.europa.ec.digit.cddl4j.validator.CddlValidator;
import eu.europa.ec.digit.cddl4j.validator.schema.CddlSchema;
import eu.europa.ec.digit.cddl4j.validator.validation.ValidationError;
import eu.europa.ec.digit.cddl4j.validator.validation.ValidationResult;

import java.io.InputStream;
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
                return validationErrors.stream().map(e -> toString(e, rootRule)).collect(Collectors.toList());
            }
        }
        return Collections.emptyList();
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
            cddlSchema = loadSchema(getSchemaLocation());
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

}
