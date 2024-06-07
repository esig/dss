package eu.europa.esig.dss.validation.executor.context;

import eu.europa.esig.dss.spi.validation.ValidationContext;
import eu.europa.esig.dss.spi.validation.ValidationContextExecutor;

import java.util.Objects;

/**
 * This class performs basic validation of {@code eu.europa.esig.dss.spi.validation.ValidationContext},
 * including certificate chain building and revocation data extraction, without executing different validity checks
 *
 */
public class DefaultValidationContextExecutor implements ValidationContextExecutor {

    /** Singleton instance */
    private static DefaultValidationContextExecutor instance;

    /**
     * Default constructor
     */
    private DefaultValidationContextExecutor() {
        // empty
    }

    /**
     * Gets the instance of {@code DefaultValidationContextExecutor}
     *
     * @return {@link DefaultValidationContextExecutor}
     */
    public static DefaultValidationContextExecutor getInstance() {
        if (instance == null) {
            instance = new DefaultValidationContextExecutor();
        }
        return instance;
    }

    @Override
    public void validate(ValidationContext validationContext) {
        Objects.requireNonNull(validationContext, "ValidationContext cannot be null!");
        validationContext.validate();
    }

}
