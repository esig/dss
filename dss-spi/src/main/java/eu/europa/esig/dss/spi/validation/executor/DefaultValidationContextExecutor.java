package eu.europa.esig.dss.spi.validation.executor;

import eu.europa.esig.dss.spi.validation.ValidationContext;

import java.util.Objects;

/**
 * This class performs basic validation of {@code eu.europa.esig.dss.spi.validation.ValidationContext},
 * including certificate chain building and revocation data extraction, without executing different validity checks
 *
 */
public class DefaultValidationContextExecutor implements ValidationContextExecutor {

    /** Singleton instance */
    public static final DefaultValidationContextExecutor INSTANCE = new DefaultValidationContextExecutor();

    /**
     * Default constructor
     */
    private DefaultValidationContextExecutor() {
        // empty
    }

    @Override
    public void validate(ValidationContext validationContext) {
        Objects.requireNonNull(validationContext, "ValidationContext cannot be null!");
        validationContext.validate();
    }

}
