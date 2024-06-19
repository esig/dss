package eu.europa.esig.dss.spi.validation.executor;

import eu.europa.esig.dss.spi.validation.ValidationContext;

/**
 * This class skips validation of the {@code ValidationContext}
 *
 */
public class SkipValidationContextExecutor implements ValidationContextExecutor {

    /** Singleton instance */
    public static final SkipValidationContextExecutor INSTANCE = new SkipValidationContextExecutor();

    /**
     * Default constructor
     */
    private SkipValidationContextExecutor() {
        // empty
    }

    @Override
    public void validate(ValidationContext validationContext) {
        // skip
    }

}
