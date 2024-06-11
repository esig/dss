package eu.europa.esig.dss.validation.executor.context;

import eu.europa.esig.dss.spi.validation.ValidationContext;
import eu.europa.esig.dss.spi.validation.ValidationContextExecutor;

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
