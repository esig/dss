package eu.europa.esig.dss.validation.executor.context;

import eu.europa.esig.dss.spi.validation.ValidationContext;
import eu.europa.esig.dss.spi.validation.ValidationContextExecutor;

/**
 * This class skips validation of the {@code ValidationContext}
 *
 */
public class SkipValidationContextExecutor implements ValidationContextExecutor {

    /** Singleton instance */
    private static SkipValidationContextExecutor instance;

    /**
     * Default constructor
     */
    private SkipValidationContextExecutor() {
        // empty
    }

    /**
     * Gets the instance of {@code SkipValidationContextExecutor}
     *
     * @return {@link SkipValidationContextExecutor}
     */
    public static SkipValidationContextExecutor getInstance() {
        if (instance == null) {
            instance = new SkipValidationContextExecutor();
        }
        return instance;
    }

    @Override
    public void validate(ValidationContext validationContext) {
        // skip
    }

}
