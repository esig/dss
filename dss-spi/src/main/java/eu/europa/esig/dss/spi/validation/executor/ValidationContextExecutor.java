package eu.europa.esig.dss.spi.validation.executor;

import eu.europa.esig.dss.spi.validation.ValidationContext;

/**
 * This class defines a strategy for execution of {@code ValidationContext}'s validation
 *
 */
public interface ValidationContextExecutor {

    /**
     * Performs validation of {@code validationContext}
     *
     * @param validationContext {@link ValidationContext} to be executed
     */
    void validate(ValidationContext validationContext);

}
