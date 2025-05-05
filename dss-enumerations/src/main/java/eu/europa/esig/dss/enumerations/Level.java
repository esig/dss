package eu.europa.esig.dss.enumerations;

/**
 * Defines a Validation Policy constraint execution level
 *
 */
public enum Level {

    /**
     * Stops the validation process and reports as error
     *
     */
    FAIL,

    /**
     * Continues the validation process and adds a warning message
     *
     */
    WARN,

    /**
     * Continues the validation process and adds an informative message
     *
     */
    INFORM,

    /**
     * Continues the validation process and skips the current check (equals to not present check)
     *
     */
    IGNORE;

}
