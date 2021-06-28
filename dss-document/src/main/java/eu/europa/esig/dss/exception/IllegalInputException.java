package eu.europa.esig.dss.exception;

/**
 * This exception indicates that a provided by the user input or file is not valid for a particular operation
 *
 */
public class IllegalInputException extends RuntimeException {

    /**
     * Default constructor
     *
     * @param message {@link String} describing the exception
     */
    public IllegalInputException(String message) {
        super(message);
    }

    /**
     * Default constructor with original exception
     *
     * @param message {@link String} describing the exception
     * @param throwable {@link Throwable} exception
     */
    public IllegalInputException(String message, Throwable throwable) {
        super(message, throwable);
    }

}
