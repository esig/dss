package eu.europa.esig.dss.pki.exception;

/**
 * Represents an error state occurred within a PKI factory processing
 *
 */
public class PKIException extends RuntimeException {

    private static final long serialVersionUID = 169016737311236775L;

    /**
     * Empty constructor
     */
    public PKIException() {
        super();
    }

    /**
     * Constructor with a message
     *
     * @param message {@link String}
     */
    public PKIException(String message) {
        super(message);
    }

    /**
     * Re-throwable constructor
     *
     * @param cause {@link Throwable}
     */
    public PKIException(Throwable cause) {
        super(cause);
    }

    /**
     * Re-throwable constructor with a custom message
     *
     * @param message {@link String}
     * @param cause {@link Throwable}
     */
    public PKIException(String message, Throwable cause) {
        super(message, cause);
    }

}
