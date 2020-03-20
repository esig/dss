package eu.europa.esig.dss.alert.exception;

/**
 * Exception to be thrown by a DSSExceptionAlert
 *
 */
public class AlertException extends RuntimeException {

	private static final long serialVersionUID = 4633744799611311623L;

	public AlertException() {
        super();
    }

    public AlertException(String message) {
        super(message);
    }

    public AlertException(Throwable cause) {
        super(cause);
    }

    public AlertException(String message, Throwable cause) {
        super(message, cause);
    }

}
