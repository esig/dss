package eu.europa.esig.dss.ws.dto.exception;

/**
 * Exception to be thrown in case of Remote Service error
 */
public class DSSRemoteServiceException extends RuntimeException {

	private static final long serialVersionUID = 7836605176128624553L;

	public DSSRemoteServiceException() {
        super();
    }

    public DSSRemoteServiceException(String message) {
        super(message);
    }

    public DSSRemoteServiceException(Throwable cause) {
        super(cause);
    }

    public DSSRemoteServiceException(String message, Throwable cause) {
        super(message, cause);
    }

}
