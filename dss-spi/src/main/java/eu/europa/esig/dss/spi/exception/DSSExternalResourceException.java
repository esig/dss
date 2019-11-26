package eu.europa.esig.dss.spi.exception;

import eu.europa.esig.dss.model.DSSException;

/**
 * The exception to be thrown in case of an external error arisen during a data loader requests
 *
 */
public class DSSExternalResourceException extends DSSException {

	private static final long serialVersionUID = 8290929546359871166L;
	
	DSSExternalResourceException() {
		super();
	}

    public DSSExternalResourceException(Throwable cause) {
        super(cause);
    }

    public DSSExternalResourceException(String message, Throwable cause) {
        super(message, cause);
    }
    
    /**
     * Returns cause {@code String} message
     * @return {@link String} caused exception's message
     */
    String getCauseMessage() {
    	return getCause().getMessage();
    }

}
