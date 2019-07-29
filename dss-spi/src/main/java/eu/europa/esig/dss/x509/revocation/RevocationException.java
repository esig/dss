package eu.europa.esig.dss.x509.revocation;

import eu.europa.esig.dss.DSSException;

public class RevocationException extends DSSException {
	
	private static final long serialVersionUID = -1698070921903310881L;

	public RevocationException() {
        super();
    }

    public RevocationException(String message) {
        super(message);
    }

    public RevocationException(Throwable cause) {
        super(cause);
    }

    public RevocationException(String message, Throwable cause) {
        super(message, cause);
    }

}
