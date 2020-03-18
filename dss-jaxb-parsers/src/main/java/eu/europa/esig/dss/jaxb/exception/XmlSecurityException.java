package eu.europa.esig.dss.jaxb.exception;

/**
 * The exception raised in case of a security issue on xml configuration
 *
 */
public class XmlSecurityException extends Exception {

	private static final long serialVersionUID = 4154185562397996470L;

	public XmlSecurityException() {
        super();
    }

    public XmlSecurityException(String message) {
        super(message);
    }

    public XmlSecurityException(Throwable cause) {
        super(cause);
    }

    public XmlSecurityException(String message, Throwable cause) {
        super(message, cause);
    }

}
