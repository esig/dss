package eu.europa.esig.dss.validation.reports;

/**
 * Exception to be thrown in case of JAXB Report marshaling or unmarshaling error
 */
public class DSSReportException extends RuntimeException {

	private static final long serialVersionUID = -2849739549071583052L;

	public DSSReportException() {
        super();
    }

    public DSSReportException(String message) {
        super(message);
    }

    public DSSReportException(Throwable cause) {
        super(cause);
    }

    public DSSReportException(String message, Throwable cause) {
        super(message, cause);
    }

}
