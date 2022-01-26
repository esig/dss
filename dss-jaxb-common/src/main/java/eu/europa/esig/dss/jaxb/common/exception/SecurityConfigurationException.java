package eu.europa.esig.dss.jaxb.common.exception;

/**
 * This exception is used to catch and re-throw an exception caused by a security feature/attribute definition
 *
 */
public class SecurityConfigurationException extends Exception {

    private static final long serialVersionUID = 5905334726222259641L;

    /**
     * Default constructor
     *
     * @param e {@link Exception} to re-throw
     */
    public SecurityConfigurationException(Exception e) {
        super(e);
    }

}
