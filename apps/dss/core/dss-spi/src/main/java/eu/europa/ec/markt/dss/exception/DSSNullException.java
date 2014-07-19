package eu.europa.ec.markt.dss.exception;

import eu.europa.ec.markt.dss.DSSUtils;

/**
 * This class is used when a null object is detected.
 *
 * <p>
 * DISCLAIMER: Project owner DG-MARKT.
 *
 * @author <a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
 * @version $Revision: 1016 $ - $Date: 2011-06-17 15:30:45 +0200 (Fri, 17 Jun 2011) $
 */
public class DSSNullException extends DSSException {

    /**
     * This constructor creates an exception with the name of the parameter's class.
     *
     * @param parameter the null object
     */
    public DSSNullException(final Class<?> parameter) {

        super("Parameter: " + parameter.getName() + " cannot be null.");
    }

    /**
     * This constructor creates an exception with the name of the parameter's class and the name of the parameter. This constructor can be used when
     * the class of the parameter doesn't allow to unambiguously identify the parameter.
     *
     * @param javaClass the null object
     * @param name      the name of the null object
     */
    public DSSNullException(final Class<?> javaClass, final String name) {

        super("Parameter with name: " + name + "[" + javaClass.getName() + "] cannot be null.");
    }

    public DSSNullException(final Class<?> javaClass, final String name, final String message) {

        super("Parameter:" + (DSSUtils.isNotBlank(name) ? (" " + name) : "") + "[" + javaClass.getName() + "] cannot be null. " + message);
    }
}
