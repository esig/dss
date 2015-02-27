package eu.europa.ec.markt.dss.exception;

/**
 * TODO
 *
 * <p>
 * DISCLAIMER: Project owner DG-MARKT.
 *
 * @author <a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
 * @version $Revision: 1016 $ - $Date: 2011-06-17 15:30:45 +0200 (Fri, 17 Jun 2011) $
 */
public class DSSNotApplicableMethodException extends DSSException {

    /**
     * This constructor creates an exception with the name of the parameter's class.
     *
     * @param parameter the null object
     */
    public DSSNotApplicableMethodException(final Class<?> parameter) {

        super("This method is not applicable for class: " + parameter.getName() + ". See javadoc for more information.");
    }

}
