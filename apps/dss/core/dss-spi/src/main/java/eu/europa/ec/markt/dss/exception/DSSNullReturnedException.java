package eu.europa.ec.markt.dss.exception;

/**
 * This class is used when a null object is returned.
 *
 * <p>
 * DISCLAIMER: Project owner DG-MARKT.
 *
 * @author <a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
 * @version $Revision: 1016 $ - $Date: 2011-06-17 15:30:45 +0200 (Fri, 17 Jun 2011) $
 */
public class DSSNullReturnedException extends DSSException {

    /**
     * This constructor creates an exception when null is returned.
     */
    public DSSNullReturnedException(String message) {

        super("Null returned: " + message);
    }

    public DSSNullReturnedException(Class<?> aClass) {

        super("Null returned for: " + aClass.getName());
    }
}
