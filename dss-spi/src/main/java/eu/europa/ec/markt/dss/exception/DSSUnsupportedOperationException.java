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
public class DSSUnsupportedOperationException extends DSSException {

    public DSSUnsupportedOperationException(final String message) {

        super("This operation is unsupported:" + message);
    }
}
