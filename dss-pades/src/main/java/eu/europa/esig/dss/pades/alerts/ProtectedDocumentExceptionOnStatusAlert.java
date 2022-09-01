package eu.europa.esig.dss.pades.alerts;

import eu.europa.esig.dss.alert.AbstractStatusAlert;
import eu.europa.esig.dss.alert.handler.AlertHandler;
import eu.europa.esig.dss.alert.status.Status;
import eu.europa.esig.dss.pades.exception.ProtectedDocumentException;

/**
 * This alert is used to throw a {@code eu.europa.esig.dss.pades.exception.ProtectedDocumentException}
 * when the corresponding check fails
 *
 */
public class ProtectedDocumentExceptionOnStatusAlert extends AbstractStatusAlert {

    /**
     * The default constructor
     */
    public ProtectedDocumentExceptionOnStatusAlert() {
        super(new AlertHandler<Status>() {

            @Override
            public void process(Status object) {
                throw new ProtectedDocumentException(object.getErrorString());
            }

        });
    }

}
