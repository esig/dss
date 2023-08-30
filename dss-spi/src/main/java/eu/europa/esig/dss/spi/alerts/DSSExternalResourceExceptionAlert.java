package eu.europa.esig.dss.spi.alerts;

import eu.europa.esig.dss.alert.AbstractStatusAlert;
import eu.europa.esig.dss.alert.handler.AlertHandler;
import eu.europa.esig.dss.alert.status.Status;
import eu.europa.esig.dss.spi.exception.DSSExternalResourceException;

/**
 * This alert is used to throw a {@code eu.europa.esig.dss.spi.exception.DSSExternalResourceException}
 * when the corresponding check fails
 *
 */
public class DSSExternalResourceExceptionAlert extends AbstractStatusAlert {

    /**
     * The default constructor
     */
    public DSSExternalResourceExceptionAlert() {
        super(new AlertHandler<Status>() {

            @Override
            public void process(Status object) {
                throw new DSSExternalResourceException(object.getErrorString());
            }

        });
    }

}
