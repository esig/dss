package eu.europa.esig.dss.alert;

import eu.europa.esig.dss.alert.handler.ThrowAlertExceptionHandler;
import eu.europa.esig.dss.alert.status.Status;

public class ExceptionOnStatusAlert extends AbstractStatusAlert {

	public ExceptionOnStatusAlert() {
		super(new ThrowAlertExceptionHandler<Status>());
	}

}
