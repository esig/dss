package eu.europa.esig.dss.alert;

import eu.europa.esig.dss.alert.detector.StatusDetector;
import eu.europa.esig.dss.alert.handler.AlertHandler;
import eu.europa.esig.dss.alert.status.Status;

public abstract class AbstractStatusAlert extends AbstractAlert<Status> implements StatusAlert {

	protected AbstractStatusAlert(AlertHandler<Status> handler) {
		super(new StatusDetector(), handler);
	}

}
