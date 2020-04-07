package eu.europa.esig.dss.alert;

import eu.europa.esig.dss.alert.detector.AlertDetector;
import eu.europa.esig.dss.alert.handler.SilentHandler;

public class SilentOnAlert<T> extends AbstractAlert<T> {

	public SilentOnAlert(AlertDetector<T> detector) {
		super(detector, new SilentHandler<T>());
	}

}
