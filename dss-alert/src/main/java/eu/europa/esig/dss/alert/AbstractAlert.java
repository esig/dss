package eu.europa.esig.dss.alert;

import eu.europa.esig.dss.alert.detector.AlertDetector;
import eu.europa.esig.dss.alert.handler.AlertHandler;

/**
 * The class containing a general logic for alert handling
 *
 */
public abstract class AbstractAlert<T> implements Alert<T> {

	protected final AlertDetector<T> detector;
	protected final AlertHandler<T> handler;

	protected AbstractAlert(AlertDetector<T> detector, AlertHandler<T> handler) {
		this.detector = detector;
		this.handler = handler;
	}

	@Override
	public void alert(T object) {
		if (detector.detect(object)) {
			handler.process(object);
		}
	}

}
