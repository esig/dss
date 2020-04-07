package eu.europa.esig.dss.alert.detector;

import eu.europa.esig.dss.alert.status.Status;

public class StatusDetector implements AlertDetector<Status> {

	@Override
	public boolean detect(Status object) {
		return !object.isEmpty();
	}

}
