package eu.europa.esig.dss.alert;

import eu.europa.esig.dss.alert.detector.StatusDetector;
import eu.europa.esig.dss.alert.status.Status;

public class SilentOnStatusAlert extends SilentOnAlert<Status> {

	public SilentOnStatusAlert() {
		super(new StatusDetector());
	}

}
