package eu.europa.esig.dss.tsl.alerts;

import eu.europa.esig.dss.spi.tsl.TLValidationJobSummary;
import eu.europa.esig.dss.tsl.alerts.detections.Detection;
import eu.europa.esig.dss.tsl.alerts.handlers.AlertHandler;

public abstract class Alert<T> {

	protected final Detection<T> detection;
	protected final AlertHandler<T> handler;

	public Alert(Detection<T> detection, AlertHandler<T> handler) {
		this.detection = detection;
		this.handler = handler;
	}

	public abstract void detectAndAlert(TLValidationJobSummary jobSummary); 
	
}
