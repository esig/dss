package eu.europa.esig.dss.tsl.alerts;

import eu.europa.esig.dss.spi.tsl.TLValidationJobSummary;

public abstract class Alert<T> {

	protected final Detection<T> detection;
	protected final AlertHandler<T> handler;

	public Alert(Detection<T> detection, AlertHandler<T> handler) {
		this.detection = detection;
		this.handler = handler;
	}

	public Detection<T> getDetection() {
		return detection;
	}

	public AlertHandler<T> getHandler() {
		return handler;
	}

	public abstract void detectChanges(TLValidationJobSummary jobSummary); 
	
}
