package eu.europa.esig.dss.tsl.alerts;

import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.spi.tsl.TLValidationJobSummary;

public class Alerter {

	private static final Logger LOG = LoggerFactory.getLogger(Alerter.class);

	private List<Alert<?>> alerts;
	private TLValidationJobSummary jobSummary;

	public Alerter(TLValidationJobSummary jobSummary, List<Alert<?>> alerts) {
		this.alerts = alerts;
		this.jobSummary = jobSummary;
	}

	public void detectChanges() {
		for (Alert<?> alert : alerts) {
			try {
				alert.detectAndAlert(jobSummary);
			} catch (Exception e) {
				LOG.warn("An error occurred while trying to detect changes inside a TL or LOTL.", e);
			}
		}
	}
}
