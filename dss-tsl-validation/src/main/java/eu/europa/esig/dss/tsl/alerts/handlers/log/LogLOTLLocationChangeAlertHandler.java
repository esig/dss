package eu.europa.esig.dss.tsl.alerts.handlers.log;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.spi.tsl.LOTLInfo;
import eu.europa.esig.dss.tsl.alerts.handlers.AlertHandler;

public class LogLOTLLocationChangeAlertHandler implements AlertHandler<LOTLInfo> {

	private static final Logger LOG = LoggerFactory.getLogger(LogLOTLLocationChangeAlertHandler.class);

	@Override
	public void alert(LOTLInfo currentInfo) {
		LOG.warn("The LOTL Location has changed - new location : {}", currentInfo.getUrl());
	}

}
