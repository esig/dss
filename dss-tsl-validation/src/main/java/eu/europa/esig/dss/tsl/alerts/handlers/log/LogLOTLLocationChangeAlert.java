package eu.europa.esig.dss.tsl.alerts.handlers.log;

import eu.europa.esig.dss.spi.tsl.LOTLInfo;

public class LogLOTLLocationChangeAlert extends AbstractLOTLLogAlert {

	@Override
	public void alert(LOTLInfo currentInfo) {
		LOG.warn("The LOTL Location has changed - new location : {}", currentInfo.getUrl());
	}

}
