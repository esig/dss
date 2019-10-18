package eu.europa.esig.dss.tsl.alerts.handlers.log;

import eu.europa.esig.dss.spi.tsl.TLInfo;

public class LogParsingAlert extends AbstractTLLogAlert {

	@Override
	public void alert(TLInfo currentInfo) {
		LOG.warn("There was an error while parsing a TL : {}", currentInfo.getUrl());
	}

	
}
