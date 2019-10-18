package eu.europa.esig.dss.tsl.alerts.handlers.log;

import eu.europa.esig.dss.spi.tsl.LOTLInfo;

public class LogOJUrlChangeAlert extends AbstractLOTLLogAlert {

	@Override
	public void alert(LOTLInfo currentInfo) {
		LOG.warn("The Official Journal URL has changed - new location : {}", currentInfo.getParsingCacheInfo().getSigningCertificateAnnouncementUrl());
	}

}
