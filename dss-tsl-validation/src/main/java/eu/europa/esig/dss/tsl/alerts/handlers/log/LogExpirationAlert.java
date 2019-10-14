package eu.europa.esig.dss.tsl.alerts.handlers.log;

import eu.europa.esig.dss.spi.tsl.TLInfo;

public class LogExpirationAlert extends AbstractTLLogAlert {

	@Override
	public void alert(TLInfo currentInfo) {
		LOG.warn("The " + currentInfo.getParsingCacheInfo().getTerritory() + " TL has expired. Last update : " + currentInfo.getParsingCacheInfo().getNextUpdateDate());
	}

	
}
