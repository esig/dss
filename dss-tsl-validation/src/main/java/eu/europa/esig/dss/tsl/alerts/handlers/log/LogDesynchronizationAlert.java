package eu.europa.esig.dss.tsl.alerts.handlers.log;

import eu.europa.esig.dss.spi.tsl.TLInfo;

public class LogDesynchronizationAlert extends AbstractTLLogAlert {

	@Override
	public void alert(TLInfo currentInfo) {
		LOG.warn("There are some Desynchronization problems please update the following TL : {}", currentInfo.getParsingCacheInfo().getTerritory());
	}

}
