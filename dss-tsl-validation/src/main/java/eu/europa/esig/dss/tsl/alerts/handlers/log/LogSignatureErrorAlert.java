package eu.europa.esig.dss.tsl.alerts.handlers.log;

import eu.europa.esig.dss.spi.tsl.TLInfo;

public class LogSignatureErrorAlert extends AbstractTLLogAlert {

	@Override
	public void alert(TLInfo currentInfo) {
		LOG.warn("There is a problem in the TL signature : {}", currentInfo.getParsingCacheInfo().getTerritory());
	}

}
