package eu.europa.esig.dss.tsl.alerts.handlers.log;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.spi.tsl.TLInfo;
import eu.europa.esig.dss.tsl.alerts.handlers.AlertHandler;

public class LogTLExpirationAlertHandler implements AlertHandler<TLInfo> {

	private static final Logger LOG = LoggerFactory.getLogger(LogTLExpirationAlertHandler.class);

	@Override
	public void alert(TLInfo currentInfo) {
		LOG.warn("The '{}' TL has expired. Last update : {}", currentInfo.getUrl(), currentInfo.getParsingCacheInfo().getNextUpdateDate());
	}
	
}
