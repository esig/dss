package eu.europa.esig.dss.tsl.alerts.handlers.log;

import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.spi.tsl.LOTLInfo;
import eu.europa.esig.dss.spi.tsl.PivotInfo;
import eu.europa.esig.dss.tsl.alerts.handlers.AlertHandler;
import eu.europa.esig.dss.utils.Utils;

public class LogLOTLLocationChangeAlertHandler implements AlertHandler<LOTLInfo> {

	private static final Logger LOG = LoggerFactory.getLogger(LogLOTLLocationChangeAlertHandler.class);

	@Override
	public void alert(LOTLInfo currentInfo) {
		List<PivotInfo> pivotInfos = currentInfo.getPivotInfos();
		if (Utils.isCollectionNotEmpty(pivotInfos)) {
			for (PivotInfo pivotInfo : pivotInfos) {
				if (!Utils.areStringsEqual(pivotInfo.getLOTLLocation(), currentInfo.getUrl())) {
					LOG.warn("The LOTL Location has changed - new location : {}", pivotInfo.getLOTLLocation());
					break;
				}
			}
		}
	}

}
