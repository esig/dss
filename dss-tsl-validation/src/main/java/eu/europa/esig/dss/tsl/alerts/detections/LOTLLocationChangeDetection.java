package eu.europa.esig.dss.tsl.alerts.detections;

import java.util.List;

import eu.europa.esig.dss.spi.tsl.LOTLInfo;
import eu.europa.esig.dss.spi.tsl.PivotInfo;
import eu.europa.esig.dss.tsl.source.LOTLSource;
import eu.europa.esig.dss.utils.Utils;

public class LOTLLocationChangeDetection extends AbstractLOTLDetection {

	public LOTLLocationChangeDetection(LOTLSource lotlSource) {
		super(lotlSource);
	}

	@Override
	public boolean detect(LOTLInfo info) {

		if (Utils.areStringsEqual(lotlSource.getUrl(), info.getUrl()) && lotlSource.isPivotSupport()) {

			List<PivotInfo> pivotInfos = info.getPivotInfos();
			if (Utils.isCollectionNotEmpty(pivotInfos)) {
				for (PivotInfo pivotInfo : pivotInfos) {
					if (!Utils.areStringsEqual(pivotInfo.getLOTLLocation(), lotlSource.getUrl())) {
						return true;
					}
				}
			}
		}
		return false;
	}

}
