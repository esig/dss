package eu.europa.esig.dss.tsl.alerts.detections;

import eu.europa.esig.dss.spi.tsl.DownloadInfoRecord;
import eu.europa.esig.dss.spi.tsl.TLInfo;
import eu.europa.esig.dss.spi.tsl.ValidationInfoRecord;

public class TLSigningErrorDetection extends AbstractTLDetection {

	@Override
	public boolean detect(TLInfo info) {

		DownloadInfoRecord downloadCacheInfo = info.getDownloadCacheInfo();
		if (downloadCacheInfo.isDesynchronized()) {
			ValidationInfoRecord validationCacheInfo = info.getValidationCacheInfo();
			if (!validationCacheInfo.isValid()) {
				return true;
			}
		}

		return false;
	}

}
