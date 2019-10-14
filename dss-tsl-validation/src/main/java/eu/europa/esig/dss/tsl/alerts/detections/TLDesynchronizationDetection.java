package eu.europa.esig.dss.tsl.alerts.detections;

import eu.europa.esig.dss.spi.tsl.DownloadInfoRecord;
import eu.europa.esig.dss.spi.tsl.ParsingInfoRecord;
import eu.europa.esig.dss.spi.tsl.TLInfo;
import eu.europa.esig.dss.spi.tsl.ValidationInfoRecord;

public class TLDesynchronizationDetection extends AbstractTLDetection{

	public TLDesynchronizationDetection() {
	}

	@Override
	public boolean detect(TLInfo info) {
		DownloadInfoRecord downloadCacheInfo = info.getDownloadCacheInfo();
		ParsingInfoRecord parsingCacheInfo = info.getParsingCacheInfo();
		ValidationInfoRecord validationCacheInfo = info.getValidationCacheInfo();
		
		// Send downloadCache Desyng Alert
		if(downloadCacheInfo.isDesynchronized()) {
			return true;
		}
		
		// Send parsingCache Desyng Alert
		if(parsingCacheInfo.isDesynchronized()) {
			return true;
		}
		
		// Send validationCache Desyng Alert
		if(validationCacheInfo.isDesynchronized()) {
			return true;
		}
		
		return false;
	}

}
