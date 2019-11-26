package eu.europa.esig.dss.tsl.alerts.detections;

import eu.europa.esig.dss.spi.tsl.ParsingInfoRecord;
import eu.europa.esig.dss.spi.tsl.TLInfo;

public class TLParsingErrorDetection implements Detection<TLInfo> {
	
	@Override
	public boolean detect(TLInfo info) {
		ParsingInfoRecord parsingCacheInfo = info.getParsingCacheInfo();
		return parsingCacheInfo.isError();
	}
	
}
