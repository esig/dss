package eu.europa.esig.dss.tsl.alerts.detections;

import java.util.Date;

import eu.europa.esig.dss.spi.tsl.ParsingInfoRecord;
import eu.europa.esig.dss.spi.tsl.TLInfo;

public class TLExpirationDetection implements Detection<TLInfo> {

	@Override
	public boolean detect(TLInfo info) {
		ParsingInfoRecord parsingCacheInfo = info.getParsingCacheInfo();
		Date nextUpdateDate = parsingCacheInfo.getNextUpdateDate();
		Date currentDate = new Date();
		
		return (nextUpdateDate != null && nextUpdateDate.before(currentDate));
	}
	
}
