package eu.europa.esig.dss.tsl.alerts.detections;

import java.util.Date;

import eu.europa.esig.dss.spi.tsl.ParsingInfoRecord;
import eu.europa.esig.dss.spi.tsl.TLInfo;

public class TLExpirationDetection extends AbstractTLDetection {

	@Override
	public boolean detect(TLInfo info) {
		ParsingInfoRecord parsingCacheInfo = info.getParsingCacheInfo();
		Date nextUpdateDate = parsingCacheInfo.getNextUpdateDate();
		Date currentDate = new Date();
		
		if(nextUpdateDate != null && nextUpdateDate.before(currentDate)) {
			return true;
		}
		return false;
	}
	
}
