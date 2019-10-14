package eu.europa.esig.dss.tsl.alerts.detections;

import java.util.Date;

import eu.europa.esig.dss.spi.tsl.ParsingInfoRecord;
import eu.europa.esig.dss.spi.tsl.TLInfo;
import eu.europa.esig.dss.tsl.source.TLSource;

public class TLExpirationDetection extends AbstractTLDetection {

	protected TLExpirationDetection(TLSource tlSource) {
		super(tlSource);
	}

	public TLExpirationDetection() {
	}

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
