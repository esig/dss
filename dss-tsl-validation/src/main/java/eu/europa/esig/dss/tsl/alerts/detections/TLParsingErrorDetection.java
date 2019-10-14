package eu.europa.esig.dss.tsl.alerts.detections;

import eu.europa.esig.dss.spi.tsl.ParsingInfoRecord;
import eu.europa.esig.dss.spi.tsl.TLInfo;

public class TLParsingErrorDetection extends AbstractTLDetection {
	
	private String tlCountry;
	
	public void setTlCountry(String tlCountry) {
		this.tlCountry = tlCountry;
	}
	
	@Override
	public boolean detect(TLInfo info) {
		ParsingInfoRecord parsingCacheInfo = info.getParsingCacheInfo();
		if(tlCountry != null && !tlCountry.equals(parsingCacheInfo.getTerritory())) {
			return false;
		}

		return checkTL(parsingCacheInfo);
	}

	private boolean checkTL(ParsingInfoRecord parsingCacheInfo) {
		if(parsingCacheInfo.isError()) {
			return true;
		}	
		
		return false;
	}
}
