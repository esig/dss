package eu.europa.esig.dss.tsl.alerts.detections;

import eu.europa.esig.dss.spi.tsl.TLInfo;
import eu.europa.esig.dss.spi.tsl.ValidationInfoRecord;
import eu.europa.esig.dss.tsl.source.TLSource;

public class TLSigningErrorDetection extends AbstractTLDetection {

	protected TLSigningErrorDetection(TLSource tlSource) {
		super(tlSource);
	}

	public TLSigningErrorDetection() {
	}

	@Override
	public boolean detect(TLInfo info) {
		ValidationInfoRecord validationCacheInfo = info.getValidationCacheInfo();
		
		// If signature is TOTAL_FAILED
		if(validationCacheInfo.isInvalid()) {
			return true;
		}
		
		// If signature is INDETERMINATE
		if(validationCacheInfo.isIndeterminate()) {
			return true;
		}
		
		return false;
	}
	
}
