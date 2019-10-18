package eu.europa.esig.dss.tsl.alerts.detections;

import eu.europa.esig.dss.spi.tsl.LOTLInfo;
import eu.europa.esig.dss.spi.tsl.TLInfo;
import eu.europa.esig.dss.tsl.alerts.Detection;

public abstract class AbstractTLDetection implements Detection <TLInfo> {
	
	protected AbstractTLDetection() {}
	
	public boolean detect(LOTLInfo currentInfo) {
		// test on the TLInfo
		return false;
	}

}
