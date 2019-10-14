package eu.europa.esig.dss.tsl.alerts.detections;

import eu.europa.esig.dss.spi.tsl.LOTLInfo;
import eu.europa.esig.dss.spi.tsl.TLInfo;
import eu.europa.esig.dss.tsl.alerts.Detection;
import eu.europa.esig.dss.tsl.source.TLSource;

public abstract class AbstractTLDetection implements Detection <TLInfo> {

	protected TLSource tlSource;
	
	protected AbstractTLDetection(TLSource tlSource) {
		this.tlSource = tlSource;
	}
	
	protected AbstractTLDetection() {}
	
	public boolean detect(LOTLInfo currentInfo) {
		// test on the TLInfo
		return false;
	}

}
