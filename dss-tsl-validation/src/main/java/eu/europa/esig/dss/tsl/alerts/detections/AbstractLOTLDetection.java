package eu.europa.esig.dss.tsl.alerts.detections;

import eu.europa.esig.dss.spi.tsl.LOTLInfo;
import eu.europa.esig.dss.tsl.alerts.Detection;
import eu.europa.esig.dss.tsl.source.LOTLSource;

public abstract class AbstractLOTLDetection implements Detection<LOTLInfo> {

	protected final LOTLSource lotlSource;

	protected AbstractLOTLDetection(LOTLSource lotlSource) {
		this.lotlSource = lotlSource;
	}
	
}
