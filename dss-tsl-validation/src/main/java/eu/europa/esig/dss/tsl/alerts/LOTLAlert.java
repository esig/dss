package eu.europa.esig.dss.tsl.alerts;

import java.util.List;

import eu.europa.esig.dss.spi.tsl.LOTLInfo;
import eu.europa.esig.dss.spi.tsl.TLValidationJobSummary;
import eu.europa.esig.dss.tsl.alerts.detections.Detection;
import eu.europa.esig.dss.tsl.alerts.handlers.AlertHandler;

public class LOTLAlert extends Alert<LOTLInfo> {

	public LOTLAlert(Detection<LOTLInfo> detection, AlertHandler<LOTLInfo> handler) {
		super(detection, handler);
	}

	@Override
	public void detectAndAlert(TLValidationJobSummary jobSummary) {
		List<LOTLInfo> lotlInfos = jobSummary.getLOTLInfos();
		for (LOTLInfo lotlInfo : lotlInfos) {
			if (detection.detect(lotlInfo)) {
				handler.alert(lotlInfo);
			}
		}
	}

}
