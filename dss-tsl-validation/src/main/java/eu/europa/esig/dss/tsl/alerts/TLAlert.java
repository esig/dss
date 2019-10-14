package eu.europa.esig.dss.tsl.alerts;

import java.util.List;

import eu.europa.esig.dss.spi.tsl.LOTLInfo;
import eu.europa.esig.dss.spi.tsl.TLInfo;
import eu.europa.esig.dss.spi.tsl.TLValidationJobSummary;

public class TLAlert extends Alert<TLInfo> {

	public TLAlert(Detection<TLInfo> detection, AlertHandler<TLInfo> handler) {
		super(detection, handler);
	}

	@Override
	public void detectChanges(TLValidationJobSummary jobSummary) {
		List<LOTLInfo> lotlInfos = jobSummary.getLOTLInfos();
		for (LOTLInfo lotlInfo : lotlInfos) {
			detectOnTrustedLists(lotlInfo.getTLInfos());
		}
		detectOnTrustedLists(jobSummary.getOtherTLInfos());
	}

	private void detectOnTrustedLists(List<TLInfo> otherTLInfos) {
		for (TLInfo tlInfo : otherTLInfos) {
			if (detection.detect(tlInfo)) {
				handler.alert(tlInfo);
			}
		}
	}

}
