package eu.europa.esig.dss.tsl.alerts.detections;

import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.spi.tsl.LOTLInfo;
import eu.europa.esig.dss.spi.tsl.OtherTSLPointer;
import eu.europa.esig.dss.tsl.source.LOTLSource;
import eu.europa.esig.dss.utils.Utils;

public class LOTLLocationChangeDetection extends AbstractLOTLDetection {
	
	private static final Logger LOG = LoggerFactory.getLogger(LOTLLocationChangeDetection.class);

	public LOTLLocationChangeDetection(LOTLSource lotlSource) {
		super(lotlSource);
	}

	private boolean checkPivots(LOTLInfo lotlInfo, String sourceUrl) {
		String pivotUrl = getPivotUrl(lotlInfo);
		if(!pivotUrl.equals(sourceUrl)) {
			return true;
		}
		return false;
	}

	// TODO Here we need the two links from the old LOTL and the new LOTL to be compared ? 
	@Override
	public boolean detect(LOTLInfo info) {
		if(lotlSource.isPivotSupport()) {
			String sourceUrl = lotlSource.getUrl();
			String infoUrl = info.getUrl();

			if(!sourceUrl.equals(infoUrl)) {
				return checkPivots(info, sourceUrl);
			}
		}
		return false;
	}
	
	// TODO We have to update the DTO to contain this information
	private String getPivotUrl(LOTLInfo lotlInfo) {
		List<OtherTSLPointer> lotlOtherPointers = lotlInfo.getParsingCacheInfo().getLotlOtherPointers();

		int nbLOTLPointersInPivot = Utils.collectionSize(lotlOtherPointers);
		if (nbLOTLPointersInPivot == 1) {
			OtherTSLPointer currentLOTLPointer = lotlOtherPointers.get(0);
			return currentLOTLPointer.getLocation();
		} else {
			LOG.warn("Unable to find the LOTL Pointer in the pivot (nb occurrence : {})", nbLOTLPointersInPivot);
		}
		return "";
	}

}
