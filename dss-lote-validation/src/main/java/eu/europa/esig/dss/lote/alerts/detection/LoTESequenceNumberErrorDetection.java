package eu.europa.esig.dss.lote.alerts.detection;

import eu.europa.esig.dss.alert.detector.AlertDetector;
import eu.europa.esig.dss.model.lote.LoTEInfo;

import java.util.HashMap;
import java.util.Map;

/**
 * Detects erroneous modifications in a LoTE's LoTESequenceNumber.
 * NOTE: As opposite to {@code eu.europa.esig.dss.tsl.alerts.detections.TSLSequenceNumberErrorDetection},
 * this class performs verification by only using the URL location comparison.
 *
 */
public class LoTESequenceNumberErrorDetection implements AlertDetector<LoTEInfo> {

    /** Map by a URL location */
    private final Map<String, LoTEInfo> locationMap = new HashMap<>();

    /**
     * Default constructor
     */
    public LoTESequenceNumberErrorDetection() {
        // empty
    }

    @Override
    public boolean detect(LoTEInfo info) {
        if (info.getParsingCacheInfo() == null || !info.getParsingCacheInfo().isResultExist()) {
            return false; // error -> skip
        }

        String url = info.getUrl();
        LoTEInfo previousInfo = getPreviousInfo(url);

        // update entries
        locationMap.put(url, info);

        if (previousInfo == null || isUpToDate(previousInfo, info)) {
            // first entry or no changes -> continue
            return false;
        }

        Integer newSequenceNumber = info.getParsingCacheInfo().getSequenceNumber();
        if (newSequenceNumber == null) {
            // no sequence number present, trigger alert
            return true;
        }

        Integer previousSequenceNumber = previousInfo.getParsingCacheInfo().getSequenceNumber();
        if (previousSequenceNumber != null && previousSequenceNumber >= newSequenceNumber) {
            // new value shall be incremented in updated document
            return true;
        }

        return false;
    }

    private LoTEInfo getPreviousInfo(String url) {
        LoTEInfo previousInfoByLocation = locationMap.get(url);
        if (previousInfoByLocation != null && previousInfoByLocation.getParsingCacheInfo() != null
                && previousInfoByLocation.getParsingCacheInfo().isResultExist()) {
            return previousInfoByLocation;
        }
        return null;
    }

    private boolean isUpToDate(LoTEInfo previousInfo, LoTEInfo newInfo) {
        return previousInfo.getDownloadCacheInfo() != null && newInfo.getDownloadCacheInfo() != null &&
                previousInfo.getDownloadCacheInfo().getDigest() != null &&
                previousInfo.getDownloadCacheInfo().getDigest().equals(newInfo.getDownloadCacheInfo().getDigest());
    }

}
