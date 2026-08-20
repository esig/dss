package eu.europa.esig.dss.tsl.alerts.detections;

import eu.europa.esig.dss.alert.detector.AlertDetector;
import eu.europa.esig.dss.model.tsl.TLInfo;

import java.util.HashMap;
import java.util.Map;

/**
 * Detects erroneous modifications in a Trusted List's TSLSequenceNumber
 *
 */
public class TSLSequenceNumberErrorDetection implements AlertDetector<TLInfo> {

    /** Map by a URL location */
    private final Map<String, TLInfo> locationMap = new HashMap<>();

    /** Map by a country code */
    private final Map<String, TLInfo> countryCodeMap = new HashMap<>();

    /**
     * Default constructor
     */
    public TSLSequenceNumberErrorDetection() {
        // empty
    }

    @Override
    public boolean detect(TLInfo info) {
        if (info.getParsingCacheInfo() == null || !info.getParsingCacheInfo().isResultExist()) {
            return false; // error -> skip
        }

        String url = info.getUrl();
        String territory = info.getParsingCacheInfo().getTerritory();

        TLInfo previousInfo = getPreviousInfo(url, territory);

        // update entries
        locationMap.put(url, info);
        countryCodeMap.put(territory, info);

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

    private TLInfo getPreviousInfo(String url, String territory) {
        TLInfo previousInfoByLocation = locationMap.get(url);
        TLInfo previousInfoByCountryCode = countryCodeMap.get(territory);

        TLInfo previousInfo = null;
        if (previousInfoByLocation != null && previousInfoByLocation.getParsingCacheInfo() != null
                && previousInfoByLocation.getParsingCacheInfo().isResultExist()) {
            previousInfo = previousInfoByLocation;
        } else if (previousInfoByCountryCode != null && previousInfoByCountryCode.getParsingCacheInfo() != null
                && previousInfoByCountryCode.getParsingCacheInfo().isResultExist() && !url.equals(previousInfoByCountryCode.getUrl())) {
            previousInfo = previousInfoByCountryCode;
        }
        return previousInfo;
    }

    private boolean isUpToDate(TLInfo previousInfo, TLInfo newInfo) {
        return previousInfo.getDownloadCacheInfo() != null && newInfo.getDownloadCacheInfo() != null && 
                previousInfo.getDownloadCacheInfo().getDigest() != null && 
                previousInfo.getDownloadCacheInfo().getDigest().equals(newInfo.getDownloadCacheInfo().getDigest());
    }

}
