package eu.europa.esig.dss.tsl.summary;

import java.util.List;

import eu.europa.esig.dss.tsl.cache.CacheAccessByKey;
import eu.europa.esig.dss.tsl.dto.OtherTSLPointerDTO;
import eu.europa.esig.dss.tsl.dto.TrustServiceProvider;

public class LOTLInfo extends TLInfo {

	public LOTLInfo(final CacheAccessByKey cacheAccessByKey, final String url) {
		super(cacheAccessByKey, url);
	}
	
	@Override
	public List<TrustServiceProvider> getTrustServiceProviders() {
		// not applicable for LOTL
		return null;
	}
	
	/**
	 * Returns a list of LOTL {@link OtherTSLPointerDTO}s
	 * @return list of {@link OtherTSLPointerDTO}s
	 */
	public List<OtherTSLPointerDTO> getLOTLOtherPointers() {
		return cacheAccessByKey.getParsingCacheDataAccess().getLOTLOtherPointers();
	}
	
	/**
	 * Returns a list of containing in the LOTL pivot urls
	 * @return list of {@link String} pivot urls
	 */
	public List<String> getPivotUrls() {
		return cacheAccessByKey.getParsingCacheDataAccess().getPivotUrls();
	}

}
