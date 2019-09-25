package eu.europa.esig.dss.tsl.summary;

import java.util.List;

import eu.europa.esig.dss.tsl.cache.CacheAccessFactory;
import eu.europa.esig.dss.tsl.cache.CacheKey;
import eu.europa.esig.dss.tsl.dto.OtherTSLPointerDTO;
import eu.europa.esig.dss.tsl.dto.TrustServiceProvider;

public class LOTLInfo extends TLInfo {

	public LOTLInfo(final CacheKey cacheKey, final String url) {
		super(cacheKey, url);
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
		return CacheAccessFactory.getParsingCacheDataAccess().getLOTLOtherPointers(cacheKey);
	}
	
	/**
	 * Returns a list of containing in the LOTL pivot urls
	 * @return list of {@link String} pivot urls
	 */
	public List<String> getPivotUrls() {
		return CacheAccessFactory.getParsingCacheDataAccess().getPivotUrls(cacheKey);
	}

}
