package eu.europa.esig.dss.tsl.summary;

import java.util.List;

import eu.europa.esig.dss.tsl.cache.CacheKey;
import eu.europa.esig.dss.tsl.cache.DownloadCache;
import eu.europa.esig.dss.tsl.cache.ParsingCache;
import eu.europa.esig.dss.tsl.cache.ValidationCache;
import eu.europa.esig.dss.tsl.dto.OtherTSLPointerDTO;
import eu.europa.esig.dss.tsl.dto.TrustServiceProvider;

public class LOTLInfo extends TLInfo {

	public LOTLInfo(final CacheKey cacheKey, final String url, final DownloadCache downloadCache, final ParsingCache parsingCache,
			final ValidationCache validationCache) {
		super(cacheKey, url, downloadCache, parsingCache, validationCache);
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
		return parsingCache.getLOTLOtherPointers(cacheKey);
	}
	
	/**
	 * Returns a list of containing in the LOTL pivot urls
	 * @return list of {@link String} pivot urls
	 */
	public List<String> getPivotUrls() {
		return parsingCache.getPivotUrls(cacheKey);
	}

}
