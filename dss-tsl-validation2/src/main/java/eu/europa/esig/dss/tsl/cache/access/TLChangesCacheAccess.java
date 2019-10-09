package eu.europa.esig.dss.tsl.cache.access;

import eu.europa.esig.dss.tsl.cache.CacheKey;
import eu.europa.esig.dss.tsl.cache.DownloadCache;
import eu.europa.esig.dss.tsl.cache.ParsingCache;
import eu.europa.esig.dss.tsl.cache.ValidationCache;

public class TLChangesCacheAccess {

	/* Global Cache */
	private final DownloadCache downloadCache;
	private final ParsingCache parsingCache;
	private final ValidationCache validationCache;

	public TLChangesCacheAccess(final DownloadCache downloadCache, final ParsingCache parsingCache, final ValidationCache validationCache) {
		this.downloadCache = downloadCache;
		this.parsingCache = parsingCache;
		this.validationCache = validationCache;
	}

	public void toBeDeleted(CacheKey cacheKey) {
		downloadCache.toBeDeleted(cacheKey);
		parsingCache.toBeDeleted(cacheKey);
		validationCache.toBeDeleted(cacheKey);
	}

	public void expireSignatureValidation(CacheKey cacheKey) {
		validationCache.expire(cacheKey);
	}

}
