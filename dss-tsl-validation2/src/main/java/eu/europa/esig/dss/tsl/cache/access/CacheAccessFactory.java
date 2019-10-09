package eu.europa.esig.dss.tsl.cache.access;

import eu.europa.esig.dss.tsl.cache.CacheKey;
import eu.europa.esig.dss.tsl.cache.DownloadCache;
import eu.europa.esig.dss.tsl.cache.ParsingCache;
import eu.europa.esig.dss.tsl.cache.ValidationCache;

public final class CacheAccessFactory {

	/* Global Cache */
	private final DownloadCache downloadCache;
	private final ParsingCache parsingCache;
	private final ValidationCache validationCache;

	public CacheAccessFactory() {
		downloadCache = new DownloadCache();
		parsingCache = new ParsingCache();
		validationCache = new ValidationCache();
	}

	public CacheAccessByKey getCacheAccess(CacheKey key) {
		return new CacheAccessByKey(key, downloadCache, parsingCache, validationCache);
	}

	public TLChangesCacheAccess getTLChangesCacheAccess() {
		return new TLChangesCacheAccess(downloadCache, parsingCache, validationCache);
	}

	public ReadOnlyCacheAccess getReadOnlyCacheAccess() {
		return new ReadOnlyCacheAccess(downloadCache, parsingCache, validationCache);
	}

	public SynchronizerCacheAccess getSynchronizerCacheAccess() {
		return new SynchronizerCacheAccess(downloadCache, parsingCache, validationCache);
	}

	public DebugCacheAccess getDebugCacheAccess() {
		return new DebugCacheAccess(downloadCache, parsingCache, validationCache);
	}

}
