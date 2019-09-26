package eu.europa.esig.dss.tsl.cache;

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

}
