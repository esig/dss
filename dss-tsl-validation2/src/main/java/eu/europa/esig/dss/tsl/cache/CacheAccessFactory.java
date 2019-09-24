package eu.europa.esig.dss.tsl.cache;

public final class CacheAccessFactory {

	private CacheAccessFactory() {
	}

	/* Global Cache */
	private static final DownloadCache DOWLOAD_CACHE = new DownloadCache();
	private static final ParsingCache PARSING_CACHE = new ParsingCache();
	private static final ValidationCache VALIDATION_CACHE = new ValidationCache();

	public static CacheAccessByKey getCacheAccess(CacheKey key) {
		return new CacheAccessByKey(key, DOWLOAD_CACHE, PARSING_CACHE, VALIDATION_CACHE);
	}

	public static TLChangesCacheAccess getTLChangesCacheAccess() {
		return new TLChangesCacheAccess(DOWLOAD_CACHE, PARSING_CACHE, VALIDATION_CACHE);
	}

	public static ReadOnlyCacheAccess getReadOnlyCacheAccess() {
		return new ReadOnlyCacheAccess(DOWLOAD_CACHE, PARSING_CACHE, VALIDATION_CACHE);
	}

}
