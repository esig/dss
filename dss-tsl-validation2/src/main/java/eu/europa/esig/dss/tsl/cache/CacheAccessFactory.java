package eu.europa.esig.dss.tsl.cache;

public final class CacheAccessFactory {

	private CacheAccessFactory() {
	}

	/* Global Cache */
	private static final DownloadCache DOWNLOAD_CACHE = new DownloadCache();
	private static final ParsingCache PARSING_CACHE = new ParsingCache();
	private static final ValidationCache VALIDATION_CACHE = new ValidationCache();

	public static CacheAccessByKey getCacheAccess(CacheKey key) {
		return new CacheAccessByKey(key, DOWNLOAD_CACHE, PARSING_CACHE, VALIDATION_CACHE);
	}

	public static TLChangesCacheAccess getTLChangesCacheAccess() {
		return new TLChangesCacheAccess(DOWNLOAD_CACHE, PARSING_CACHE, VALIDATION_CACHE);
	}

	public static ReadOnlyCacheAccess getReadOnlyCacheAccess() {
		return new ReadOnlyCacheAccess(DOWNLOAD_CACHE, PARSING_CACHE, VALIDATION_CACHE);
	}
	
	public static DownloadCacheDataAccess getDownloadCacheDataAccess() {
		return new DownloadCacheDataAccess(DOWNLOAD_CACHE);
	}
	
	public static ParsingCacheDataAccess getParsingCacheDataAccess() {
		return new ParsingCacheDataAccess(PARSING_CACHE);
	}
	
	public static ValidationCacheDataAccess getValidationCacheDataAccess() {
		return new ValidationCacheDataAccess(VALIDATION_CACHE);
	}

}
