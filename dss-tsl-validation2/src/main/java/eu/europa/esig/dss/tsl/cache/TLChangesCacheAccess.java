package eu.europa.esig.dss.tsl.cache;

public class TLChangesCacheAccess {

	/* Global Cache */
	private final DownloadCache fileCache;
	private final ParsingCache parsingCache;
	private final ValidationCache validationCache;

	public TLChangesCacheAccess(final DownloadCache fileCache, final ParsingCache parsingCache, final ValidationCache validationCache) {
		this.fileCache = fileCache;
		this.parsingCache = parsingCache;
		this.validationCache = validationCache;
	}

	public void toBeDeleted(CacheKey cacheKey) {
		fileCache.toBeDeleted(cacheKey);
		parsingCache.toBeDeleted(cacheKey);
		validationCache.toBeDeleted(cacheKey);
	}

	public void expireSignatureValidation(CacheKey cacheKey) {
		validationCache.expire(cacheKey);
	}

}
