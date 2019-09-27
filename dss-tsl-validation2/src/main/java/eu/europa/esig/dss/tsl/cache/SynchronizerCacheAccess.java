package eu.europa.esig.dss.tsl.cache;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SynchronizerCacheAccess {

	private static final Logger LOG = LoggerFactory.getLogger(SynchronizerCacheAccess.class);

	/* Global Cache */
	private final DownloadCache downloadCache;
	private final ParsingCache parsingCache;
	private final ValidationCache validationCache;

	public SynchronizerCacheAccess(final DownloadCache downloadCache, final ParsingCache parsingCache, final ValidationCache validationCache) {
		this.downloadCache = downloadCache;
		this.parsingCache = parsingCache;
		this.validationCache = validationCache;
	}

	public void sync(CacheKey key) {
		LOG.info("Sync all caches for key {}", key.getKey());
		downloadCache.sync(key);
		parsingCache.sync(key);
		validationCache.sync(key);
	}

}
