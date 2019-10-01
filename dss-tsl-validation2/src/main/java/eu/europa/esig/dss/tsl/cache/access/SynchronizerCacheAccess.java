package eu.europa.esig.dss.tsl.cache.access;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.tsl.cache.CacheKey;
import eu.europa.esig.dss.tsl.cache.DownloadCache;
import eu.europa.esig.dss.tsl.cache.ParsingCache;
import eu.europa.esig.dss.tsl.cache.ValidationCache;

public class SynchronizerCacheAccess extends ReadOnlyCacheAccess {

	private static final Logger LOG = LoggerFactory.getLogger(SynchronizerCacheAccess.class);

	public SynchronizerCacheAccess(final DownloadCache downloadCache, final ParsingCache parsingCache, final ValidationCache validationCache) {
		super(downloadCache, parsingCache, validationCache);
	}

	public void sync(CacheKey key) {
		LOG.info("Sync all caches for key {}", key.getKey());

		if (downloadCache.isDesync(key)) {
			downloadCache.sync(key);
		}

		if (parsingCache.isDesync(key)) {
			parsingCache.sync(key);
		}

		if (validationCache.isDesync(key)) {
			validationCache.sync(key);
		}
	}

}
