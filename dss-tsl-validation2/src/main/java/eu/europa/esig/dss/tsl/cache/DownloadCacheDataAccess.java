package eu.europa.esig.dss.tsl.cache;

import java.util.Date;

public class DownloadCacheDataAccess extends AbstractCacheDataAccess<DownloadCache> {
	
	public DownloadCacheDataAccess(final DownloadCache downloadCache, final CacheKey cacheKey) {
		super(downloadCache, cacheKey);
	}
	
	public Date getLastSynchronizationDate() {
		return cache.getLastSynchronizationDate(getCacheKey());
	}

}
