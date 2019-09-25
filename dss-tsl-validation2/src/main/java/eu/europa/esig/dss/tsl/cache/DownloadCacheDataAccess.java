package eu.europa.esig.dss.tsl.cache;

import java.util.Date;

public class DownloadCacheDataAccess extends AbstractCacheDataAccess<DownloadCache> {
	
	public DownloadCacheDataAccess(DownloadCache downloadCache) {
		super(downloadCache);
	}
	
	public Date getLastSynchronizationDate(CacheKey cacheKey) {
		return cache.getLastSynchronizationDate(cacheKey);
	}

}
