package eu.europa.esig.dss.tsl.cache;

import java.util.Date;

import eu.europa.esig.dss.tsl.cache.dto.DownloadCacheDTO;

public class DownloadCacheDataAccess extends AbstractCacheDataAccess<DownloadCache> {
	
	public DownloadCacheDataAccess(final DownloadCache downloadCache, final CacheKey cacheKey) {
		super(downloadCache, cacheKey);
	}
	
	@Override
	public DownloadCacheDTO getCacheDTO() {
		DownloadCacheDTO downloadCacheDTO = new DownloadCacheDTO(super.getCacheDTO());
		downloadCacheDTO.setLastSynchronizationDate(getLastSynchronizationDate());
		return downloadCacheDTO;
	}
	
	private Date getLastSynchronizationDate() {
		return cache.getLastSynchronizationDate(getCacheKey());
	}

}
