package eu.europa.esig.dss.tsl.cache;

import java.util.Date;

import eu.europa.esig.dss.tsl.cache.dto.AbstractCacheDTO;
import eu.europa.esig.dss.tsl.cache.state.CacheStateEnum;

public class AbstractCacheDataAccess<C extends AbstractCache<?>> {
	
	protected final C cache;
	
	private final CacheKey cacheKey;
	
	protected AbstractCacheDataAccess(final C cache, final CacheKey cacheKey) {
		this.cache = cache;
		this.cacheKey = cacheKey;
	}
	
	protected final CacheKey getCacheKey() {
		return cacheKey;
	}
	
	public AbstractCacheDTO getCacheDTO() {
		AbstractCacheDTO abstractCacheDTO = new AbstractCacheDTO();
		abstractCacheDTO.setCacheState(getCurrentState());
		abstractCacheDTO.setLastSuccessDate(getLastSuccessDate());
		abstractCacheDTO.setExceptionMessage(getCachedExceptionMessage());
		abstractCacheDTO.setExceptionStackTrace(getCachedExceptionStackTrace());
		return abstractCacheDTO;
	}
	
	private CacheStateEnum getCurrentState() {
		return cache.getCurrentState(getCacheKey());
	}
	
	private Date getLastSuccessDate() {
		return cache.getLastSuccessDate(getCacheKey());
	}
	
	private String getCachedExceptionMessage() {
		return cache.getCachedExceptionMessage(getCacheKey());
	}
	
	private String getCachedExceptionStackTrace() {
		return cache.getCachedExceptionStackTrace(getCacheKey());
	}

}
