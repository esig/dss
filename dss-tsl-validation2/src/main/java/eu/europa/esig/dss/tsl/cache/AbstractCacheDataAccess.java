package eu.europa.esig.dss.tsl.cache;

import java.util.Date;

import eu.europa.esig.dss.tsl.cache.state.CacheStateEnum;

public class AbstractCacheDataAccess<C extends AbstractCache<?>> {
	
	protected final C cache;
	
	protected AbstractCacheDataAccess(C cache) {
		this.cache = cache;
	}
	
	public CacheStateEnum getCurrentState(CacheKey cacheKey) {
		return cache.getCurrentState(cacheKey);
	}
	
	public Date getLastSuccessDate(CacheKey cacheKey) {
		return cache.getLastSuccessDate(cacheKey);
	}
	
	public String getCachedExceptionMessage(CacheKey cacheKey) {
		return cache.getCachedExceptionMessage(cacheKey);
	}
	
	public String getCachedExceptionStackTrace(CacheKey cacheKey) {
		return cache.getCachedExceptionStackTrace(cacheKey);
	}

}
