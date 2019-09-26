package eu.europa.esig.dss.tsl.cache;

import java.util.Date;

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
	
	public CacheStateEnum getCurrentState() {
		return cache.getCurrentState(getCacheKey());
	}
	
	public Date getLastSuccessDate() {
		return cache.getLastSuccessDate(getCacheKey());
	}
	
	public String getCachedExceptionMessage() {
		return cache.getCachedExceptionMessage(getCacheKey());
	}
	
	public String getCachedExceptionStackTrace() {
		return cache.getCachedExceptionStackTrace(getCacheKey());
	}

}
