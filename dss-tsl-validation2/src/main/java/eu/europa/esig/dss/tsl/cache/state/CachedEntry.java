package eu.europa.esig.dss.tsl.cache.state;

import java.util.Date;
import java.util.Objects;

public class CachedEntry<O extends Object> {

	private final CacheContext cacheContext = new CurrentCacheContext();
	private O cachedObject;
	
	public CachedEntry() {
	}

	public CachedEntry(O cachedObject) {
		update(cachedObject);
	}

	public CacheState getCurrentState() {
		return cacheContext.getCurrentState();
	}

	public Date getCurrentStateDate() {
		return cacheContext.getCurrentStateDate();
	}

	public O getCachedObject() {
		return cachedObject;
	}

	public void update(O newCachedObject) {
		Objects.requireNonNull(newCachedObject, "Cached object cannot be overrided with a null value");
		cacheContext.desync(); // if transition is not allowed, cached object is not updated
		cachedObject = newCachedObject;
	}

	public void expire() {
		cacheContext.expire();
	}

	public void sync() {
		cacheContext.sync();
	}

	public void toBeDeleted() {
		cacheContext.toBeDeleted();
	}

	public boolean isRefreshNeeded() {
		return cacheContext.isRefreshNeeded();
	}

}
