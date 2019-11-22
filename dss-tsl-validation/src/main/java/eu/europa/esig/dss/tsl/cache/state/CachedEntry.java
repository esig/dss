package eu.europa.esig.dss.tsl.cache.state;

import java.util.Date;
import java.util.Objects;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.tsl.cache.CachedResult;
import eu.europa.esig.dss.utils.Utils;

public class CachedEntry<R extends CachedResult> {
	
	private static final Logger LOG = LoggerFactory.getLogger(CachedEntry.class);

	private final CacheContext cacheContext = new CurrentCacheContext();
	private R cachedResult;

	public CachedEntry() {
	}

	public CachedEntry(R cachedObject) {
		update(cachedObject);
	}

	public CacheStateEnum getCurrentState() {
		return cacheContext.getCurrentState();
	}

	public Date getLastStateTransitionTime() {
		return cacheContext.getLastStateTransitionTime();
	}

	public R getCachedResult() {
		return cachedResult;
	}

	public void update(R newCachedResult) {
		Objects.requireNonNull(newCachedResult, "Cached result cannot be overrided with a null value");
		cacheContext.desync(); // if transition is not allowed, cached object is not updated
		cachedResult = newCachedResult;
	}

	public void error(CachedException exception) {
		if (isNewError(exception)) {
			cacheContext.error(exception);
			cachedResult = null; // reset in case of error
		} else {
			cacheContext.errorUpdateDate(cacheContext.getException());
			LOG.trace("Update is skipped, ERROR is already recorded (Error last occurrence updated)");
		}
	}
	
	private boolean isNewError(CachedException wrappedException) {
		return !isError() || !Utils.areStringsEqual(getExceptionStackTrace(), wrappedException.getStackTrace());
	}
	
	public void expire() {
		cacheContext.refreshNeeded();
	}

	public void sync() {
		cacheContext.sync();
	}

	public void toBeDeleted() {
		cacheContext.toBeDeleted();
	}
	
	public boolean isToBeDeleted() {
		return cacheContext.isToBeDeleted();
	}

	public boolean isDesync() {
		return cacheContext.isDesync();
	}

	public boolean isRefreshNeeded() {
		return cacheContext.isRefreshNeeded();
	}
	
	public boolean isEmpty() {
		return cachedResult == null;
	}

	public boolean isError() {
		return cacheContext.isError();
	}

	public String getExceptionMessage() {
		if (cacheContext.getException() != null) {
			return cacheContext.getException().getExceptionMessage();
		}
		return null;
	}

	public String getExceptionStackTrace() {
		if (cacheContext.getException() != null) {
			return cacheContext.getException().getStackTrace();
		}
		return null;
	}
	
	public Date getExceptionFirstOccurrenceTime() {
		if (cacheContext.getException() != null) {
			return cacheContext.getException().getDate();
		}
		return null;
	}

	public Date getExceptionLastOccurrenceTime() {
		if (cacheContext.getException() != null) {
			return cacheContext.getException().getLastOccurrenceDate();
		}
		return null;
	}
}
