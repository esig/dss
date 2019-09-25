package eu.europa.esig.dss.tsl.cache;

import java.util.Collection;
import java.util.Date;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.tsl.cache.state.CacheState;
import eu.europa.esig.dss.tsl.cache.state.CacheStateEnum;
import eu.europa.esig.dss.tsl.cache.state.CachedEntry;
import eu.europa.esig.dss.tsl.cache.state.CachedException;
import eu.europa.esig.dss.utils.Utils;

/**
 * The abstract class containing basic methods for handling the {@code Result} implementations
 *
 * @param <R> implementation of {@link CachedResult} interface
 */
public abstract class AbstractCache<R extends CachedResult> {

	private static final Logger LOG = LoggerFactory.getLogger(AbstractCache.class);
	
	/**
	 * Map between {@code CacheKey} and the related result wrapper {@code CachedEntry<CachedResult>}
	 */
	private Map<CacheKey, CachedEntry<R>> cachedEntriesMap = new ConcurrentHashMap<CacheKey, CachedEntry<R>>();
	
	/**
	 * Returns the CachedEntry<R> for the related {@code cacheKey}. Returns new empty entry if no result found for the key
	 * @param cacheKey {@link CacheKey}
	 * @return {@link CachedEntry<R>}
	 */
	protected CachedEntry<R> get(CacheKey cacheKey) {
		LOG.trace("Extracting the result for key [{}]...", cacheKey);
		CachedEntry<R> cacheWrapper = cachedEntriesMap.get(cacheKey);
		if (cacheWrapper != null) {
			LOG.trace("Return result for the key [{}]...", cacheKey);
			return cacheWrapper;
		}
		LOG.trace("A result for key [{}] is not found in the cache. Return empty object.", cacheKey);
		CachedEntry<R> emptyEntry = new CachedEntry<R>();
		cachedEntriesMap.put(cacheKey, emptyEntry);
		return emptyEntry;
	}
	
	/**
	 * Updates in the cache the value for {@code cacheKey} with the given {@code result}
	 * @param cacheKey {@link CacheKey} key to update value for
	 * @param result {@link CachedResult} to store
	 */
	public void update(CacheKey cacheKey, R result) {
		LOG.trace("Update result for the key [{}]...", cacheKey);
		CachedEntry<R> cachedEntry = get(cacheKey);
		cachedEntry.update(result);
	}
	
	/**
	 * Updates the state for a CachedEntry matching to the given key to EXPIRED
	 * @param cacheKey {@link CacheKey} of a CachedEntry to update
	 */
	public void expire(CacheKey cacheKey) {
		LOG.trace("Update state to EXPIRED for an entry with the key [{}]...", cacheKey);
		CachedEntry<R> cachedEntry = get(cacheKey);
		cachedEntry.expire();
	}
	
	/**
	 * Updates states for CachedEntries for entries with provided cacheKeys to EXPIRED
	 * @param cacheKeys collection of {@link CacheKey}s to update entries for
	 */
	public void expire(Collection<CacheKey> cacheKeys) {
		if (Utils.isCollectionNotEmpty(cacheKeys)) {
			LOG.trace("Updating a collection of {} keys from the cache...", cacheKeys.size());
			for (CacheKey cacheKey : cacheKeys) {
				expire(cacheKey);
			}
			LOG.trace("{} keys were updated to the state EXPIRED in the cache.", cacheKeys.size());
		} else {
			LOG.trace("Empty collection of cache keys obtained.", cacheKeys);
		}
	}
	
	/**
	 * Removes the requested entry with the given {@code cacheKey}
	 * @param cacheKey {@link CacheKey} of the entry to be deleted from the cache
	 */
	public void remove(CacheKey cacheKey) {
		LOG.trace("Removing value for the key [{}] from cache...", cacheKey);
		CachedEntry<R> removedEntry = cachedEntriesMap.remove(cacheKey);
		if (removedEntry != null) {
			LOG.info("The cachedEntry with the key [{}], type [{}], creation time [{}] and status [{}], has been REMOVED from the cache.",
					cacheKey, getCacheType(), removedEntry.getLastSuccessDate(), removedEntry.getCurrentState());
		} else {
			LOG.warn("Cannot remove the value for key [{}]. Object does not exist!", cacheKey);
		}
	}
	
	/**
	 * Removes a list of entries with the matching keys
	 * @param cacheKeys
	 * 				collection of {@link CacheKey}s to remove from the cache
	 */
	public void remove(Collection<CacheKey> cacheKeys) {
		if (Utils.isCollectionNotEmpty(cacheKeys)) {
			LOG.trace("Removing a collection of {} keys from the cache...", cacheKeys.size());
			for (CacheKey cacheKey : cacheKeys) {
				remove(cacheKey);
			}
			LOG.trace("{} keys were removed from the cache.", cacheKeys.size());
		} else {
			LOG.trace("Empty collection of cache keys obtained.", cacheKeys);
		}
	}
	
	/**
	 * Updates the state for a CachedEntry matching to the given key to SYNCHRONIZED
	 * @param cacheKey {@link CacheKey} of a CachedEntry to update
	 */
	public void sync(CacheKey cacheKey) {
		LOG.trace("Update state to SYNCHRONIZED for an entry with the key [{}]...", cacheKey);
		CachedEntry<R> cachedEntry = get(cacheKey);
		cachedEntry.sync();
	}

	/**
	 * Updates states for CachedEntries for entries with provided cacheKeys to SYNCHRONIZED
	 * @param cacheKeys collection of {@link CacheKey}s to update entries for
	 */
	public void sync(Collection<CacheKey> cacheKeys) {
		if (Utils.isCollectionNotEmpty(cacheKeys)) {
			LOG.trace("Updating a collection of {} keys from the cache...", cacheKeys.size());
			for (CacheKey cacheKey : cacheKeys) {
				sync(cacheKey);
			}
			LOG.trace("{} keys were updated to the state SYNCHRONIZED in the cache.", cacheKeys.size());
		} else {
			LOG.trace("Empty collection of cache keys obtained.");
		}
	}
	
	/**
	 * Checks if a CachedEntry for the given key is not up to date
	 * @param cacheKey {@link CacheKey} of the CacheEntry to check
	 * @return TRUE if update is required for the matching CachedKey, FALSE otherwise
	 */
	public boolean isRefreshNeeded(CacheKey cacheKey) {
		LOG.trace("Checking if the update is required for an entry with the key [{}]...", cacheKey);
		CachedEntry<R> cachedEntry = get(cacheKey);
		boolean refreshNeeded = cachedEntry.isRefreshNeeded();
		LOG.trace("Is update required for the entry with key [{}] ? {}", cacheKey, refreshNeeded);
		return refreshNeeded;
	}

	/**
	 * Checks if a CachedEntry for the given key is empty (has no result)
	 * @param cacheKey {@link CacheKey} of the CacheEntry to check
	 * @return TRUE if the entry is empty, FALSE otherwise
	 */
	public boolean isEmpty(CacheKey cacheKey) {
		LOG.trace("Checking if an entry with the key [{}] is empty", cacheKey);
		CachedEntry<R> cachedEntry = get(cacheKey);
		boolean isEmpty = cachedEntry.isEmpty();
		LOG.trace("Is the entry with key [{}] empty ? {}", cacheKey, isEmpty);
		return isEmpty;
	}
	
	/**
	 * Returns the update date for the given {@code cacheKey}. Returns NULL if the cache does not contain a value for the key
	 * @param cacheKey {@link CacheKey} to get update value for
	 * @return update {@link Date}
	 */
	public Date getLastSuccessDate(CacheKey cacheKey) {
		LOG.trace("Extracting the update date for the key [{}]...", cacheKey);
		CachedEntry<R> cacheWrapper = get(cacheKey);
		if (cacheWrapper != null) {
			Date updateDate = cacheWrapper.getLastSuccessDate();
			LOG.trace("Returns the update date [{}] for the key [{}]", updateDate, cacheKey);
			return updateDate;
		}
		LOG.trace("The result for the key [{}] is not stored in the cache. Return null.", cacheKey);
		return null;
	}
	
	/**
	 * Updates entry status to ERROR value
	 * @param cacheKey {@link CacheKey} to update
	 * @param e {@link Exception} the throwed exception
	 */
	public void error(CacheKey cacheKey, Exception e) {
		LOG.trace("Update state to ERROR for an entry with the key [{}]...", cacheKey);
		CachedEntry<R> cacheWrapper = get(cacheKey);
		cacheWrapper.error(new CachedException(e));
	}

	/**
	 * Updates entry status to TO_BE_DELETED value
	 * @param cacheKey {@link CacheKey} to update
	 */
	public void toBeDeleted(CacheKey cacheKey) {
		LOG.trace("Update state to TO_BE_DELETED for an entry with the key [{}]...", cacheKey);
		CachedEntry<R> cacheWrapper = get(cacheKey);
		cacheWrapper.toBeDeleted();
	}
	
	/**
	 * Checks if the requested cacheKey has TO_BE_DELETED value
	 * @param cacheKey {@link CacheKey} to check
	 * @return TRUE if the entry with the provided {@code cacheKey} has TO_BE_DELETED status, FALSE otherwise
	 */
	public boolean isToBeDeleted(CacheKey cacheKey) {
		LOG.trace("Checking if the status TO_BE_DELETED for an entry with the key [{}]...", cacheKey);
		CachedEntry<R> cachedEntry = get(cacheKey);
		boolean toBeDeleted = cachedEntry.isToBeDeleted();
		LOG.trace("Is TO_BE_DELETED status for the entry with key [{}] ? {}", cacheKey, toBeDeleted);
		return toBeDeleted;
	}
	
	/**
	 * Returns a current state of entry by requested cacheKey
	 * @param cacheKey {@link CacheKey} to get current state for
	 * @return {@link CacheState}
	 */
	public CacheStateEnum getCurrentState(CacheKey cacheKey) {
		LOG.trace("Extracting a state for the key [{}]...", cacheKey);
		CachedEntry<R> cachedEntry = get(cacheKey);
		CacheStateEnum currentState = cachedEntry.getCurrentState();
		LOG.trace("Current state for an entry with key [{}] is [{}]", cacheKey, currentState);
		return currentState;
	}
	
	/**
	 * Returns a cached exception message in case of error during a job for the current entry
	 * @param cacheKey {@link CacheKey} of the entry to get exception message for
	 * @return {@link String} exception message
	 */
	public String getCachedExceptionMessage(CacheKey cacheKey) {
		LOG.trace("Extracting a cached exception message for the key [{}]...", cacheKey);
		CachedEntry<R> cachedEntry = get(cacheKey);
		String exceptionMessage = cachedEntry.getExceptionMessage();
		if (exceptionMessage != null) {
			LOG.trace("Obtained exception message for the key [{}]. Message : [{}]", cacheKey, exceptionMessage);
		} else {
			LOG.debug("The entry with the key [{}] does not contain an exception. Return null.", cacheKey);
		}
		return exceptionMessage;
	}
	
	/**
	 * Returns a cached exception stack trace in case of error during a job for the current entry
	 * @param cacheKey {@link CacheKey} of the entry to get exception stack trace for
	 * @return {@link String} exception stack trace
	 */
	public String getCachedExceptionStackTrace(CacheKey cacheKey) {
		LOG.trace("Extracting a cached exception message for the key [{}]...", cacheKey);
		CachedEntry<R> cachedEntry = get(cacheKey);
		String exception = cachedEntry.getExceptionStackTrace();
		if (exception != null) {
			LOG.trace("Obtained exception stackTrace for the key [{}]. Message : [{}]", cacheKey, exception);
		} else {
			LOG.debug("The entry with the key [{}] does not contain an exception. Return null.", cacheKey);
		}
		return exception;
	}

	/**
	 * Returns a type of current Cache
	 * @return {@link CacheType}
	 */
	protected abstract CacheType getCacheType();
	
}
