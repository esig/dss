/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.tsl.cache;

import eu.europa.esig.dss.tsl.cache.state.CacheStateEnum;
import eu.europa.esig.dss.tsl.cache.state.CachedEntry;
import eu.europa.esig.dss.tsl.cache.state.CachedExceptionWrapper;
import eu.europa.esig.dss.utils.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

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
	private Map<CacheKey, CachedEntry<R>> cachedEntriesMap = new ConcurrentHashMap<>();

	/**
	 * Default constructor instantiating cache with empty map
	 */
	protected AbstractCache() {
		// empty
	}
	
	/**
	 * Returns all current keys
	 * 
	 * @return a set with all current keys
	 */
	public Set<CacheKey> getKeys() {
		return cachedEntriesMap.keySet();
	}

	/**
	 * Returns the CachedEntry for the related {@code cacheKey}. Returns new empty entry if no result found for the key
	 *
	 * @param cacheKey {@link CacheKey}
	 * @return {@link CachedEntry}
	 */
	public CachedEntry<R> get(CacheKey cacheKey) {
		LOG.trace("Extracting the result for key [{}]...", cacheKey);
		CachedEntry<R> cacheWrapper = cachedEntriesMap.get(cacheKey);
		if (cacheWrapper != null) {
			LOG.trace("Return result for the key [{}]...", cacheKey);
			return cacheWrapper;
		}
		LOG.trace("A result for key [{}] is not found in the cache. Return empty object.", cacheKey);
		CachedEntry<R> emptyEntry = new CachedEntry<>();
		cachedEntriesMap.put(cacheKey, emptyEntry);
		return emptyEntry;
	}
	
	/**
	 * Updates in the cache the value for {@code cacheKey} with the given {@code result}
	 *
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
	 *
	 * @param cacheKey {@link CacheKey} of a CachedEntry to update
	 */
	public void expire(CacheKey cacheKey) {
		LOG.trace("Update state to EXPIRED for an entry with the key [{}]...", cacheKey);
		CachedEntry<R> cachedEntry = get(cacheKey);
		cachedEntry.expire();
	}
	
	/**
	 * Removes the requested entry with the given {@code cacheKey}
	 *
	 * @param cacheKey {@link CacheKey} of the entry to be deleted from the cache
	 */
	public void remove(CacheKey cacheKey) {
		LOG.trace("Removing value for the key [{}] from cache...", cacheKey);
		CachedEntry<R> removedEntry = cachedEntriesMap.remove(cacheKey);
		if (removedEntry != null) {
			LOG.info("The cachedEntry with the key [{}], type [{}], last state transition time [{}] and status [{}], has been REMOVED from the cache.",
					cacheKey, getCacheType(), removedEntry.getLastStateTransitionTime(), removedEntry.getCurrentState());
		} else {
			LOG.warn("Cannot remove the value for key [{}]. Object does not exist!", cacheKey);
		}
	}
	
	/**
	 * Updates the state for a CachedEntry matching to the given key to SYNCHRONIZED
	 *
	 * @param cacheKey {@link CacheKey} of a CachedEntry to update
	 */
	public void sync(CacheKey cacheKey) {
		LOG.trace("Update state to SYNCHRONIZED for an entry with the key [{}]...", cacheKey);
		CachedEntry<R> cachedEntry = get(cacheKey);
		cachedEntry.sync();
	}

	/**
	 * Checks if a CachedEntry for the given key is not up to date
	 *
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
	 * Checks if a CachedEntry for the given key is not up to date
	 *
	 * @param cacheKey {@link CacheKey} of the CacheEntry to check
	 * @return TRUE if update is required for the matching CachedKey, FALSE otherwise
	 */
	public boolean isDesync(CacheKey cacheKey) {
		LOG.trace("Checking if the cache entry is desynchronized with the key [{}]...", cacheKey);
		CachedEntry<R> cachedEntry = get(cacheKey);
		boolean desync = cachedEntry.isDesync();
		LOG.trace("Is cache entry desynchronized with key [{}] ? {}", cacheKey, desync);
		return desync;
	}

	/**
	 * Checks if a CachedEntry for the given key is empty (has no result)
	 *
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
	 * Updates entry status to ERROR value
	 * 
	 * @param cacheKey
	 *            {@link CacheKey} to update
	 * @param e
	 *            {@link Exception} the thrown exception
	 */
	public void error(CacheKey cacheKey, Exception e) {
		LOG.trace("Updating state to ERROR for an entry with the key [{}]...", cacheKey);
		CachedEntry<R> cacheWrapper = get(cacheKey);
		CachedExceptionWrapper wrappedException = new CachedExceptionWrapper(e);
		cacheWrapper.error(wrappedException);
	}

	/**
	 * Updates entry status to TO_BE_DELETED value
	 *
	 * @param cacheKey {@link CacheKey} to update
	 */
	public void toBeDeleted(CacheKey cacheKey) {
		LOG.trace("Update state to TO_BE_DELETED for an entry with the key [{}]...", cacheKey);
		CachedEntry<R> cacheWrapper = get(cacheKey);
		cacheWrapper.toBeDeleted();
	}
	
	/**
	 * Checks if the requested cacheKey has TO_BE_DELETED value
	 *
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
	 * Returns a type of current Cache
	 * 
	 * @return {@link CacheType}
	 */
	protected abstract CacheType getCacheType();

	/**
	 * Produces a report of the current cache state
	 *
	 * @return {@link String} the cache report
	 */
	public String dump() {
		SimpleDateFormat sdf = new SimpleDateFormat("yyyy/MM/dd HH:mm:ss");

		StringBuilder sb = new StringBuilder();
		sb.append("Cache ");
		sb.append(getCacheType());
		if (Utils.isMapEmpty(cachedEntriesMap)) {
			sb.append(" : EMPTY");
		} else {
			sb.append(" : (nb entries : ");
			sb.append(cachedEntriesMap.size());
			sb.append(")\n");
			for (Entry<CacheKey, CachedEntry<R>> mapEntry : cachedEntriesMap.entrySet()) {
				CacheKey key = mapEntry.getKey();
				CachedEntry<R> value = mapEntry.getValue();

				String currentKey = key.getKey();
				CacheStateEnum currentState = value.getCurrentState();
				String date = "?";
				Date lastStateTransitionTime = value.getLastStateTransitionTime();
				if (lastStateTransitionTime != null) {
					date = sdf.format(lastStateTransitionTime);
				}

				sb.append(String.format("%-70.70s -> %-25.25s @ %.20s", currentKey, currentState, date));
				sb.append("\n");
			}
		}
		return sb.toString();
	}

}
