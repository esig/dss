package eu.europa.esig.dss.tsl.cache;

import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.tsl.cache.result.CachedResult;
import eu.europa.esig.dss.tsl.cache.result.CachedResultWrapper;
import eu.europa.esig.dss.utils.Utils;

/**
 * The abstract class containing basic methods for handling the {@code Result} implementations
 *
 * @param <R> implementation of {@link CachedResult} interface
 */
public abstract class AbstractCache<R extends CachedResult> {

	private static final Logger LOG = LoggerFactory.getLogger(AbstractCache.class);
	
	/**
	 * Map between {@code String} CACHE_KEY and the related result wrapper {@code CachedResultWrapper<Result>}
	 */
	protected Map<String, CachedResultWrapper<R>> cachedResultsMap = new HashMap<String, CachedResultWrapper<R>>();
	
	/**
	 * Returns the CachedResult for the related {@code cacheKey}. Returns NULL if no result is assigned to the key
	 * @param cacheKey {@link String} 
	 * @return {@link CachedResult}
	 */
	public R getCachedResult(String cacheKey) {
		LOG.trace("Extracting the result for key [{}]...", cacheKey);
		CachedResultWrapper<R> cacheWrapper = cachedResultsMap.get(cacheKey);
		if (cacheWrapper != null) {
			LOG.trace("Return result for the key [{}]...", cacheKey);
			return cacheWrapper.getResult();
		}
		LOG.trace("A result for key [{}] is not found in the cache. Return null.", cacheKey);
		return null;
	}
	
	/**
	 * Updates in the cache the value for {@code cacheKey} with the given {@code result}
	 * @param cacheKey {@link String} key to update value for
	 * @param result {@link CachedResult} to store
	 */
	public void update(String cacheKey, R result) {
		LOG.trace("Update result for the key [{}]...", cacheKey);
		cachedResultsMap.put(cacheKey, new CachedResultWrapper<R>(result));
	}
	
	/**
	 * Returns the update date for the given {@code cacheKey}. Returns NULL if the cache does not contain a value for the key
	 * @param cacheKey {@link String} key to get update value for
	 * @return update {@link Date}
	 */
	public Date getUpdateDate(String cacheKey) {
		LOG.trace("Extracting the update date for the key [{}]...", cacheKey);
		CachedResultWrapper<R> cacheWrapper = cachedResultsMap.get(cacheKey);
		if (cacheWrapper != null) {
			Date updateDate = cacheWrapper.getUpdateDate();
			LOG.trace("Returns the update date [{}] for the key [{}]", updateDate, cacheKey);
			return updateDate;
		}
		LOG.trace("The result for the key [{}] is not stored in the cache. Return null.", cacheKey);
		return null;
	}
	
	/**
	 * Removes the requested entry with the given {@code cacheKey}
	 * @param cacheKey {@link String} representing the key of the entry to be deleted from the cache
	 */
	public void remove(String cacheKey) {
		LOG.trace("Removing value for the key [{}] from cache...", cacheKey);
		cachedResultsMap.remove(cacheKey);
	}
	
	/**
	 * Removes a list of entries with the matching keys
	 * @param cacheKeys
	 * 				collection of {@link String} cache keys to remove from the cache
	 */
	public void remove(Collection<String> cacheKeys) {
		if (Utils.isCollectionNotEmpty(cacheKeys)) {
			LOG.trace("Removing a collection of {} keys from the cache...", cacheKeys.size());
			for (String cacheKey : cacheKeys) {
				remove(cacheKey);
			}
			LOG.trace("{} keys were removed from the cache.", cacheKeys.size());
		} else {
			LOG.trace("Empty collection of cache keys obtained.", cacheKeys);
		}
	}

}
