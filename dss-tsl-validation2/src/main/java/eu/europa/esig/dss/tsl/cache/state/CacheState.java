package eu.europa.esig.dss.tsl.cache.state;

/**
 * The interface defines the different possible transitions from a CacheState to
 * another one
 *
 */
public interface CacheState {

	/**
	 * The cache entry is marked as Synchronized
	 * 
	 * @param cacheContext
	 *                     the current cache context
	 */
	void sync(CacheContext cacheContext);

	/**
	 * The cache entry is marked as Desynchronized
	 * 
	 * @param cacheContext
	 *                     the current cache context
	 */
	void desync(CacheContext cacheContext);

	/**
	 * The cache entry is marked as Expired
	 * 
	 * @param cacheContext
	 *                     the current cache context
	 */
	void expire(CacheContext cacheContext);

	/**
	 * The cache entry is marked as to be deleted
	 * 
	 * @param cacheContext
	 *                     the current cache context
	 */
	void toBeDeleted(CacheContext cacheContext);

}
