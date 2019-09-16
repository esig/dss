package eu.europa.esig.dss.tsl.cache.state;

import java.util.Date;

public interface CacheContext {
	
	/**
	 * Returns the current state in the cache
	 * 
	 * @return the Cache state
	 */
	CacheState getCurrentState();
	
	/**
	 * Returns the date of the last transition
	 * 
	 * @return the last date when the state has been changed
	 */
	Date getCurrentStateDate();

	/**
	 * This method operates a state change
	 * 
	 * @param newState
	 *                 the new state to be assigned
	 */
	void state(CacheState newState);

	/**
	 * Set the context as DESYNCHRONIZED
	 */
	void desync();

	/**
	 * Set the context as SYNCHRONIZED
	 */
	void sync();

	/**
	 * Set the context as EXPIRED
	 */
	void expire();

	/**
	 * Set the context as TO_BE_DELETED
	 */
	void toBeDeleted();

	/**
	 * Returns TRUE is a refresh is needed (missing / expired data)
	 * 
	 * @return TRUE if a refresh is required
	 */
	boolean isRefreshNeeded();

}
