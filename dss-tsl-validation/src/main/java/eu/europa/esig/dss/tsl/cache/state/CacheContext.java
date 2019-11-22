package eu.europa.esig.dss.tsl.cache.state;

import java.util.Date;

public interface CacheContext {

	/**
	 * Returns the current state in the cache
	 * 
	 * @return the Cache state
	 */
	CacheStateEnum getCurrentState();

	/**
	 * Returns the date of the last state transition
	 * 
	 * @return the last date when the state has had a transition
	 */
	Date getLastStateTransitionTime();

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
	 * Set the context as REFRESH_NEEDED
	 */
	void refreshNeeded();

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

	/**
	 * Returns TRUE if the cache is in a error status
	 * 
	 * @return TRUE if an exception is stored
	 */
	boolean isError();

	/**
	 * Store the exception for its occurrence time
	 * 
	 * @param exception an instance of {@link CachedException}
	 */
	void error(CachedException exception);

	/**
	 * Store the last occurrence of this exception
	 * 
	 * @param exception an instance of {@link CachedException}
	 */
	void errorUpdateDate(CachedException exception);
	
	/**
	 * Returns the met exception
	 * 
	 * @return an object with the exception and its occurrence time
	 */
	CachedException getException();
	
	/**
	 * Returns TRUE if the cache is in TO_BE_DELETED status
	 * 
	 * @return TRUE if the entry must be deleted
	 */
	boolean isToBeDeleted();

	/**
	 * Returns TRUE if the cache is in DESYNC status
	 * 
	 * @return TRUE if the entry is desynchronized
	 */
	boolean isDesync();

}
