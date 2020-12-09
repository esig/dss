/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * 
 * This file is part of the "DSS - Digital Signature Services" project.
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.tsl.cache.state;

import java.util.Date;

/**
 * Contains information for a Cache entry
 */
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
	 * Returns the last time when the cache has been synchronized successfully
	 * NOTE: can be null in case if the cache has never been synchronized
	 * 
	 * @return the last date when the state has been synchronized
	 */
	Date getLastSuccessSynchronizationTime();

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
	 * Updates the lastSuccessSynchronization date
	 */
	void syncUpdateDate();

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
	 * @param updatedException an instance of {@link CachedException}
	 */
	void errorUpdateDate(CachedException updatedException);
	
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
