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

import eu.europa.esig.dss.tsl.cache.CachedResult;
import eu.europa.esig.dss.utils.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Date;
import java.util.Objects;

/**
 * Defines a cached entry
 *
 * @param <R> type of the entry
 */
public class CachedEntry<R extends CachedResult> {
	
	private static final Logger LOG = LoggerFactory.getLogger(CachedEntry.class);

	/** Contains information about the cache entry */
	private final CacheContext cacheContext = new CurrentCacheContext();

	/** The cached result */
	private R cachedResult;

	/**
	 * Empty constructor
	 */
	public CachedEntry() {
		// empty
	}

	/**
	 * Default constructor
	 *
	 * @param cachedResult the cached result
	 */
	public CachedEntry(R cachedResult) {
		update(cachedResult);
	}

	/**
	 * Gets the state of the cache
	 *
	 * @return {@link CacheStateEnum}
	 */
	public CacheStateEnum getCurrentState() {
		return cacheContext.getCurrentState();
	}

	/**
	 * Gets last status change time
	 *
	 * @return {@link Date}
	 */
	public Date getLastStateTransitionTime() {
		return cacheContext.getLastStateTransitionTime();
	}

	/**
	 * Gets last synchronization time
	 *
	 * @return {@link Date}
	 */
	public Date getLastSuccessSynchronizationTime() {
		return cacheContext.getLastSuccessSynchronizationTime();
	}

	/**
	 * Gets the cached result
	 *
	 * @return cached result
	 */
	public R getCachedResult() {
		return cachedResult;
	}

	/**
	 * Updates the cache record
	 *
	 * @param newCachedResult new cache record
	 */
	public void update(R newCachedResult) {
		Objects.requireNonNull(newCachedResult, "Cached result cannot be overwritten with a null value");
		cacheContext.desync(); // if transition is not allowed, cached object is not updated
		cachedResult = newCachedResult;
	}

	/**
	 * Synchronizes the update date
	 */
	public void syncUpdateDate() {
		cacheContext.syncUpdateDate();
	}

	/**
	 * Sets the error
	 *
	 * @param exception {@link CachedExceptionWrapper}
	 */
	public void error(CachedExceptionWrapper exception) {
		if (isNewError(exception)) {
			cacheContext.error(exception);
			cachedResult = null; // reset in case of error
		} else {
			LOG.trace("The ERROR is already recorded.");
			cacheContext.errorUpdateDate(exception);
		}
	}

	/**
	 * Checks if the {@code wrappedException} is a new one
	 *
	 * @param wrappedException {@link CachedExceptionWrapper}
	 * @return TRUE if the given exception has not been defined before, FALSE otherwise
	 */
	private boolean isNewError(CachedExceptionWrapper wrappedException) {
		return !isError() || !Utils.areStringsEqual(getExceptionStackTrace(), wrappedException.getStackTrace());
	}

	/**
	 * Expires the cache entry
	 */
	public void expire() {
		cacheContext.refreshNeeded();
	}

	/**
	 * Synchronizes the cache entry
	 */
	public void sync() {
		cacheContext.sync();
	}

	/**
	 * Sets 'toBeDeleted' status for the cache entry
	 */
	public void toBeDeleted() {
		cacheContext.toBeDeleted();
	}

	/**
	 * Checks if the status 'toBeDeleted' is set for the cache entry
	 *
	 * @return TRUE if the status is 'toBeDeleted', FALSE otherwise
	 */
	public boolean isToBeDeleted() {
		return cacheContext.isToBeDeleted();
	}

	/**
	 * Checks if the status 'desynchronized' is set for the cache entry
	 *
	 * @return TRUE if the status is 'desynchronized', FALSE otherwise
	 */
	public boolean isDesync() {
		return cacheContext.isDesync();
	}

	/**
	 * Checks if the refresh is needed for the cache entry
	 *
	 * @return TRUE if refresh is needed', FALSE otherwise
	 */
	public boolean isRefreshNeeded() {
		return cacheContext.isRefreshNeeded();
	}

	/**
	 * Checks if the cache record is empty
	 *
	 * @return TRUE if the cache record is empty, FALSE otherwise
	 */
	public boolean isEmpty() {
		return cachedResult == null;
	}

	/**
	 * Checks if the current status of the cache is error
	 *
	 * @return TRUE if the status is error, FALSE otherwise
	 */
	public boolean isError() {
		return cacheContext.isError();
	}

	/**
	 * Gets the exception message for an error status
	 *
	 * @return {@link String} exception message if error, FALSE otherwise
	 */
	public String getExceptionMessage() {
		if (cacheContext.getException() != null) {
			return cacheContext.getException().getExceptionMessage();
		}
		return null;
	}

	/**
	 * Gets the exception stack trace for an error status
	 *
	 * @return {@link String} exception stack trace if error, FALSE otherwise
	 */
	public String getExceptionStackTrace() {
		if (cacheContext.getException() != null) {
			return cacheContext.getException().getStackTrace();
		}
		return null;
	}

	/**
	 * Gets the first time when the exception occurred
	 *
	 * @return {@link Date} first time when the exception occurred if error, FALSE otherwise
	 */
	public Date getExceptionFirstOccurrenceTime() {
		if (cacheContext.getException() != null) {
			return cacheContext.getException().getDate();
		}
		return null;
	}

	/**
	 * Gets the last time when the exception occurred
	 *
	 * @return {@link Date} last time when the exception occurred if error, FALSE otherwise
	 */
	public Date getExceptionLastOccurrenceTime() {
		if (cacheContext.getException() != null) {
			return cacheContext.getException().getLastOccurrenceDate();
		}
		return null;
	}

}
