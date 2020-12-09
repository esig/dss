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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Date;

/**
 * Contains information for a cache record state
 */
public class CurrentCacheContext implements CacheContext {

	private static final Logger LOG = LoggerFactory.getLogger(CurrentCacheContext.class);

	/** The current state */
	private CacheState state;

	/** Last time when state of the current cache context has been changed */
	private Date lastStateTransitionTime;

	/** Last time when the cache had been synchronized */
	private Date lastSuccessSynchronizationTime;

	/** The exception message */
	private CachedException exception;

	/**
	 * Default constructor
	 */
	public CurrentCacheContext() {
		state(CacheStateEnum.REFRESH_NEEDED);
	}

	@Override
	public CacheStateEnum getCurrentState() {
		return (CacheStateEnum) state;
	}

	@Override
	public Date getLastStateTransitionTime() {
		return lastStateTransitionTime;
	}

	@Override
	public Date getLastSuccessSynchronizationTime() {
		return lastSuccessSynchronizationTime;
	}

	@Override
	public void state(CacheState newState) {
		LOG.trace("State transition from '{}' to '{}'", state, newState);
		if (state == newState) {
			LOG.trace("The newer state is the same. The CurrentCacheContext is not updated.");
		} else {
			state = newState;
			lastStateTransitionTime = new Date();
			exception = null;
		}
	}

	@Override
	public void syncUpdateDate() {
		lastSuccessSynchronizationTime = new Date();
	}

	@Override
	public void error(CachedException cachedException) {
		LOG.trace("State transition from '{}' to '{}'", state, CacheStateEnum.ERROR);
		state = CacheStateEnum.ERROR;
		exception = cachedException;
	}
	
	@Override
	public void errorUpdateDate(CachedException updatedException) {
		LOG.trace("Exception last occurrence updated '{}'", updatedException.getDate());
		exception.setLastOccurrenceDate(updatedException.getDate());
	}

	@Override
	public void desync() {
		state.desync(this);
	}

	@Override
	public void sync() {
		state.sync(this);
		syncUpdateDate();
	}

	@Override
	public void refreshNeeded() {
		state.refreshNeeded(this);
	}

	@Override
	public void toBeDeleted() {
		state.toBeDeleted(this);
	}

	@Override
	public boolean isRefreshNeeded() {
		return CacheStateEnum.REFRESH_NEEDED == state;
	}

	@Override
	public boolean isError() {
		return CacheStateEnum.ERROR == state;
	}

	@Override
	public CachedException getException() {
		return exception;
	}

	@Override
	public boolean isToBeDeleted() {
		return CacheStateEnum.TO_BE_DELETED == state;
	}

	@Override
	public boolean isDesync() {
		return CacheStateEnum.DESYNCHRONIZED == state;
	}

}
