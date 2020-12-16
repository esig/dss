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
package eu.europa.esig.dss.tsl.dto.builder;

import eu.europa.esig.dss.tsl.cache.CachedResult;
import eu.europa.esig.dss.tsl.cache.state.CacheStateEnum;
import eu.europa.esig.dss.tsl.cache.state.CachedEntry;
import eu.europa.esig.dss.tsl.dto.AbstractCacheDTO;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Date;

/**
 * An abstract builder of a Cache DTO
 *
 * @param <R> type of the cache result
 */
public abstract class AbstractCacheDTOBuilder<R extends CachedResult> {

	private static final Logger LOG = LoggerFactory.getLogger(AbstractCacheDTOBuilder.class);

	/** The cached entry */
	private final CachedEntry<R> cachedEntry;

	/**
	 * Default constructor
	 *
	 * @param cachedEntry the entry
	 */
	protected AbstractCacheDTOBuilder(final CachedEntry<R> cachedEntry) {
		this.cachedEntry = cachedEntry;
	}

	/**
	 * Builds the DTO
	 *
	 * @return {@link AbstractCacheDTO}
	 */
	public AbstractCacheDTO build() {
		AbstractCacheDTO abstractCacheDTO = new AbstractCacheDTO();
		abstractCacheDTO.setCacheState(getCurrentState());
		abstractCacheDTO.setLastStateTransitionTime(getLastStateTransitionTime());
		abstractCacheDTO.setLastSuccessSynchronizationTime(getLastSuccessSynchronizationTime());
		abstractCacheDTO.setExceptionMessage(getCachedExceptionMessage());
		abstractCacheDTO.setExceptionStackTrace(getCachedExceptionStackTrace());
		abstractCacheDTO.setExceptionFirstOccurrenceTime(getCachedExceptionFirstOccurrenceTime());
		abstractCacheDTO.setExceptionLastOccurrenceTime(getCachedExceptionLastOccurrenceTime());
		abstractCacheDTO.setResultExist(isResultExist());
		return abstractCacheDTO;
	}

	/**
	 * Gets the cached result
	 *
	 * @return cached result
	 */
	protected final R getResult() {
		return cachedEntry.getCachedResult();
	}

	/**
	 * Gets if the result exists
	 *
	 * @return TRUE if the result exists, FALSE otherwise
	 */
	protected boolean isResultExist() {
		boolean resultExist = getResult() != null;
		if (resultExist) {
			LOG.trace("The result exists in the cache. The related parameters will be filled in the DTO.");
		} else {
			LOG.debug("The result does not exist for the entry in the cache. The specifiic parameters are not filled!");
		}
		return resultExist;
	}
	
	private CacheStateEnum getCurrentState() {
		return cachedEntry.getCurrentState();
	}
	
	private Date getLastStateTransitionTime() {
		return cachedEntry.getLastStateTransitionTime();
	}

	private Date getLastSuccessSynchronizationTime() {
		return cachedEntry.getLastSuccessSynchronizationTime();
	}
	
	private String getCachedExceptionMessage() {
		return cachedEntry.getExceptionMessage();
	}
	
	private String getCachedExceptionStackTrace() {
		return cachedEntry.getExceptionStackTrace();
	}
	
	private Date getCachedExceptionFirstOccurrenceTime() {
		return cachedEntry.getExceptionFirstOccurrenceTime();
	}
	
	private Date getCachedExceptionLastOccurrenceTime() {
		return cachedEntry.getExceptionLastOccurrenceTime();
	}

}
