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
package eu.europa.esig.dss.tsl.dto;

import eu.europa.esig.dss.spi.tsl.InfoRecord;
import eu.europa.esig.dss.tsl.cache.state.CacheStateEnum;

import java.util.Date;

/**
 * The abstract cache DTO
 */
public class AbstractCacheDTO implements InfoRecord {

	private static final long serialVersionUID = -8787039602635778771L;

	/** The state of the record */
	private CacheStateEnum cacheState;

	/** The last time of the state change */
	private Date lastStateTransitionTime;

	/** The last time of a successful synchronization */
	private Date lastSuccessSynchronizationTime;

	/** The exception message */
	private String exceptionMessage;

	/** The exception stack trace */
	private String exceptionStackTrace;

	/** The first time of the exception occurrence */
	private Date exceptionFirstOccurrenceTime;

	/** The last time of the exception occurrence */
	private Date exceptionLastOccurrenceTime;

	/** Defines if the result exists */
	private boolean resultExist;

	/**
	 * Empty constructor
	 */
	public AbstractCacheDTO() {}

	/**
	 * Copies the cache DTO
	 *
	 * @param cacheDTO {@link AbstractCacheDTO} to copy
	 */
	public AbstractCacheDTO(AbstractCacheDTO cacheDTO) {
		this.cacheState = cacheDTO.cacheState;
		this.lastStateTransitionTime = cacheDTO.lastStateTransitionTime;
		this.lastSuccessSynchronizationTime = cacheDTO.lastSuccessSynchronizationTime;
		this.exceptionMessage = cacheDTO.exceptionMessage;
		this.exceptionStackTrace = cacheDTO.exceptionStackTrace;
		this.exceptionFirstOccurrenceTime = cacheDTO.exceptionFirstOccurrenceTime;
		this.exceptionLastOccurrenceTime = cacheDTO.exceptionLastOccurrenceTime;
		this.resultExist = cacheDTO.resultExist;
	}

	/**
	 * Gets the state of the cache
	 *
	 * @return {@link CacheStateEnum}
	 */
	public CacheStateEnum getCacheState() {
		return cacheState;
	}

	/**
	 * Sets the cache state
	 *
	 * @param cacheState {@link CacheStateEnum}
	 */
	public void setCacheState(CacheStateEnum cacheState) {
		this.cacheState = cacheState;
	}

	@Override
	public Date getLastStateTransitionTime() {
		return lastStateTransitionTime;
	}

	/**
	 * Sets the last time of the state change
	 *
	 * @param lastStateTransitionTime {@link Date}
	 */
	public void setLastStateTransitionTime(Date lastStateTransitionTime) {
		this.lastStateTransitionTime = lastStateTransitionTime;
	}
	
	@Override
	public Date getLastSuccessSynchronizationTime() {
		return lastSuccessSynchronizationTime;
	}

	/**
	 * Sets the last time of a successful synchronization
	 *
	 * @param lastSuccessSynchronizationTime {@link Date}
	 */
	public void setLastSuccessSynchronizationTime(Date lastSuccessSynchronizationTime) {
		this.lastSuccessSynchronizationTime = lastSuccessSynchronizationTime;
	}

	@Override
	public String getExceptionMessage() {
		return exceptionMessage;
	}

	/**
	 * Sets the exception message
	 *
	 * @param exceptionMessage {@link String}
	 */
	public void setExceptionMessage(String exceptionMessage) {
		this.exceptionMessage = exceptionMessage;
	}

	@Override
	public String getExceptionStackTrace() {
		return exceptionStackTrace;
	}

	/**
	 * Sets the exception stack trace
	 *
	 * @param exceptionStackTrace {@link String}
	 */
	public void setExceptionStackTrace(String exceptionStackTrace) {
		this.exceptionStackTrace = exceptionStackTrace;
	}
	
	@Override
	public Date getExceptionFirstOccurrenceTime() {
		return exceptionFirstOccurrenceTime;
	}

	/**
	 * Sets the first time of the exception occurrence
	 *
	 * @param exceptionFirstOccurrenceTime {@link Date}
	 */
	public void setExceptionFirstOccurrenceTime(Date exceptionFirstOccurrenceTime) {
		this.exceptionFirstOccurrenceTime = exceptionFirstOccurrenceTime;
	}
	
	@Override
	public Date getExceptionLastOccurrenceTime() {
		return exceptionLastOccurrenceTime;
	}

	/**
	 * Sets the last time of a the exception occurrence
	 *
	 * @param exceptionLastOccurrenceTime {@link Date}
	 */
	public void setExceptionLastOccurrenceTime(Date exceptionLastOccurrenceTime) {
		this.exceptionLastOccurrenceTime = exceptionLastOccurrenceTime;
	}

	@Override
	public boolean isResultExist() {
		return resultExist;
	}

	/**
	 * Sets if the cache result exists
	 *
	 * @param resultExist if the cache result exists
	 */
	public void setResultExist(boolean resultExist) {
		this.resultExist = resultExist;
	}

	@Override
	public boolean isRefreshNeeded() {
		return CacheStateEnum.REFRESH_NEEDED == cacheState;
	}

	@Override
	public boolean isDesynchronized() {
		return CacheStateEnum.DESYNCHRONIZED == cacheState;
	}

	@Override
	public boolean isSynchronized() {
		return CacheStateEnum.SYNCHRONIZED == cacheState;
	}

	@Override
	public boolean isError() {
		return CacheStateEnum.ERROR == cacheState;
	}

	@Override
	public boolean isToBeDeleted() {
		return CacheStateEnum.TO_BE_DELETED == cacheState;
	}

	@Override
	public String getStatusName() {
		return cacheState.name();
	}

}
