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

import java.util.Date;

import eu.europa.esig.dss.spi.tsl.InfoRecord;
import eu.europa.esig.dss.tsl.cache.state.CacheStateEnum;

public class AbstractCacheDTO implements InfoRecord {

	private static final long serialVersionUID = -8787039602635778771L;
	
	private CacheStateEnum cacheState;
	private Date lastStateTransitionTime;
	private Date lastSuccessSynchronizationTime;

	private String exceptionMessage;
	private String exceptionStackTrace;
	private Date exceptionFirstOccurrenceTime;
	private Date exceptionLastOccurrenceTime;
	
	private boolean resultExist;

	public AbstractCacheDTO() {}
	
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
	
	public CacheStateEnum getCacheState() {
		return cacheState;
	}
	
	public void setCacheState(CacheStateEnum cacheState) {
		this.cacheState = cacheState;
	}

	@Override
	public Date getLastStateTransitionTime() {
		return lastStateTransitionTime;
	}
	
	public void setLastStateTransitionTime(Date lastStateTransitionTime) {
		this.lastStateTransitionTime = lastStateTransitionTime;
	}
	
	@Override
	public Date getLastSuccessSynchronizationTime() {
		return lastSuccessSynchronizationTime;
	}

	public void setLastSuccessSynchronizationTime(Date lastSuccessSynchronizationTime) {
		this.lastSuccessSynchronizationTime = lastSuccessSynchronizationTime;
	}

	@Override
	public String getExceptionMessage() {
		return exceptionMessage;
	}
	
	public void setExceptionMessage(String exceptionMessage) {
		this.exceptionMessage = exceptionMessage;
	}

	@Override
	public String getExceptionStackTrace() {
		return exceptionStackTrace;
	}
	
	public void setExceptionStackTrace(String exceptionStackTrace) {
		this.exceptionStackTrace = exceptionStackTrace;
	}
	
	@Override
	public Date getExceptionFirstOccurrenceTime() {
		return exceptionFirstOccurrenceTime;
	}
	
	public void setExceptionFirstOccurrenceTime(Date exceptionFirstOccurrenceTime) {
		this.exceptionFirstOccurrenceTime = exceptionFirstOccurrenceTime;
	}
	
	@Override
	public Date getExceptionLastOccurrenceTime() {
		return exceptionLastOccurrenceTime;
	}
	
	public void setExceptionLastOccurrenceTime(Date exceptionLastOccurrenceTime) {
		this.exceptionLastOccurrenceTime = exceptionLastOccurrenceTime;
	}

	@Override
	public boolean isResultExist() {
		return resultExist;
	}

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
