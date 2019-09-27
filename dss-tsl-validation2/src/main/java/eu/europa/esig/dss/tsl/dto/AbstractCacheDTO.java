package eu.europa.esig.dss.tsl.dto;

import java.io.Serializable;
import java.util.Date;

import eu.europa.esig.dss.tsl.cache.state.CacheStateEnum;

public class AbstractCacheDTO implements Serializable {

	private static final long serialVersionUID = -8787039602635778771L;
	
	private CacheStateEnum cacheState;
	private Date lastSuccessDate;
	private String exceptionMessage;
	private String exceptionStackTrace;
	
	private boolean resultExist;

	public AbstractCacheDTO() {}
	
	public AbstractCacheDTO(AbstractCacheDTO cacheDTO) {
		this.cacheState = cacheDTO.cacheState;
		this.lastSuccessDate = cacheDTO.lastSuccessDate;
		this.exceptionMessage = cacheDTO.exceptionMessage;
		this.exceptionStackTrace = cacheDTO.exceptionStackTrace;
	}
		
	public CacheStateEnum getCacheState() {
		return cacheState;
	}
	
	public void setCacheState(CacheStateEnum cacheState) {
		this.cacheState = cacheState;
	}
	
	public Date getLastSuccessDate() {
		return lastSuccessDate;
	}
	
	public void setLastSuccessDate(Date lastSuccessDate) {
		this.lastSuccessDate = lastSuccessDate;
	}
	
	public String getExceptionMessage() {
		return exceptionMessage;
	}
	
	public void setExceptionMessage(String exceptionMessage) {
		this.exceptionMessage = exceptionMessage;
	}
	
	public String getExceptionStackTrace() {
		return exceptionStackTrace;
	}
	
	public void setExceptionStackTrace(String exceptionStackTrace) {
		this.exceptionStackTrace = exceptionStackTrace;
	}
	
	public boolean isResultExist() {
		return resultExist;
	}

	public void setResultExist(boolean resultExist) {
		this.resultExist = resultExist;
	}

}
