package eu.europa.esig.dss.tsl.dto;

import java.util.Date;

import eu.europa.esig.dss.spi.tsl.InfoRecord;
import eu.europa.esig.dss.tsl.cache.state.CacheStateEnum;

public class AbstractCacheDTO implements InfoRecord {

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
		this.resultExist = cacheDTO.resultExist;
	}
	
	public CacheStateEnum getCacheState() {
		return cacheState;
	}
	
	public void setCacheState(CacheStateEnum cacheState) {
		this.cacheState = cacheState;
	}

	@Override
	public Date getLastSuccessDate() {
		return lastSuccessDate;
	}
	
	public void setLastSuccessDate(Date lastSuccessDate) {
		this.lastSuccessDate = lastSuccessDate;
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

}
