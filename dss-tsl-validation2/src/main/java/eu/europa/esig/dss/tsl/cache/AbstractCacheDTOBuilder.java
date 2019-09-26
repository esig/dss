package eu.europa.esig.dss.tsl.cache;

import java.util.Date;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.tsl.cache.dto.AbstractCacheDTO;
import eu.europa.esig.dss.tsl.cache.state.CacheStateEnum;
import eu.europa.esig.dss.tsl.cache.state.CachedEntry;

public abstract class AbstractCacheDTOBuilder<R extends CachedResult> {

	private static final Logger LOG = LoggerFactory.getLogger(AbstractCacheDTOBuilder.class);
	
	private final CachedEntry<R> cachedEntry;
	
	protected AbstractCacheDTOBuilder(final CachedEntry<R> cachedEntry) {
		this.cachedEntry = cachedEntry;
	}
	
	public AbstractCacheDTO build() {
		AbstractCacheDTO abstractCacheDTO = new AbstractCacheDTO();
		abstractCacheDTO.setCacheState(getCurrentState());
		abstractCacheDTO.setLastSuccessDate(getLastSuccessDate());
		abstractCacheDTO.setExceptionMessage(getCachedExceptionMessage());
		abstractCacheDTO.setExceptionStackTrace(getCachedExceptionStackTrace());
		abstractCacheDTO.setResultExist(isResultExist());
		return abstractCacheDTO;
	}
	
	protected final R getResult() {
		return cachedEntry.getCachedResult();
	}
	
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
	
	private Date getLastSuccessDate() {
		return cachedEntry.getLastSuccessDate();
	}
	
	private String getCachedExceptionMessage() {
		return cachedEntry.getExceptionMessage();
	}
	
	private String getCachedExceptionStackTrace() {
		return cachedEntry.getExceptionStackTrace();
	}

}
