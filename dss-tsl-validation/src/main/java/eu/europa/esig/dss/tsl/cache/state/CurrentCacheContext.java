package eu.europa.esig.dss.tsl.cache.state;

import java.util.Date;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class CurrentCacheContext implements CacheContext {

	private static final Logger LOG = LoggerFactory.getLogger(CurrentCacheContext.class);

	private CacheState state;
	private Date lastStateTransitionTime;
	private CachedException exception;

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
