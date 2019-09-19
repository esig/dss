package eu.europa.esig.dss.tsl.cache.state;

import java.util.Date;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class CurrentCacheContext implements CacheContext {

	private static final Logger LOG = LoggerFactory.getLogger(CurrentCacheContext.class);

	private CacheState state;
	private Date date;

	private Date errorDate;
	private String errorMessage;

	public CurrentCacheContext() {
		state(CacheStateEnum.REFRESH_NEEDED);
	}

	@Override
	public CacheState getCurrentState() {
		return state;
	}

	@Override
	public Date getLastSuccessDate() {
		return date;
	}

	@Override
	public void state(CacheState newState) {
		LOG.trace("State transition from '{}' to '{}'", state, newState);
		state = newState;
		date = new Date();
		errorDate = null;
		errorMessage = null;
	}

	@Override
	public void error(String error) {
		LOG.trace("State transition from '{}' to '{}'", state, CacheStateEnum.ERROR);
		state = CacheStateEnum.ERROR;
		errorMessage = error;
		errorDate = new Date();
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
	public String getErrorMessage() {
		return errorMessage;
	}

	@Override
	public Date getErrorDate() {
		return errorDate;
	}

}
