package eu.europa.esig.dss.tsl.cache.state;

import java.util.Date;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class CurrentCacheContext implements CacheContext {

	private static final Logger LOG = LoggerFactory.getLogger(CurrentCacheContext.class);

	private CacheState state;
	private Date date;

	public CurrentCacheContext() {
		state(CacheStates.EMPTY);
	}

	@Override
	public CacheState getCurrentState() {
		return state;
	}

	@Override
	public Date getCurrentStateDate() {
		return date;
	}

	@Override
	public void state(CacheState newState) {
		LOG.trace("State transition from '{}' to '{}'", state, newState);
		state = newState;
		date = new Date();
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
	public void expire() {
		state.expire(this);
	}

	@Override
	public void toBeDeleted() {
		state.toBeDeleted(this);
	}

	@Override
	public boolean isRefreshNeeded() {
		return CacheStates.EMPTY == state || CacheStates.EXPIRED == state;
	}

}
