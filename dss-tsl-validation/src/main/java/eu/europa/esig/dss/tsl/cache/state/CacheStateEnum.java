package eu.europa.esig.dss.tsl.cache.state;

public enum CacheStateEnum implements CacheState {

	/**
	 * Nothing / Expired content is stored in the cache
	 */
	REFRESH_NEEDED {

		@Override
		public void desync(CacheContext cacheContext) {
			cacheContext.state(DESYNCHRONIZED);
		}

		@Override
		public void refreshNeeded(CacheContext cacheContext) {
			cacheContext.state(REFRESH_NEEDED);
		}

		@Override
		public void error(CacheContext cacheContext, CachedException exception) {
			cacheContext.error(exception);
		}

	},

	/**
	 * The cache content is not synchronized with the application
	 */
	DESYNCHRONIZED {

		@Override
		public void sync(CacheContext cacheContext) {
			cacheContext.state(SYNCHRONIZED);
		}

	},

	/**
	 * The application and the cache content are synchronized
	 */
	SYNCHRONIZED {

		@Override
		public void desync(CacheContext cacheContext) {
			cacheContext.state(DESYNCHRONIZED);
		}

		@Override
		public void refreshNeeded(CacheContext cacheContext) {
			cacheContext.state(REFRESH_NEEDED);
		}

		@Override
		public void toBeDeleted(CacheContext cacheContext) {
			cacheContext.state(TO_BE_DELETED);
		}

		@Override
		public void sync(CacheContext cacheContext) {
			cacheContext.state(SYNCHRONIZED);
		}

	},

	/**
	 * The data cannot be downloaded / parsed / validated
	 */
	ERROR {

		@Override
		public void desync(CacheContext cacheContext) {
			cacheContext.state(DESYNCHRONIZED);
		}

		@Override
		public void refreshNeeded(CacheContext cacheContext) {
			cacheContext.state(REFRESH_NEEDED);
		}

		@Override
		public void toBeDeleted(CacheContext cacheContext) {
			cacheContext.state(TO_BE_DELETED);
		}

	},

	/**
	 * The cache content needs to be deleted
	 */
	TO_BE_DELETED;

	private static final String NOT_ALLOWED_TRANSITION = "Transition from '%s' to '%s' is not allowed";

	@Override
	public void sync(CacheContext cacheContext) {
		throw new IllegalStateException(String.format(NOT_ALLOWED_TRANSITION, cacheContext.getCurrentState(), SYNCHRONIZED));
	}

	@Override
	public void desync(CacheContext cacheContext) {
		throw new IllegalStateException(String.format(NOT_ALLOWED_TRANSITION, cacheContext.getCurrentState(), DESYNCHRONIZED));
	}

	@Override
	public void refreshNeeded(CacheContext cacheContext) {
		throw new IllegalStateException(String.format(NOT_ALLOWED_TRANSITION, cacheContext.getCurrentState(), REFRESH_NEEDED));
	}

	@Override
	public void toBeDeleted(CacheContext cacheContext) {
		throw new IllegalStateException(String.format(NOT_ALLOWED_TRANSITION, cacheContext.getCurrentState(), TO_BE_DELETED));
	}

	@Override
	public void error(CacheContext cacheContext, CachedException exception) {
		throw new IllegalStateException("Cannot store error");
	}

}
