package eu.europa.esig.dss.tsl.cache.state;

public enum CacheStates implements CacheState {

	/**
	 * Nothing is stored in the cache
	 */
	EMPTY {

		@Override
		public void desync(CacheContext cacheContext) {
			cacheContext.state(DESYNCHRONIZED);
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
		public void expire(CacheContext cacheContext) {
			cacheContext.state(EXPIRED);
		}

		@Override
		public void toBeDeleted(CacheContext cacheContext) {
			cacheContext.state(TO_BE_DELETED);
		}

	},

	/**
	 * The cache content is expired
	 */
	EXPIRED {

		@Override
		public void desync(CacheContext cacheContext) {
			cacheContext.state(DESYNCHRONIZED);
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
	public void expire(CacheContext cacheContext) {
		throw new IllegalStateException(String.format(NOT_ALLOWED_TRANSITION, cacheContext.getCurrentState(), EXPIRED));
	}

	@Override
	public void toBeDeleted(CacheContext cacheContext) {
		throw new IllegalStateException(String.format(NOT_ALLOWED_TRANSITION, cacheContext.getCurrentState(), TO_BE_DELETED));
	}

}
