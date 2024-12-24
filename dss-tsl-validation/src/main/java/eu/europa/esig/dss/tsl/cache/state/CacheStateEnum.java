/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.tsl.cache.state;

/**
 * Contains states for a cache record
 */
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
		public void toBeDeleted(CacheContext cacheContext) {
			cacheContext.state(TO_BE_DELETED);
		}

		@Override
		public void error(CacheContext cacheContext, CachedExceptionWrapper exception) {
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
	 * NOTE: URL may become available again if not cleaned!
	 */
	TO_BE_DELETED {

		@Override
		public void desync(CacheContext cacheContext) {
			cacheContext.state(DESYNCHRONIZED);
		}

		@Override
		public void refreshNeeded(CacheContext cacheContext) {
			cacheContext.state(REFRESH_NEEDED);
		}

	};

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
	public void error(CacheContext cacheContext, CachedExceptionWrapper exception) {
		throw new IllegalStateException("Cannot store error");
	}

}
