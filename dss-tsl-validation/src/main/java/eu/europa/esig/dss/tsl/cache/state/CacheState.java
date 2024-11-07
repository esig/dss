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
 * The interface defines the different possible transitions from a CacheState to
 * another one
 *
 */
public interface CacheState {

	/**
	 * The cache entry is marked as Synchronized
	 * 
	 * @param cacheContext
	 *                     the current cache context
	 */
	void sync(CacheContext cacheContext);

	/**
	 * The cache entry is marked as Desynchronized
	 * 
	 * @param cacheContext
	 *                     the current cache context
	 */
	void desync(CacheContext cacheContext);

	/**
	 * The cache entry needs to be refreshed
	 * 
	 * @param cacheContext
	 *                     the current cache context
	 */
	void refreshNeeded(CacheContext cacheContext);

	/**
	 * The cache entry is marked as to be deleted
	 * 
	 * @param cacheContext
	 *                     the current cache context
	 */
	void toBeDeleted(CacheContext cacheContext);

	/**
	 * The cache entry is marked in error state with the related exception
	 * 
	 * @param cacheContext
	 *                     the current cache context
	 * @param exception
	 *                     the wrapped met exception
	 */
	void error(CacheContext cacheContext, CachedExceptionWrapper exception);

}
