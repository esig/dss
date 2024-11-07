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
package eu.europa.esig.dss.tsl.cache.access;

import eu.europa.esig.dss.tsl.cache.CacheKey;
import eu.europa.esig.dss.tsl.cache.DownloadCache;
import eu.europa.esig.dss.tsl.cache.ParsingCache;
import eu.europa.esig.dss.tsl.cache.ValidationCache;

/**
 * Builds the classes to deal with the cache
 */
public final class CacheAccessFactory {

	/** Global download Cache */
	private final DownloadCache downloadCache;

	/** Global parsing Cache */
	private final ParsingCache parsingCache;

	/** Global validation Cache */
	private final ValidationCache validationCache;

	/**
	 * Default constructor
	 */
	public CacheAccessFactory() {
		downloadCache = new DownloadCache();
		parsingCache = new ParsingCache();
		validationCache = new ValidationCache();
	}

	/**
	 * Loads a class to deal with a cache by the {@code key} records
	 *
	 * @param key {@link CacheKey} to use
	 * @return {@link CacheAccessByKey}
	 */
	public CacheAccessByKey getCacheAccess(CacheKey key) {
		return new CacheAccessByKey(key, downloadCache, parsingCache, validationCache);
	}

	/**
	 * Loads a class for TL updates
	 *
	 * @return {@link TLChangesCacheAccess}
	 */
	public TLChangesCacheAccess getTLChangesCacheAccess() {
		return new TLChangesCacheAccess(downloadCache, parsingCache, validationCache);
	}

	/**
	 * Loads a read-only cache access
	 *
	 * @return {@link ReadOnlyCacheAccess}
	 */
	public ReadOnlyCacheAccess getReadOnlyCacheAccess() {
		return new ReadOnlyCacheAccess(downloadCache, parsingCache, validationCache);
	}

	/**
	 * Loads a cache access to synchronize records
	 *
	 * @return {@link SynchronizerCacheAccess}
	 */
	public SynchronizerCacheAccess getSynchronizerCacheAccess() {
		return new SynchronizerCacheAccess(downloadCache, parsingCache, validationCache);
	}

	/**
	 * Loads a cache access to load the information about the current cache state
	 *
	 * @return {@link DebugCacheAccess}
	 */
	public DebugCacheAccess getDebugCacheAccess() {
		return new DebugCacheAccess(downloadCache, parsingCache, validationCache);
	}

}
